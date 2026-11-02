// A fake Google (OpenID Connect: authorization code + PKCE, RS256 ID tokens with a nonce, JWKS) and a fake GitHub (OAuth 2: authorization code,
// /user and /user/emails) on one loopback server, for the social sign-in tests. Start the rewrite pointing at it:
//   SocialProviders__Google__ClientId=g-client SocialProviders__Google__ClientSecret=g-secret SocialProviders__Google__AuthorizationEndpoint=$URL/google/authorize ...
// (area-social.mjs and ui-social.js print the exact settings.) `p.google` / `p.github` choose who signs in next and how the provider misbehaves.
const http = require('http');
const crypto = require('crypto');

const b64u = (b) => Buffer.from(b).toString('base64url');
const json = (res, status, body) => { res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify(body)); };

async function startFakeSocial({ host = '127.0.0.1', port = 0 } = {}) {
  const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const other = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const kid = 'g-' + crypto.randomBytes(3).toString('hex');
  const jwk = { ...rsa.publicKey.export({ format: 'jwk' }), kid, alg: 'RS256', use: 'sig' };
  const p = {
    url: '', clientIds: { google: 'g-client', github: 'h-client' }, secrets: { google: 'g-secret', github: 'h-secret' },
    // who signs in next
    google: { sub: 'g-sub-1', email: 'g.person@example.test', email_verified: true, name: 'Gee Person', picture: 'https://example.test/g.png', fault: '' },
    // emails: what /user/emails returns; profileEmail: what /user claims as the public email (never trusted)
    github: { id: 4242, login: 'octo-person', name: 'Octo Person', profileEmail: 'public@example.test', emails: [{ email: 'octo@example.test', primary: true, verified: true }], fault: '' },
    authRequests: [], tokenRequests: [], apiCalls: [], codes: new Map(),
  };

  const sign = (payload, fault) => {
    const header = { alg: 'RS256', typ: 'JWT', kid };
    const h = b64u(JSON.stringify(header)), body = b64u(JSON.stringify(payload));
    return `${h}.${body}.${b64u(crypto.sign('RSA-SHA256', Buffer.from(`${h}.${body}`), fault === 'sig' ? other.privateKey : rsa.privateKey))}`;
  };

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, p.url || 'http://127.0.0.1');
    const [, provider, ...rest] = url.pathname.split('/');
    const path = '/' + rest.join('/');
    if (provider !== 'google' && provider !== 'github') { res.writeHead(404); return res.end('not found'); }
    const cfg = p[provider];
    if (provider === 'google' && path === '/jwks') return json(res, 200, { keys: [jwk] });
    if (path === '/authorize') {
      const q = Object.fromEntries(url.searchParams);
      p.authRequests.push({ provider, ...q });
      if (q.client_id !== p.clientIds[provider] || q.response_type !== 'code' || !q.redirect_uri) { res.writeHead(400); return res.end('bad authorization request'); }
      const back = new URL(q.redirect_uri);
      if (cfg.fault === 'error') { back.searchParams.set('error', 'access_denied'); back.searchParams.set('error_description', 'The person said no'); back.searchParams.set('state', q.state); res.writeHead(302, { location: back.toString() }); return res.end(); }
      const code = crypto.randomBytes(12).toString('hex');
      p.codes.set(code, { provider, q, identity: JSON.parse(JSON.stringify(cfg)), used: false });
      back.searchParams.set('code', code);
      back.searchParams.set('state', cfg.fault === 'state' ? 'forged-state' : q.state);
      res.writeHead(302, { location: back.toString() });
      return res.end();
    }
    if (path === '/token' && req.method === 'POST') {
      let raw = ''; for await (const c of req) raw += c;
      const f = Object.fromEntries(new URLSearchParams(raw));
      p.tokenRequests.push({ provider, ...f });
      const rec = p.codes.get(f.code);
      if (f.client_id !== p.clientIds[provider] || f.client_secret !== p.secrets[provider]) return json(res, 401, { error: 'invalid_client' });
      if (!rec || rec.used || rec.provider !== provider) return json(res, provider === 'github' ? 200 : 400, { error: 'bad_verification_code' });
      rec.used = true;
      if (f.redirect_uri !== rec.q.redirect_uri) return json(res, 400, { error: 'redirect_uri_mismatch' });
      const want = crypto.createHash('sha256').update(f.code_verifier ?? '').digest('base64url');
      if (rec.q.code_challenge_method !== 'S256' || want !== rec.q.code_challenge) { p.pkceFailures = (p.pkceFailures ?? 0) + 1; return json(res, 400, { error: 'invalid_grant', error_description: 'pkce' }); }
      if (provider === 'github') { const at = 'gho_' + crypto.randomBytes(8).toString('hex'); p.tokens = { ...(p.tokens ?? {}), [at]: rec.identity }; return json(res, 200, { access_token: at, token_type: 'bearer', scope: 'read:user,user:email' }); }
      const now = Math.floor(Date.now() / 1000), id = rec.identity, fault = id.fault;
      const claims = { iss: fault === 'iss' ? 'https://evil.example' : p.url + '/google', aud: fault === 'aud' ? 'someone-else' : p.clientIds.google, sub: id.sub, iat: now, exp: fault === 'exp' ? now - 3600 : now + 300,
        email: id.email, email_verified: id.email_verified, name: id.name, picture: id.picture };
      if (fault !== 'no-nonce') claims.nonce = fault === 'nonce' ? 'not-the-nonce' : rec.q.nonce;
      return json(res, 200, { access_token: 'ya29.' + crypto.randomBytes(6).toString('hex'), token_type: 'Bearer', expires_in: 300, id_token: sign(claims, fault) });
    }
    if (provider === 'github' && path.startsWith('/api/')) {
      p.apiCalls.push({ path: path.slice(4), authorization: req.headers.authorization, userAgent: req.headers['user-agent'] });
      const id = p.tokens?.[(req.headers.authorization ?? '').replace(/^Bearer /i, '')];
      if (!id) return json(res, 401, { message: 'Bad credentials' });
      if (path === '/api/user') return json(res, 200, { id: id.id, login: id.login, name: id.name, email: id.profileEmail, avatar_url: 'https://example.test/h.png' });
      if (path === '/api/user/emails') return json(res, 200, id.emails);
    }
    res.writeHead(404); res.end('not found');
  });
  await new Promise((r) => server.listen(port, host, r));
  p.url = `http://${host}:${server.address().port}`;
  p.close = () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); });
  /** The environment variables that point a rewrite at this fake. */
  p.env = () => ({
    SocialProviders__Google__ClientId: p.clientIds.google, SocialProviders__Google__ClientSecret: p.secrets.google,
    SocialProviders__Google__AuthorizationEndpoint: `${p.url}/google/authorize`, SocialProviders__Google__TokenEndpoint: `${p.url}/google/token`,
    SocialProviders__Google__JwksUri: `${p.url}/google/jwks`, SocialProviders__Google__Issuer: `${p.url}/google`,
    SocialProviders__GitHub__ClientId: p.clientIds.github, SocialProviders__GitHub__ClientSecret: p.secrets.github,
    SocialProviders__GitHub__AuthorizationEndpoint: `${p.url}/github/authorize`, SocialProviders__GitHub__TokenEndpoint: `${p.url}/github/token`,
    SocialProviders__GitHub__ApiBase: `${p.url}/github/api`,
  });
  return p;
}
module.exports = { startFakeSocial };

// Run directly: keep it up on a fixed port and print the settings (so a rewrite can be started against it).
if (require.main === module) {
  startFakeSocial({ port: Number(process.env.FAKE_SOCIAL_PORT ?? 0) }).then((p) => {
    console.log(`fake social providers at ${p.url}`);
    for (const [k, v] of Object.entries(p.env())) console.log(`${k}=${v}`);
  });
}
