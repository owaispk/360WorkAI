// A small fake OpenID Connect provider for tests (authorization code + PKCE, RS256 ID tokens, JWKS, discovery).
// It runs on loopback and signs in whoever `p.identity` names. `p.fault` makes it misbehave on purpose so tests can attack the relying party:
//   'nonce' wrong nonce | 'no-nonce' | 'aud' wrong audience | 'iss' wrong issuer | 'exp' expired | 'sig' signed by another key
//   'alg-none' unsigned token | 'alg-hs256' HS256 signed with the public key text | 'no-sub' | 'no-email' | 'state' returns another state
//   'error' redirects back with error=access_denied | 'bad-verifier' (records only) | 'kid-unknown'
const http = require('http');
const crypto = require('crypto');

const b64u = (b) => Buffer.from(b).toString('base64url');
const json = (res, status, body, headers = {}) => { res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers }); res.end(JSON.stringify(body)); };

async function startFakeOidc({ port = 0, host = process.env.IDP_HOST || '127.0.0.1', clientId = 'fake-client', clientSecret = 'fake-secret' } = {}) {
  const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const other = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const kid = 'k-' + crypto.randomBytes(3).toString('hex');
  const jwk = { ...rsa.publicKey.export({ format: 'jwk' }), kid, alg: 'RS256', use: 'sig' };
  const p = {
    clientId, clientSecret, kid,
    identity: { sub: 'sub-1', email: 'person@example.test', email_verified: true, name: 'Person One' },
    fault: '',
    authRequests: [], tokenRequests: [], codes: new Map(), tokenEndpointCalls: 0,
    issuer: '', url: '',
  };

  function sign(payload, fault) {
    let header = { alg: 'RS256', typ: 'JWT', kid };
    let key = rsa.privateKey;
    if (fault === 'sig') key = other.privateKey;
    if (fault === 'kid-unknown') header.kid = 'nope';
    const h = b64u(JSON.stringify(header)), body = b64u(JSON.stringify(payload));
    if (fault === 'alg-none') return `${b64u(JSON.stringify({ alg: 'none', typ: 'JWT' }))}.${body}.`;
    if (fault === 'alg-hs256') {
      const hh = b64u(JSON.stringify({ alg: 'HS256', typ: 'JWT', kid }));
      const secret = rsa.publicKey.export({ format: 'pem', type: 'spki' });
      return `${hh}.${body}.${b64u(crypto.createHmac('sha256', secret).update(`${hh}.${body}`).digest())}`;
    }
    return `${h}.${body}.${b64u(crypto.sign('RSA-SHA256', Buffer.from(`${h}.${body}`), key))}`;
  }

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, p.url || 'http://127.0.0.1');
    if (url.pathname === '/.well-known/openid-configuration') {
      return json(res, 200, { issuer: p.issuer, authorization_endpoint: `${p.url}/authorize`, token_endpoint: `${p.url}/token`, jwks_uri: `${p.url}/jwks`,
        response_types_supported: ['code'], subject_types_supported: ['public'], id_token_signing_alg_values_supported: ['RS256'], code_challenge_methods_supported: ['S256'] });
    }
    if (url.pathname === '/jwks') return json(res, 200, { keys: [jwk] });
    if (url.pathname === '/authorize') {
      const q = Object.fromEntries(url.searchParams);
      p.authRequests.push(q);
      if (q.client_id !== p.clientId || q.response_type !== 'code' || !q.redirect_uri) { res.writeHead(400); return res.end('bad authorization request'); }
      const back = new URL(q.redirect_uri);
      if (p.fault === 'error') { back.searchParams.set('error', 'access_denied'); back.searchParams.set('error_description', 'The person said no'); if (q.state) back.searchParams.set('state', q.state); res.writeHead(302, { location: back.toString() }); return res.end(); }
      const code = crypto.randomBytes(12).toString('hex');
      p.codes.set(code, { q, identity: { ...p.identity }, fault: p.fault, used: false });
      back.searchParams.set('code', code);
      back.searchParams.set('state', p.fault === 'state' ? 'forged-state' : q.state);
      res.writeHead(302, { location: back.toString() });
      return res.end();
    }
    if (url.pathname === '/token' && req.method === 'POST') {
      let raw = ''; for await (const c of req) raw += c;
      const f = Object.fromEntries(new URLSearchParams(raw));
      p.tokenEndpointCalls++;
      let id = null, secret = null;
      const basic = req.headers.authorization?.match(/^Basic (.+)$/i);
      if (basic) { const [a, ...b] = Buffer.from(basic[1], 'base64').toString().split(':'); id = decodeURIComponent(a); secret = decodeURIComponent(b.join(':')); } else { id = f.client_id; secret = f.client_secret; }
      p.tokenRequests.push({ ...f, _auth: basic ? 'basic' : 'post', _clientId: id });
      if (id !== p.clientId || secret !== p.clientSecret) return json(res, 401, { error: 'invalid_client' });
      const rec = p.codes.get(f.code);
      if (f.grant_type !== 'authorization_code' || !rec || rec.used) return json(res, 400, { error: 'invalid_grant' });
      rec.used = true;
      if (f.redirect_uri !== rec.q.redirect_uri) return json(res, 400, { error: 'invalid_grant', error_description: 'redirect_uri mismatch' });
      if (rec.q.code_challenge) {
        const want = crypto.createHash('sha256').update(f.code_verifier ?? '').digest('base64url');
        if (rec.q.code_challenge_method !== 'S256' || want !== rec.q.code_challenge) { p.pkceFailures = (p.pkceFailures ?? 0) + 1; return json(res, 400, { error: 'invalid_grant', error_description: 'pkce' }); }
      }
      const now = Math.floor(Date.now() / 1000), fault = rec.fault;
      const claims = { iss: fault === 'iss' ? 'https://evil.example' : p.issuer, aud: fault === 'aud' ? 'someone-else' : p.clientId, sub: rec.identity.sub, iat: now, exp: fault === 'exp' ? now - 3600 : now + 300,
        email: rec.identity.email, email_verified: rec.identity.email_verified, name: rec.identity.name };
      if (fault !== 'no-nonce') claims.nonce = fault === 'nonce' ? 'not-the-nonce' : rec.q.nonce;
      if (fault === 'no-sub') delete claims.sub;
      if (fault === 'no-email') { delete claims.email; delete claims.email_verified; }
      return json(res, 200, { access_token: 'at-' + crypto.randomBytes(6).toString('hex'), token_type: 'Bearer', expires_in: 300, id_token: sign(claims, fault) });
    }
    res.writeHead(404); res.end('not found');
  });
  await new Promise((r) => server.listen(port, '127.0.0.1', r));
  p.url = `http://${host}:${server.address().port}`;
  p.issuer = p.url;
  p.close = () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); });
  p.signRaw = sign;
  return p;
}
module.exports = { startFakeOidc };
