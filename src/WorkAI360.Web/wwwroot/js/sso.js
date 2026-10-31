// Browser helpers for the single sign-on pages. Same-origin fetch (the session cookie, and the sign-in binding cookie, are set by the browser).
export async function post(path, headers, bodyJson) {
  try {
    const response = await fetch(path, { method: 'POST', credentials: 'include', headers: { 'content-type': 'application/json', accept: 'application/json', ...(headers ?? {}) }, body: bodyJson ?? '{}' });
    return { status: response.status, text: await response.text() };
  } catch {
    return { status: 0, text: JSON.stringify({ message: 'Could not reach the server. Check your connection and try again.' }) };
  }
}

// The test runs in a small window so the settings page stays in place; false when the browser blocked it.
export function openTestWindow(url) {
  return !!window.open(url, 'openwork-sso-test', 'popup,width=520,height=720');
}

export function go(url) { window.location.assign(url); }

// The last page of a test: tell the window that opened it, then close.
export function finishTest(intentId, failed) {
  window.history.replaceState(null, '', '/sso/test/complete');
  if (!window.opener) return;
  window.opener.postMessage({ type: 'openwork:sso-test-complete', intentId, failed }, window.location.origin);
  window.close();
}
