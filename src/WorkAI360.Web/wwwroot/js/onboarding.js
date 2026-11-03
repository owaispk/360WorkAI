// Small browser helpers for the onboarding pages.
export function detectPlatform() {
  const ua = (navigator.userAgent || '').toLowerCase();
  if (ua.includes('windows')) return 'win-x64';
  if (ua.includes('mac')) return 'mac-arm64';
  if (ua.includes('linux') || ua.includes('x11')) return ua.includes('aarch64') || ua.includes('arm64') ? 'linux-arm64' : 'linux-x64';
  return '';
}
export function isMobile() { return /android|iphone|ipad|ipod|mobile/i.test(navigator.userAgent || ''); }
export function origin() { return window.location.origin; }
export function readHash() { return window.location.hash.replace(/^#/, ''); }
// A page opened by the desktop app's browser window tells that window it finished, then closes itself.
export function notifyOpener(nonce, error) {
  if (!window.opener) return false;
  window.opener.postMessage({ type: 'openwork:reauth-complete', nonce, error }, window.location.origin);
  window.close();
  return true;
}
