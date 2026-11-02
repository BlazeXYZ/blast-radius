// Formatting and DOM-safety helpers for the UI layer.

const ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

/** Everything from a registry or advisory is untrusted; escape before it touches innerHTML. */
export const esc = value => String(value ?? '').replace(/[&<>"']/g, ch => ESCAPES[ch]);

export function safeUrl(url) {
  try {
    const u = new URL(url);
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.href : null;
  } catch {
    return null;
  }
}

export function fmtNum(n) {
  if (n == null) return '–';
  if (n >= 1e9) return `${(n / 1e9).toFixed(1)}B`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
  if (n >= 1e4) return `${Math.round(n / 1e3)}k`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)}k`;
  return String(n);
}

export function relTime(iso, now = Date.now()) {
  if (!iso) return '–';
  const days = (now - Date.parse(iso)) / 86_400_000;
  if (days < 1) return 'today';
  if (days < 45) return `${Math.round(days)}d ago`;
  if (days < 365) return `${Math.round(days / 30)}mo ago`;
  return `${(days / 365).toFixed(days < 3650 ? 1 : 0)}y ago`;
}

export function download(filename, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = Object.assign(document.createElement('a'), { href: url, download: filename });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
