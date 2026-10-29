export function formatStell(nano: number | string | undefined | null): string {
  if (nano === undefined || nano === null) return '0 STELL';
  const val = typeof nano === 'string' ? Number(nano) : nano;
  if (isNaN(val)) return '0 STELL';
  const stell = val / 1_000_000_000;
  if (stell === 0) return '0 STELL';
  if (stell < 0.0001) return `${stell.toFixed(6)} STELL`;
  if (stell < 1) return `${stell.toFixed(4)} STELL`;
  return `${stell.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 4 })} STELL`;
}

export function formatNano(nano: number | string | undefined | null): string {
  if (!nano) return '0 nano';
  const val = typeof nano === 'string' ? Number(nano) : nano;
  return `${val.toLocaleString()} nano`;
}

export function truncateMiddle(str: string | undefined | null, left = 8, right = 8): string {
  if (!str) return '';
  if (str.length <= left + right + 3) return str;
  return `${str.slice(0, left)}...${str.slice(-right)}`;
}

export function timeAgo(timestampSec: number): string {
  if (!timestampSec) return 'just now';
  const now = Math.floor(Date.now() / 1000);
  const diff = now - timestampSec;
  if (diff < 2) return 'just now';
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export function formatDateTime(timestampSec: number): string {
  if (!timestampSec) return '-';
  const d = new Date(timestampSec * 1000);
  return d.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}

export function copyToClipboard(text: string): Promise<boolean> {
  return navigator.clipboard.writeText(text).then(() => true).catch(() => false);
}
