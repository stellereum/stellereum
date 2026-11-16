const NANO_PER_STELL = 1_000_000_000n;

/**
 * Parse a nano-STELL integer quantity from a decimal string, `0x` hex string,
 * or safe JS integer without losing precision on values > MAX_SAFE_INTEGER.
 */
function parseNanoBigInt(nano: number | string | undefined | null): bigint | null {
  if (nano === undefined || nano === null) return null;
  if (typeof nano === 'number') {
    if (!Number.isFinite(nano) || !Number.isInteger(nano)) return null;
    if (Math.abs(nano) > Number.MAX_SAFE_INTEGER) return null;
    return BigInt(nano);
  }
  if (typeof nano === 'string') {
    const s = nano.trim();
    if (!s) return null;
    if (/^-?0x[0-9a-fA-F]+$/i.test(s)) {
      return s.startsWith('-') ? -BigInt(s.slice(1)) : BigInt(s);
    }
    if (/^-?\d+$/.test(s)) {
      return BigInt(s);
    }
  }
  return null;
}

export function formatStell(nano: number | string | undefined | null): string {
  if (nano === undefined || nano === null) return '0 STELL';
  const bi = parseNanoBigInt(nano);
  if (bi !== null) {
    if (bi === 0n) return '0 STELL';
    const neg = bi < 0n;
    const abs = neg ? -bi : bi;
    const sign = neg ? '-' : '';
    const whole = abs / NANO_PER_STELL;
    const frac = abs % NANO_PER_STELL;

    if (whole === 0n) {
      const stell = Number(frac) / 1_000_000_000;
      if (stell < 0.0001) return `${sign}${stell.toFixed(6)} STELL`;
      return `${sign}${stell.toFixed(4)} STELL`;
    }

    const totalTenThousandths = (abs + 50_000n) / 100_000n;
    const roundedWhole = totalTenThousandths / 10_000n;
    const roundedFrac4 = Number(totalTenThousandths % 10_000n);
    const fracPadded = String(roundedFrac4).padStart(4, '0');
    const fracTrimmed = fracPadded.replace(/0+$/, '');
    const fracStr = fracTrimmed.length < 2 ? fracPadded.slice(0, 2) : fracTrimmed;
    return `${sign}${roundedWhole.toLocaleString('en-US')}.${fracStr} STELL`;
  }

  const val = typeof nano === 'string' ? Number(nano.trim()) : nano;
  if (!Number.isFinite(val)) return '0 STELL';
  const stell = val / 1_000_000_000;
  if (stell === 0) return '0 STELL';
  if (Math.abs(stell) < 0.0001) return `${stell.toFixed(6)} STELL`;
  if (Math.abs(stell) < 1) return `${stell.toFixed(4)} STELL`;
  return `${stell.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 4 })} STELL`;
}

export function formatNano(nano: number | string | undefined | null): string {
  if (nano === undefined || nano === null) return '0 nano';
  const bi = parseNanoBigInt(nano);
  if (bi !== null) {
    return `${bi.toLocaleString('en-US')} nano`;
  }
  const val = typeof nano === 'string' ? Number(nano.trim()) : nano;
  if (!Number.isFinite(val)) return '0 nano';
  return `${val.toLocaleString('en-US')} nano`;
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
