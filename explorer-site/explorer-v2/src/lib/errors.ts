import { ApiError } from './api';

/** True when the indexer answered "this item does not exist". */
export function isNotFound(err: unknown): boolean {
  return err instanceof ApiError && err.status === 404;
}

/**
 * Turn a data-layer error into a sentence a human can act on.
 *
 * Never renders the raw `API error 404: Not Found` string: a 404 means "not
 * indexed yet" (or a wrong identifier), a 5xx means "the indexer is down",
 * and a `TypeError` means the request never reached the API.
 */
export function friendlyError(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    if (err.status === 404) {
      return `${fallback}: not found on the indexer. It may not be indexed yet.`;
    }
    if (err.status === 429) {
      return `${fallback}: too many requests. Try again in a moment.`;
    }
    if (err.status >= 500) {
      return `${fallback}: the indexer is temporarily unavailable.`;
    }
    return `${fallback} (HTTP ${err.status}).`;
  }
  if (err instanceof TypeError) {
    return `${fallback}: cannot reach the API.`;
  }
  if (err instanceof Error && err.message && !/^(API|RPC) error \d+/.test(err.message)) {
    return err.message;
  }
  return fallback;
}
