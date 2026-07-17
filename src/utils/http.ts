import { TTLCache } from "./cache.js";
import { RateLimiter } from "./rate-limiter.js";

const defaultCache = new TTLCache<string>(600);
const defaultLimiter = new RateLimiter(30, 60);

export interface FetchOptions {
  cache?: TTLCache<string>;
  limiter?: RateLimiter;
  headers?: Record<string, string>;
  timeout?: number;
}

export async function apiFetch<T = unknown>(url: string, opts: FetchOptions = {}): Promise<T> {
  const cache = opts.cache ?? defaultCache;
  const limiter = opts.limiter ?? defaultLimiter;

  const cached = cache.get(url);
  if (cached) return JSON.parse(cached) as T;

  await limiter.acquire();

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), opts.timeout ?? 30000);

  try {
    const res = await fetch(url, {
      headers: opts.headers,
      signal: controller.signal,
    });

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${res.statusText} for ${url}`);
    }

    const text = await res.text();
    cache.set(url, text);
    return JSON.parse(text) as T;
  } finally {
    clearTimeout(timeoutId);
  }
}

export async function apiFetchText(url: string, opts: FetchOptions = {}): Promise<string> {
  const cache = opts.cache ?? defaultCache;
  const limiter = opts.limiter ?? defaultLimiter;

  const cached = cache.get(url);
  if (cached) return cached;

  await limiter.acquire();

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), opts.timeout ?? 30000);

  try {
    const res = await fetch(url, {
      headers: opts.headers,
      signal: controller.signal,
    });

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${res.statusText} for ${url}`);
    }

    const text = await res.text();
    cache.set(url, text);
    return text;
  } finally {
    clearTimeout(timeoutId);
  }
}
