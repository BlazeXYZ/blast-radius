// Small async helpers shared by the resolvers and enrichers.

const responseCache = new Map();

export const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

/**
 * fetch() + JSON with retries for flaky/rate-limited public APIs.
 * Resolves to null on 404 so callers can treat "doesn't exist" as data, not an error.
 * Identical GET requests share one in-flight promise unless `cache: false`.
 */
export function fetchJson(url, { cache = true, retries = 3, ...init } = {}) {
  const key = `${init.method || 'GET'} ${url} ${init.body || ''}`;
  if (cache && responseCache.has(key)) return responseCache.get(key);

  const promise = (async () => {
    for (let attempt = 0; ; attempt++) {
      let res;
      try {
        res = await fetch(url, init);
      } catch (err) {
        if (attempt < retries) { await sleep(400 * 2 ** attempt); continue; }
        throw new Error(`Network error fetching ${url}: ${err.message}`);
      }
      if ((res.status === 429 || res.status >= 500) && attempt < retries) {
        await sleep(600 * 2 ** attempt);
        continue;
      }
      if (res.status === 404) return null;
      if (!res.ok) throw new Error(`${res.status} ${res.statusText} from ${url}`);
      return res.json();
    }
  })();

  if (cache) {
    responseCache.set(key, promise);
    promise.catch(() => responseCache.delete(key));
  }
  return promise;
}

/** Returns a function that runs at most `n` tasks concurrently. */
export function createLimiter(n) {
  let active = 0;
  const waiting = [];
  const pump = () => {
    if (active >= n || !waiting.length) return;
    active++;
    const { task, resolve, reject } = waiting.shift();
    Promise.resolve().then(task).then(resolve, reject).finally(() => { active--; pump(); });
  };
  return task => new Promise((resolve, reject) => { waiting.push({ task, resolve, reject }); pump(); });
}

export function mapLimit(items, n, fn) {
  const limit = createLimiter(n);
  return Promise.all(items.map((item, i) => limit(() => fn(item, i))));
}

export function chunk(items, size) {
  const out = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}
