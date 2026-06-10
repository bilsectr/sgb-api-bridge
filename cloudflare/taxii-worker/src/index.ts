/**
 * SGB TAXII 2.1 Worker
 *
 * GitHub Pages'de servis edilen statik TAXII agacinin (scripts/build_taxii.py
 * ciktisi) onunde durur ve TAXII 2.1 semantik katmanini ekler:
 *   - Content-Type: application/taxii+json;version=2.1
 *   - __TAXII_BASE__ placeholder -> PUBLIC_BASE host rewrite
 *   - ?added_after=T&limit=N&next=cursor query semantigi (pages.json kullanir)
 *   - CORS (anonim erisim)
 *   - Edge cache (Cloudflare Cache API)
 *
 * Endpoint'ler (TAXII 2.1 spec):
 *   GET /taxii2/                                 Discovery
 *   GET /api/                                    API Root
 *   GET /api/collections/                        Collections list
 *   GET /api/collections/{cid}/                  Collection metadata
 *   GET /api/collections/{cid}/objects/          Envelope (paginated)
 *   GET /api/collections/{cid}/manifest/         Manifest envelope
 *   GET /api/collections/{cid}/objects/{stix}/   Tek STIX objesi (manifest scan)
 */

export interface Env {
  UPSTREAM_BASE: string;   // ornek: https://bilsectr.github.io/sgb-api-bridge/taxii
  PUBLIC_BASE: string;     // ornek: https://sgb-taxii.bilsec.tr
  EDGE_CACHE_TTL: string;  // saniye
  PAGES_CACHE_TTL: string;
}

interface PageMeta {
  page: number;
  file: string;
  count: number;
  min_id: number;
  max_id: number;
  min_date_added: string;
  max_date_added: string;
  max_last_changed: string;
}

interface PagesIndex {
  collection_id: string;
  alias: string;
  page_size: number;
  total_objects: number;
  pages: PageMeta[];
}

interface Envelope {
  more: boolean;
  next?: string;
  objects: any[];
}

const TAXII_CT = "application/taxii+json;version=2.1";
const STIX_CT = "application/stix+json;version=2.1";

const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
  "Access-Control-Allow-Headers": "Accept, Content-Type, Range",
  "Access-Control-Max-Age": "86400",
};

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }
    if (req.method !== "GET" && req.method !== "HEAD") {
      return errorResponse(405, "Method Not Allowed");
    }

    const url = new URL(req.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    try {
      // Discovery
      if (path === "/taxii2") {
        return await serveStatic(env, ctx, "/taxii2/index.json", TAXII_CT);
      }
      // API Root
      if (path === "/api") {
        return await serveStatic(env, ctx, "/api/index.json", TAXII_CT);
      }
      // Collections list
      if (path === "/api/collections") {
        return await serveStatic(env, ctx, "/api/collections/index.json", TAXII_CT);
      }

      // /api/collections/{cid}[/...]
      const m = path.match(/^\/api\/collections\/([a-z0-9-]+)(?:\/(objects|manifest)(?:\/([^\/]+))?)?$/);
      if (m) {
        const [, cid, kind, sub] = m;
        if (!kind) {
          return await serveStatic(env, ctx, `/api/collections/${cid}/index.json`, TAXII_CT);
        }
        if (kind === "objects" && sub) {
          return await serveSingleObject(env, ctx, cid, sub);
        }
        return await serveEnvelope(env, ctx, cid, kind as "objects" | "manifest", url);
      }

      return errorResponse(404, "Not Found");
    } catch (e: any) {
      return errorResponse(500, `Worker error: ${e?.message || String(e)}`);
    }
  },
};

// ---------------------------------------------------------------------------
// Static passthrough (discovery / api root / collections / collection-meta)
// ---------------------------------------------------------------------------

async function serveStatic(
  env: Env,
  ctx: ExecutionContext,
  upstreamPath: string,
  contentType: string,
): Promise<Response> {
  const upstream = env.UPSTREAM_BASE + upstreamPath;
  const cacheKey = new Request(upstream, { method: "GET" });
  const cache = caches.default;

  let resp = await cache.match(cacheKey);
  if (!resp) {
    const upstreamResp = await fetch(upstream, { cf: { cacheTtl: 60, cacheEverything: true } });
    if (!upstreamResp.ok) {
      return errorResponse(upstreamResp.status, `Upstream ${upstreamResp.status}`);
    }
    const body = rewriteBase(await upstreamResp.text(), env);
    resp = new Response(body, {
      status: 200,
      headers: {
        "Content-Type": contentType,
        "Cache-Control": `public, max-age=${env.EDGE_CACHE_TTL}`,
        ...CORS_HEADERS,
      },
    });
    ctx.waitUntil(cache.put(cacheKey, resp.clone()));
  }
  return withCORS(resp);
}

// ---------------------------------------------------------------------------
// Envelope orchestration (objects / manifest)
// ---------------------------------------------------------------------------

async function serveEnvelope(
  env: Env,
  ctx: ExecutionContext,
  cid: string,
  kind: "objects" | "manifest",
  url: URL,
): Promise<Response> {
  const pages = await loadPagesIndex(env, ctx, cid);
  if (!pages) return errorResponse(404, `Collection not found: ${cid}`);

  const addedAfter = url.searchParams.get("added_after");
  const next = url.searchParams.get("next");
  const limit = parseLimit(url.searchParams.get("limit"));

  // Sayfa + sayfa-ici offset secimi. Cursor formati: "NNNN" veya "NNNN.OFFSET".
  //  - next cursor verilmisse onu kullan; OFFSET, kucuk `limit`'lerde ayni sayfa
  //    icinde ilerlemeyi saglar (offset olmadan limit sonsuz dongu uretiyordu).
  //  - degilse: added_after > T olan ilk sayfa (yoksa 1)
  let startPage = 1;
  let startOffset = 0;
  if (next) {
    const dot = next.indexOf(".");
    const pStr = dot === -1 ? next : next.slice(0, dot);
    const p = parseInt(pStr, 10);
    if (!Number.isFinite(p) || p < 1) {
      return errorResponse(400, "Invalid next cursor");
    }
    startPage = p;
    if (dot !== -1) {
      const o = parseInt(next.slice(dot + 1), 10);
      if (!Number.isFinite(o) || o < 0) {
        return errorResponse(400, "Invalid next cursor");
      }
      startOffset = o;
    }
  } else if (addedAfter) {
    const idx = pages.pages.findIndex(p => p.max_last_changed > addedAfter);
    startPage = idx === -1 ? pages.pages.length + 1 : idx + 1;
  }

  if (startPage > pages.pages.length) {
    // Bos envelope (yeni icerik yok)
    return jsonResponse(env, { more: false, objects: [] }, TAXII_CT);
  }

  const pageMeta = pages.pages[startPage - 1];
  const upstreamPath = `/api/collections/${cid}/${kind}/${pageMeta.file}`;
  const upstreamResp = await fetchCached(env, ctx, upstreamPath, parseInt(env.EDGE_CACHE_TTL, 10));
  if (!upstreamResp.ok) {
    return errorResponse(upstreamResp.status, `Upstream page ${upstreamResp.status}`);
  }

  const envelope: Envelope = await upstreamResp.json();

  // added_after filtresi sayfa-icinde uygula (manifest icin date_added/version,
  // objects icin modified). Bu sayede client ayni sayfayi kismi olarak alir.
  if (addedAfter) {
    envelope.objects = envelope.objects.filter(o => {
      if (kind === "manifest") {
        return o.date_added > addedAfter || (o.version && o.version > addedAfter);
      }
      // objects: identity'yi her zaman koru; indicator'larda modified karsilastir.
      if (o.type === "identity") return true;
      return o.modified && o.modified > addedAfter;
    });
  }

  // Sayfa-ici offset: onceki istekte limit ile kirpilmis sayfanin kaldigi yerden devam.
  // Filtre (added_after) deterministik oldugu icin offset her istekte ayni indekslere denk gelir.
  if (startOffset > 0) {
    envelope.objects = envelope.objects.slice(startOffset);
  }

  // limit uygula. Kalan limit'ten buyukse AYNI sayfada offset'li cursor ile devam et;
  // degilse sonraki sayfaya gec. Boylece page_size'dan kucuk limit'lerde de ilerleme garanti.
  if (limit !== null && envelope.objects.length > limit) {
    envelope.objects = envelope.objects.slice(0, limit);
    envelope.more = true;
    envelope.next = `${pad4(startPage)}.${startOffset + limit}`;
  } else {
    // upstream envelope.more/next: gercek "daha sayfa var mi" durumu
    const hasMore = startPage < pages.pages.length;
    envelope.more = hasMore;
    if (hasMore) {
      envelope.next = pad4(startPage + 1);
    } else {
      delete envelope.next;
    }
  }

  return jsonResponse(env, envelope, TAXII_CT);
}

// ---------------------------------------------------------------------------
// Tek obje lookup
// ---------------------------------------------------------------------------

async function serveSingleObject(
  env: Env,
  ctx: ExecutionContext,
  cid: string,
  stixId: string,
): Promise<Response> {
  // STIX id formati: indicator--<uuid>
  if (!/^[a-z][a-z-]*--[a-f0-9-]{36}$/.test(stixId)) {
    return errorResponse(400, "Invalid STIX id");
  }

  const pages = await loadPagesIndex(env, ctx, cid);
  if (!pages) return errorResponse(404, `Collection not found: ${cid}`);

  // Tum sayfalari taramak yerine: manifest taramasi yapilamiyor (id-aralik
  // index'i yok). Pragmatik: sayfalari sirayla tara, ilk match'i don.
  // Tipik client kullanimi nadir oldugu icin acceptable.
  for (const pm of pages.pages) {
    const upstreamPath = `/api/collections/${cid}/objects/${pm.file}`;
    const resp = await fetchCached(env, ctx, upstreamPath, parseInt(env.EDGE_CACHE_TTL, 10));
    if (!resp.ok) continue;
    const env_: Envelope = await resp.json();
    const hit = env_.objects.find((o: any) => o.id === stixId);
    if (hit) {
      return jsonResponse(env, { more: false, objects: [hit] }, STIX_CT);
    }
  }
  return errorResponse(404, "Object not found in collection");
}

// ---------------------------------------------------------------------------
// pages.json yukleyici (kisa TTL)
// ---------------------------------------------------------------------------

async function loadPagesIndex(
  env: Env,
  ctx: ExecutionContext,
  cid: string,
): Promise<PagesIndex | null> {
  const upstreamPath = `/api/collections/${cid}/pages.json`;
  const resp = await fetchCached(env, ctx, upstreamPath, parseInt(env.PAGES_CACHE_TTL, 10));
  if (!resp.ok) return null;
  return await resp.json() as PagesIndex;
}

// ---------------------------------------------------------------------------
// Yardimcilar
// ---------------------------------------------------------------------------

async function fetchCached(
  env: Env,
  ctx: ExecutionContext,
  upstreamPath: string,
  ttl: number,
): Promise<Response> {
  const upstream = env.UPSTREAM_BASE + upstreamPath;
  const cacheKey = new Request(upstream, { method: "GET" });
  const cache = caches.default;
  let resp = await cache.match(cacheKey);
  if (!resp) {
    resp = await fetch(upstream, { cf: { cacheTtl: ttl, cacheEverything: true } });
    if (resp.ok) {
      const cloned = new Response(resp.body, resp);
      cloned.headers.set("Cache-Control", `public, max-age=${ttl}`);
      ctx.waitUntil(cache.put(cacheKey, cloned.clone()));
      resp = cloned;
    }
  }
  return resp;
}

function rewriteBase(body: string, env: Env): string {
  return body.split("__TAXII_BASE__").join(env.PUBLIC_BASE);
}

function jsonResponse(env: Env, obj: unknown, contentType: string): Response {
  return new Response(JSON.stringify(obj), {
    status: 200,
    headers: {
      "Content-Type": contentType,
      "Cache-Control": `public, max-age=${env.EDGE_CACHE_TTL}`,
      ...CORS_HEADERS,
    },
  });
}

function withCORS(resp: Response): Response {
  const h = new Headers(resp.headers);
  for (const [k, v] of Object.entries(CORS_HEADERS)) h.set(k, v);
  return new Response(resp.body, { status: resp.status, headers: h });
}

function errorResponse(status: number, msg: string): Response {
  return new Response(
    JSON.stringify({
      title: "Error",
      http_status: String(status),
      description: msg,
    }),
    {
      status,
      headers: { "Content-Type": TAXII_CT, ...CORS_HEADERS },
    },
  );
}

function pad4(n: number): string {
  return String(n).padStart(4, "0");
}

function parseLimit(raw: string | null): number | null {
  if (!raw) return null;
  const n = parseInt(raw, 10);
  if (!Number.isFinite(n) || n < 1) return null;
  return Math.min(n, 10000);
}
