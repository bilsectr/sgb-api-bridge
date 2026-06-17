#!/usr/bin/env python3
"""
SGB TAXII 2.1 servisi (self-hosted).

build_taxii.py'nin urettigi statik TAXII agacinin (docs/taxii/) onunde durur ve
TAXII 2.1 sorgu semantik katmanini ekler — boylece self-hosted (Docker/K8s)
dagitim, Cloudflare Worker ile DAVRANIS PARITY'sine ulasir ve her standart
client (QRadar, Splunk, MISP, OpenCTI, Sentinel) ayni servisten cekebilir.

Eklenen katman:
  - ?added_after=T   spec'e gore date_added uzerinden filtre (page meta: max_date_added)
  - ?limit=N         sayfa boyutu (cap 10000); kalan > N ise next cursor ile devam
  - ?next=cursor     "NNNN" veya "NNNN.OFFSET" — kucuk limit'lerde sayfa-ici ilerleme
  - ?match[id]/[type] spec opsiyonel filtreleri
  - __TAXII_BASE__ -> istegin host'una rewrite (X-Forwarded-Proto/Host saygili)
  - Content-Type: application/taxii+json;version=2.1 (tek obje: stix+json)
  - CORS (anonim erisim), TAXII media-type hata govdesi

nginx '/taxii2/' ve '/api/'yi bu servise proxy'ler; '.txt' feed'leri, stats.json
ve html'i kendisi servis eder. Statik agac tek kaynak (Worker ile ortak); servis
onu okur, STIX donusumunu TEKRAR etmez.

Calistirma:
  uvicorn taxii_server:app --host 127.0.0.1 --port 8081
  python taxii_server.py            # dev: uvicorn'u kendi baslatir
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
from functools import lru_cache
from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

# ---------------------------------------------------------------------------
# Sabitler / config
# ---------------------------------------------------------------------------

_ROOT_OVERRIDE = os.environ.get("SGB_BRIDGE_ROOT")
ROOT = Path(_ROOT_OVERRIDE) if _ROOT_OVERRIDE else Path(__file__).resolve().parent.parent
TAXII_DIR = ROOT / "docs" / "taxii"

# Sabit domain dagitimi icin opsiyonel override; bos ise host istekten turetilir.
PUBLIC_BASE_OVERRIDE = os.environ.get("SGB_TAXII_PUBLIC_BASE", "").rstrip("/")

BASE_PLACEHOLDER = "__TAXII_BASE__"
TAXII_CT = "application/taxii+json;version=2.1"
STIX_CT = "application/stix+json;version=2.1"
LIMIT_CAP = 10000

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
    "Access-Control-Allow-Headers": "Accept, Content-Type, Range",
    "Access-Control-Max-Age": "86400",
}
CACHE_CONTROL = f"public, max-age={os.environ.get('SGB_TAXII_EDGE_TTL', '300')}"

_CID_RE = re.compile(r"^[a-z0-9-]+$")
_COLLECTION_RE = re.compile(
    r"^/api/collections/(?P<cid>[a-z0-9-]+)"
    r"(?:/(?P<kind>objects|manifest)(?:/(?P<sub>[^/]+))?)?$"
)
_STIX_ID_RE = re.compile(r"^[a-z][a-z-]*--[a-f0-9-]{36}$")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("taxii_server")


# ---------------------------------------------------------------------------
# Dosya erisimi (mtime-aware cache)
# ---------------------------------------------------------------------------

@lru_cache(maxsize=256)
def _read_text_cached(path_str: str, mtime: float) -> str:
    """Ham dosya icerigi; (path, mtime) anahtarli cache. build atomik yazar,
    mtime degisince yeni surum okunur."""
    return Path(path_str).read_text(encoding="utf-8")


def read_text(path: Path) -> str | None:
    try:
        return _read_text_cached(str(path), path.stat().st_mtime)
    except FileNotFoundError:
        return None


def read_json(path: Path):
    txt = read_text(path)
    return None if txt is None else json.loads(txt)


def read_page(path: Path) -> dict | None:
    """Sayfa dosyalari buyuk olabilir (5000 obje); cache'lemeyiz, istek basina
    okuruz (OS dosya cache yeterli, bellek sinirli kalir)."""
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None


# ---------------------------------------------------------------------------
# Yanit yardimcilari
# ---------------------------------------------------------------------------

def _public_base(request: Request) -> str:
    if PUBLIC_BASE_OVERRIDE:
        return PUBLIC_BASE_OVERRIDE
    scheme = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    return f"{scheme}://{host}"


def _json_bytes(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def taxii_response(request: Request, obj, content_type: str = TAXII_CT) -> Response:
    body = _json_bytes(obj)
    headers = {"Cache-Control": CACHE_CONTROL, **CORS_HEADERS}
    if request.method == "HEAD":
        body = b""
    return Response(body, status_code=200, media_type=content_type, headers=headers)


def static_response(request: Request, path: Path, content_type: str = TAXII_CT) -> Response:
    raw = read_text(path)
    if raw is None:
        return error_response(404, "Not Found")
    body = raw.replace(BASE_PLACEHOLDER, _public_base(request)).encode("utf-8")
    headers = {"Cache-Control": CACHE_CONTROL, **CORS_HEADERS}
    if request.method == "HEAD":
        body = b""
    return Response(body, status_code=200, media_type=content_type, headers=headers)


def error_response(status: int, msg: str) -> Response:
    body = _json_bytes({"title": "Error", "http_status": str(status), "description": msg})
    return Response(body, status_code=status, media_type=TAXII_CT, headers=dict(CORS_HEADERS))


# ---------------------------------------------------------------------------
# Sorgu param parse
# ---------------------------------------------------------------------------

def _parse_limit(raw: str | None) -> int | None:
    if not raw:
        return None
    try:
        n = int(raw)
    except ValueError:
        return None
    if n < 1:
        return None
    return min(n, LIMIT_CAP)


def _parse_cursor(raw: str) -> tuple[int, int] | None:
    """'NNNN' veya 'NNNN.OFFSET' -> (page, offset). Gecersizse None."""
    dot = raw.find(".")
    p_str = raw if dot == -1 else raw[:dot]
    try:
        page = int(p_str)
        offset = int(raw[dot + 1:]) if dot != -1 else 0
    except ValueError:
        return None
    if page < 1 or offset < 0:
        return None
    return page, offset


def _match_filters(params) -> tuple[set[str] | None, set[str] | None]:
    ids = params.get("match[id]")
    types = params.get("match[type]")
    id_set = {x for x in ids.split(",") if x} if ids else None
    type_set = {x for x in types.split(",") if x} if types else None
    return id_set, type_set


# ---------------------------------------------------------------------------
# Envelope (objects / manifest) — sayfalama + filtre
# ---------------------------------------------------------------------------

def serve_envelope(request: Request, cid: str, kind: str) -> Response:
    pages_index = read_json(TAXII_DIR / "api" / "collections" / cid / "pages.json")
    if pages_index is None:
        return error_response(404, f"Collection not found: {cid}")
    pages = pages_index.get("pages", [])

    p = request.query_params
    added_after = p.get("added_after")
    next_cursor = p.get("next")
    limit = _parse_limit(p.get("limit"))
    id_set, type_set = _match_filters(p)

    # Baslangic sayfasi + sayfa-ici offset
    start_page, start_offset = 1, 0
    if next_cursor:
        parsed = _parse_cursor(next_cursor)
        if parsed is None:
            return error_response(400, "Invalid next cursor")
        start_page, start_offset = parsed
    elif added_after:
        # modified > T olan ilk sayfa. Sayfalar modified-ASC -> max_last_changed
        # monoton; QRadar gibi added_after'i max(modified) ile ilerleten client'lar
        # atlamasiz gezer.
        idx = next((i for i, pm in enumerate(pages)
                    if pm.get("max_last_changed", "") > added_after), None)
        start_page = len(pages) + 1 if idx is None else idx + 1

    if start_page > len(pages):
        return taxii_response(request, {"more": False, "objects": []})

    page_meta = pages[start_page - 1]
    page = read_page(TAXII_DIR / "api" / "collections" / cid / kind / page_meta["file"])
    if page is None:
        return error_response(404, "Page not found")
    objects = page.get("objects", [])

    # added_after filtresi: STIX 'modified' uzerinden ("changed after"). Sayfalar
    # modified-ASC oldugundan QRadar'in max(modified) cursor'i ile tam tutarli.
    # objects -> modified (identity her zaman kalir); manifest -> version (= modified).
    if added_after:
        if kind == "manifest":
            objects = [o for o in objects if o.get("version", "") > added_after]
        else:
            objects = [o for o in objects
                       if o.get("type") == "identity" or o.get("modified", "") > added_after]

    # match[id] / match[type]
    if id_set is not None:
        objects = [o for o in objects if o.get("id") in id_set]
    if type_set is not None:
        if kind == "manifest":
            objects = [o for o in objects
                       if (o.get("id", "").split("--", 1)[0]) in type_set]
        else:
            objects = [o for o in objects if o.get("type") in type_set]

    # sayfa-ici offset (onceki limit kirpmasinin kaldigi yer)
    if start_offset > 0:
        objects = objects[start_offset:]

    # limit + cursor: kalan > limit ise AYNI sayfada offset'li devam; degilse sonraki sayfa.
    envelope: dict = {"more": False, "objects": objects}
    if limit is not None and len(objects) > limit:
        envelope["objects"] = objects[:limit]
        envelope["more"] = True
        envelope["next"] = f"{start_page:04d}.{start_offset + limit}"
    else:
        has_more = start_page < len(pages)
        envelope["more"] = has_more
        if has_more:
            envelope["next"] = f"{start_page + 1:04d}"

    return taxii_response(request, envelope)


# ---------------------------------------------------------------------------
# Tek obje
# ---------------------------------------------------------------------------

def serve_single_object(request: Request, cid: str, stix_id: str) -> Response:
    if not _STIX_ID_RE.match(stix_id):
        return error_response(400, "Invalid STIX id")
    pages_index = read_json(TAXII_DIR / "api" / "collections" / cid / "pages.json")
    if pages_index is None:
        return error_response(404, f"Collection not found: {cid}")
    for pm in pages_index.get("pages", []):
        page = read_page(TAXII_DIR / "api" / "collections" / cid / "objects" / pm["file"])
        if not page:
            continue
        for o in page.get("objects", []):
            if o.get("id") == stix_id:
                return taxii_response(request, {"more": False, "objects": [o]}, STIX_CT)
    return error_response(404, "Object not found in collection")


# ---------------------------------------------------------------------------
# Dispatch (Worker index.ts ile birebir yol mantigi)
# ---------------------------------------------------------------------------

async def dispatch(request: Request) -> Response:
    if request.method == "OPTIONS":
        return Response(status_code=204, headers=dict(CORS_HEADERS))
    if request.method not in ("GET", "HEAD"):
        return error_response(405, "Method Not Allowed")

    path = request.url.path.rstrip("/") or "/"

    if path == "/taxii2":
        return static_response(request, TAXII_DIR / "taxii2" / "index.json")
    if path == "/api":
        return static_response(request, TAXII_DIR / "api" / "index.json")
    if path == "/api/collections":
        return static_response(request, TAXII_DIR / "api" / "collections" / "index.json")

    m = _COLLECTION_RE.match(path)
    if m:
        cid, kind, sub = m.group("cid"), m.group("kind"), m.group("sub")
        if not kind:
            return static_response(request, TAXII_DIR / "api" / "collections" / cid / "index.json")
        if kind == "objects" and sub:
            return serve_single_object(request, cid, sub)
        return serve_envelope(request, cid, kind)

    return error_response(404, "Not Found")


app = Starlette(routes=[Route("/{path:path}", dispatch, methods=["GET", "HEAD", "OPTIONS"])])


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host=os.environ.get("SGB_TAXII_HOST", "127.0.0.1"),
        port=int(os.environ.get("SGB_TAXII_PORT", "8081")),
    )
