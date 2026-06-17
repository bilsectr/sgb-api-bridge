"""taxii_server.py icin spec-davranis testleri (Starlette TestClient).

Commit'li docs/taxii/ agacina karsi calisir. CI'da ve lokalde:
  pip install starlette httpx pytest
  pytest tests/test_taxii_server.py
"""
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
os.environ["SGB_BRIDGE_ROOT"] = str(ROOT)
sys.path.insert(0, str(ROOT / "scripts"))

from starlette.testclient import TestClient  # noqa: E402
import taxii_server  # noqa: E402

client = TestClient(taxii_server.app)

TAXII_CT = "application/taxii+json;version=2.1"
STIX_CT = "application/stix+json;version=2.1"
COL = "sgb-mining"  # kucuk koleksiyon (tek sayfa) — sayim sync'le degisir, pages.json'dan okunur

import json as _json  # noqa: E402
_PAGES = _json.loads((ROOT / "docs/taxii/api/collections" / COL / "pages.json").read_text(encoding="utf-8"))
EXPECTED_INDICATORS = _PAGES["total_objects"]
assert len(_PAGES["pages"]) == 1, f"{COL} test icin tek sayfa olmali (su an {len(_PAGES['pages'])})"


# --- Discovery / API root / collections list ---

def test_discovery_base_rewrite_and_ct():
    r = client.get("/taxii2/")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith(TAXII_CT)
    body = r.json()
    # __TAXII_BASE__ istegin host'una rewrite edilmeli
    assert body["api_roots"] == ["http://testserver/api/"]
    assert "__TAXII_BASE__" not in r.text


def test_api_root_versions():
    r = client.get("/api/")
    assert r.status_code == 200
    assert TAXII_CT in r.json()["versions"]


def test_collections_list_id_equals_alias():
    r = client.get("/api/collections/")
    assert r.status_code == 200
    cols = r.json()["collections"]
    for c in cols:
        assert c["id"] == c["alias"]  # spec: id == URL segmenti


def test_collection_meta():
    r = client.get(f"/api/collections/{COL}/")
    assert r.status_code == 200
    assert r.json()["id"] == COL


# --- Envelope: sayfalama / filtre ---

def test_objects_full_single_page():
    r = client.get(f"/api/collections/{COL}/objects/")
    assert r.status_code == 200
    env = r.json()
    assert env["more"] is False
    inds = [o for o in env["objects"] if o.get("type") == "indicator"]
    assert len(inds) == EXPECTED_INDICATORS
    assert any(o.get("type") == "identity" for o in env["objects"])


def test_limit_and_next_cursor_progress():
    r1 = client.get(f"/api/collections/{COL}/objects/?limit=50")
    e1 = r1.json()
    assert len(e1["objects"]) == 50
    assert e1["more"] is True
    assert e1["next"] == "0001.50"

    r2 = client.get(f"/api/collections/{COL}/objects/?limit=50&next={e1['next']}")
    e2 = r2.json()
    assert len(e2["objects"]) == 50
    assert e2["objects"][0]["id"] != e1["objects"][0]["id"]  # ilerleme var


def test_limit_pagination_terminates_and_covers_all():
    """QRadar-benzeri: next cursor ile tum sayfayi gez, bitmeli + tam kapsam."""
    seen, nxt, guard = [], None, 0
    while True:
        guard += 1
        assert guard < 1000, "sonsuz dongu!"
        q = "?limit=50" + (f"&next={nxt}" if nxt else "")
        env = client.get(f"/api/collections/{COL}/objects/{q}").json()
        seen.extend(o["id"] for o in env["objects"])
        if not env.get("more"):
            break
        nxt = env["next"]
    # identity + 206 indicator = 207 (her sayfada identity tekrar gelir; sayfa tek)
    assert len([s for s in seen if s.startswith("indicator--")]) == EXPECTED_INDICATORS


def test_added_after_max_returns_empty():
    # added_after artik 'modified' uzerinden -> sayfa max_last_changed'ini kullan
    max_mod = _PAGES["pages"][0]["max_last_changed"]
    env = client.get(f"/api/collections/{COL}/objects/?added_after={max_mod}").json()
    assert env["more"] is False
    assert [o for o in env["objects"] if o.get("type") == "indicator"] == []


def test_added_after_old_returns_all():
    env = client.get(f"/api/collections/{COL}/objects/?added_after=2000-01-01T00:00:00.000Z").json()
    inds = [o for o in env["objects"] if o.get("type") == "indicator"]
    assert len(inds) == EXPECTED_INDICATORS


def test_manifest_records():
    env = client.get(f"/api/collections/{COL}/manifest/").json()
    assert all("media_type" in o and "date_added" in o for o in env["objects"])


def test_match_type_filter():
    env = client.get(f"/api/collections/{COL}/objects/?match[type]=identity").json()
    assert all(o["type"] == "identity" for o in env["objects"])


# --- Tek obje ---

def test_single_object_roundtrip():
    env = client.get(f"/api/collections/{COL}/objects/?limit=5").json()
    ind = next(o for o in env["objects"] if o["type"] == "indicator")
    r = client.get(f"/api/collections/{COL}/objects/{ind['id']}/")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith(STIX_CT)
    got = r.json()["objects"]
    assert len(got) == 1 and got[0]["id"] == ind["id"]


def test_single_object_invalid_id():
    assert client.get(f"/api/collections/{COL}/objects/not-a-stix-id/").status_code == 400


# --- Hata / CORS / method ---

def test_unknown_collection_404():
    r = client.get("/api/collections/does-not-exist/")
    assert r.status_code == 404
    assert r.headers["content-type"].startswith(TAXII_CT)


def test_options_cors():
    r = client.options("/taxii2/")
    assert r.status_code == 204
    assert r.headers["access-control-allow-origin"] == "*"


def test_post_not_allowed():
    assert client.post("/taxii2/").status_code == 405


# --- QRadar-simulasyon: added_after = max(modified) cursor ile TAM kapsam ---

def _write_synth_tree(base, n_pages=3, per_page=4):
    """modified-ASC sirali sentetik koleksiyon yazar (build_taxii ciktisi gibi)."""
    col = base / "api" / "collections" / "synth" / "objects"
    col.mkdir(parents=True, exist_ok=True)
    identity = {"type": "identity",
                "id": "identity--00000000-0000-4000-8000-000000000000",
                "modified": "2020-01-01T00:00:00.000Z"}
    pages_meta, k = [], 0
    for p in range(1, n_pages + 1):
        objs, last_mod = [identity], None
        for _ in range(per_page):
            k += 1
            mod = f"2026-01-{k:02d}T00:00:00.000Z"
            objs.append({"type": "indicator",
                         "id": f"indicator--{k:08d}-0000-4000-8000-000000000000",
                         "modified": mod, "created": mod})
            last_mod = mod
        is_last = p == n_pages
        env = {"more": not is_last, "objects": objs}
        if not is_last:
            env["next"] = f"{p + 1:04d}"
        (col / f"page-{p:04d}.json").write_text(_json.dumps(env), encoding="utf-8")
        pages_meta.append({"page": p, "file": f"page-{p:04d}.json", "count": per_page,
                           "max_last_changed": last_mod, "max_date_added": last_mod})
    (base / "api/collections/synth/pages.json").write_text(
        _json.dumps({"collection_id": "synth", "alias": "synth", "page_size": per_page,
                     "total_objects": k, "pages": pages_meta}), encoding="utf-8")
    return k


def test_qradar_style_added_after_full_coverage(tmp_path, monkeypatch):
    """QRadar get_all_objects'i taklit: 'next' cursor'u YOKSAY, added_after'i
    max(modified) ile ilerlet, len<limit'te dur. modified-sirali agacta TAM kapsam
    + sonlanma garanti olmali (eski id-sirali + date_added kurgusu burada atlardi)."""
    total = _write_synth_tree(tmp_path)
    monkeypatch.setattr(taxii_server, "TAXII_DIR", tmp_path)
    LIMIT = 3
    seen, aa, guard = set(), "2025-01-01T00:00:00.000Z", 0
    while True:
        guard += 1
        assert guard < 500, "ilerlemiyor / sonsuz dongu"
        env = client.get(f"/api/collections/synth/objects/?added_after={aa}&limit={LIMIT}").json()
        objs = env["objects"]
        inds = [o for o in objs if o.get("type") == "indicator"]
        seen |= {o["id"] for o in inds}
        if len(objs) < LIMIT:          # QRadar per_request dur kosulu
            break
        new_aa = max((o["modified"] for o in inds), default=aa)
        assert new_aa > aa, "cursor ilerlemedi -> atlama/dongu riski"
        aa = new_aa
    assert len(seen) == total          # hicbir indicator atlanmadi
