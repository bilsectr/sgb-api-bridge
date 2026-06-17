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
    pages = (ROOT / "docs/taxii/api/collections" / COL / "pages.json")
    import json
    max_added = json.loads(pages.read_text(encoding="utf-8"))["pages"][0]["max_date_added"]
    env = client.get(f"/api/collections/{COL}/objects/?added_after={max_added}").json()
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
