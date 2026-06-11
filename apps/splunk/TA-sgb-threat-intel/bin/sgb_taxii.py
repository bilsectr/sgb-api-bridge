#!/usr/bin/env python3
"""
sgb_taxii — TAXII 2.1 modular input (SGB threat feed).

SGB (Siber Guvenlik Baskanligi, eski USOM) TAXII 2.1 servisinden STIX 2.1
indicator'larini ceker ve her birini tek satirlik JSON event olarak Splunk'a
yazar. Incremental polling: her basarili run'dan sonra gorulen en buyuk STIX
`modified` degeri checkpoint'e yazilir; sonraki run `added_after` ile yalniz
yeni/degisen kayitlari ceker.

Yalniz stdlib kullanir (urllib) — bundled dependency yok.
"""

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from xml.sax.saxutils import escape

DEFAULT_DISCOVERY_URL = "https://sgb-taxii.bilsec.tr/taxii2/"
DEFAULT_PAGE_LIMIT = 5000
TAXII_ACCEPT = "application/taxii+json;version=2.1"
USER_AGENT = "TA-sgb-threat-intel/1.0 (+https://github.com/bilsectr/sgb-api-bridge)"
HTTP_TIMEOUT_SEC = 120
HTTP_RETRIES = 3
RETRY_BACKOFF_SEC = 10

# STIX pattern'den deger cikarmak icin (x_sgb_value yoksa fallback)
_PATTERN_RE = re.compile(
    r"\[(?:domain-name|url|ipv4-addr|ipv6-addr):value\s*=\s*'((?:[^'\\]|\\.)*)'\]"
)


def log(level, msg):
    # splunkd.log'a duser (component=ExecProcessor)
    sys.stderr.write("%s sgb_taxii: %s\n" % (level, msg))
    sys.stderr.flush()


def do_scheme():
    sys.stdout.write(
        """<scheme>
  <title>SGB TAXII 2.1 Threat Feed</title>
  <description>Polls a SGB TAXII 2.1 collection and indexes STIX 2.1 indicators as JSON events.</description>
  <use_external_validation>true</use_external_validation>
  <streaming_mode>xml</streaming_mode>
  <use_single_instance>false</use_single_instance>
  <endpoint>
    <args>
      <arg name="discovery_url">
        <title>Discovery URL</title>
        <description>TAXII 2.1 discovery endpoint. Default: https://sgb-taxii.bilsec.tr/taxii2/</description>
        <required_on_create>false</required_on_create>
      </arg>
      <arg name="api_root">
        <title>API root URL</title>
        <description>Optional. Overrides API root resolution from the discovery document.</description>
        <required_on_create>false</required_on_create>
      </arg>
      <arg name="collection">
        <title>Collection alias</title>
        <description>TAXII collection alias, e.g. sgb-phishing.</description>
        <required_on_create>true</required_on_create>
      </arg>
      <arg name="page_limit">
        <title>Page limit</title>
        <description>Objects per page request. Default: 5000.</description>
        <required_on_create>false</required_on_create>
      </arg>
    </args>
  </endpoint>
</scheme>
"""
    )


def _read_input_config():
    """stdin'deki <input> XML'ini parse eder (run ve validate modlari)."""
    root = ET.fromstring(sys.stdin.read())
    conf = {
        "checkpoint_dir": (root.findtext("checkpoint_dir") or "").strip(),
        "stanzas": [],
    }
    # validate modunda <item>, run modunda <configuration><stanza> gelir
    for stanza in root.iter("stanza"):
        params = {p.get("name"): (p.text or "").strip() for p in stanza.iter("param")}
        conf["stanzas"].append({"name": stanza.get("name"), "params": params})
    item = root.find("item")
    if item is not None:
        params = {p.get("name"): (p.text or "").strip() for p in item.iter("param")}
        conf["stanzas"].append({"name": item.get("name"), "params": params})
    return conf


def _validate_params(params):
    collection = params.get("collection", "")
    if not collection:
        raise ValueError("collection is required")
    if not re.match(r"^[A-Za-z0-9._-]+$", collection):
        raise ValueError("collection contains invalid characters: %r" % collection)
    for key in ("discovery_url", "api_root"):
        val = params.get(key, "")
        if val and not val.startswith(("http://", "https://")):
            raise ValueError("%s must be an http(s) URL" % key)
    limit = params.get("page_limit", "")
    if limit and (not limit.isdigit() or int(limit) < 1):
        raise ValueError("page_limit must be a positive integer")


def validate_arguments():
    try:
        conf = _read_input_config()
        for stanza in conf["stanzas"]:
            _validate_params(stanza["params"])
    except Exception as exc:
        sys.stdout.write("<error><message>%s</message></error>" % escape(str(exc)))
        sys.exit(1)


def _http_get_json(url):
    req = urllib.request.Request(
        url, headers={"Accept": TAXII_ACCEPT, "User-Agent": USER_AGENT}
    )
    last_err = None
    for attempt in range(1, HTTP_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SEC) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, ValueError) as exc:
            last_err = exc
            log("WARN", "GET %s attempt %d/%d failed: %s" % (url, attempt, HTTP_RETRIES, exc))
            if attempt < HTTP_RETRIES:
                time.sleep(RETRY_BACKOFF_SEC * attempt)
    raise RuntimeError("GET %s failed after %d attempts: %s" % (url, HTTP_RETRIES, last_err))


def _resolve_api_root(params):
    api_root = params.get("api_root", "")
    if api_root:
        return api_root if api_root.endswith("/") else api_root + "/"
    discovery_url = params.get("discovery_url") or DEFAULT_DISCOVERY_URL
    disc = _http_get_json(discovery_url)
    root = disc.get("default") or (disc.get("api_roots") or [None])[0]
    if not root:
        raise RuntimeError("discovery document has no api root: %s" % discovery_url)
    return root if root.endswith("/") else root + "/"


def _checkpoint_path(checkpoint_dir, stanza_name):
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", stanza_name)
    return os.path.join(checkpoint_dir, safe + ".json")


def _load_checkpoint(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save_checkpoint(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, path)


def _iso_to_epoch(iso_ts):
    if not iso_ts:
        return None
    try:
        ts = iso_ts.rstrip("Z")
        if "." in ts:
            dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f")
        else:
            dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S")
        return dt.replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


def _indicator_to_event(obj):
    value = obj.get("x_sgb_value")
    if not value:
        m = _PATTERN_RE.search(obj.get("pattern") or "")
        value = m.group(1).replace("\\'", "'").replace("\\\\", "\\") if m else None
    return {
        "stix_id": obj.get("id"),
        "value": value,
        "type": obj.get("x_sgb_type"),
        "connectiontype": obj.get("x_sgb_connectiontype"),
        "criticality_level": obj.get("x_sgb_criticality"),
        "sgb_source": obj.get("x_sgb_source"),
        "category": obj.get("x_sgb_description"),
        "confidence": obj.get("confidence"),
        "sgb_id": obj.get("x_sgb_id"),
        "api_date": obj.get("x_sgb_api_date"),
        "labels": obj.get("labels"),
        "pattern": obj.get("pattern"),
        "created": obj.get("created"),
        "modified": obj.get("modified"),
    }


def _emit_event(stanza_name, event_dict, epoch):
    payload = json.dumps(event_dict, ensure_ascii=False, separators=(",", ":"))
    sys.stdout.write("<event stanza=\"%s\">" % escape(stanza_name, {'"': "&quot;"}))
    if epoch is not None:
        sys.stdout.write("<time>%.3f</time>" % epoch)
    sys.stdout.write("<data>%s</data></event>\n" % escape(payload))


def _poll_collection(stanza_name, params, checkpoint_dir):
    collection = params["collection"]
    page_limit = int(params.get("page_limit") or DEFAULT_PAGE_LIMIT)
    api_root = _resolve_api_root(params)
    objects_url = "%scollections/%s/objects/" % (api_root, urllib.parse.quote(collection))

    ckpt_path = _checkpoint_path(checkpoint_dir, stanza_name)
    ckpt = _load_checkpoint(ckpt_path)
    added_after = ckpt.get("added_after")

    query = {"limit": str(page_limit)}
    if added_after:
        query["added_after"] = added_after

    total = 0
    max_modified = added_after or ""
    next_cursor = None
    while True:
        q = dict(query)
        if next_cursor:
            q["next"] = next_cursor
        url = objects_url + "?" + urllib.parse.urlencode(q)
        envelope = _http_get_json(url)
        for obj in envelope.get("objects") or []:
            if obj.get("type") != "indicator":
                continue
            ev = _indicator_to_event(obj)
            modified = ev.get("modified") or ""
            _emit_event(stanza_name, ev, _iso_to_epoch(modified) or time.time())
            if modified > max_modified:
                max_modified = modified
            total += 1
        if envelope.get("more") and envelope.get("next"):
            next_cursor = envelope["next"]
        else:
            break

    if max_modified:
        _save_checkpoint(ckpt_path, {"added_after": max_modified, "updated": time.time()})
    log("INFO", "stanza=%s collection=%s indicators=%d added_after=%s"
        % (stanza_name, collection, total, added_after or "(full)"))


def run():
    conf = _read_input_config()
    checkpoint_dir = conf["checkpoint_dir"] or "."
    sys.stdout.write("<stream>\n")
    try:
        for stanza in conf["stanzas"]:
            try:
                _poll_collection(stanza["name"], stanza["params"], checkpoint_dir)
            except Exception as exc:  # tek stanza hatasi run'i oldurmesin
                log("ERROR", "stanza=%s failed: %s" % (stanza["name"], exc))
    finally:
        sys.stdout.write("</stream>\n")
        sys.stdout.flush()


def main():
    if len(sys.argv) > 1:
        if sys.argv[1] == "--scheme":
            do_scheme()
            return
        if sys.argv[1] == "--validate-arguments":
            validate_arguments()
            return
    run()


if __name__ == "__main__":
    main()
