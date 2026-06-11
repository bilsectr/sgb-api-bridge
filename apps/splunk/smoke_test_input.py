#!/usr/bin/env python3
"""sgb_taxii modular input'unu canli TAXII servisine karsi calistirir.

Splunk'in run-time'da stdin'e verdigi <input> XML'ini simule eder,
event stream'ini parse edip ozetler. Kucuk koleksiyon (sgb-mining) ile
hizli kosar; ikinci kosumda checkpoint'in calistigini da dogrular.
"""
import io
import json
import os
import sys
import tempfile
import xml.etree.ElementTree as ET
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "TA-sgb-threat-intel", "bin"))
import sgb_taxii  # noqa: E402

INPUT_XML = """<?xml version="1.0" encoding="UTF-8"?>
<input>
  <server_host>localhost</server_host>
  <server_uri>https://127.0.0.1:8089</server_uri>
  <session_key>dummy</session_key>
  <checkpoint_dir>{ckpt}</checkpoint_dir>
  <configuration>
    <stanza name="sgb_taxii://SGB-Mining-Test">
      <param name="discovery_url">https://sgb-taxii.bilsec.tr/taxii2/</param>
      <param name="collection">sgb-mining</param>
      <param name="page_limit">5000</param>
    </stanza>
  </configuration>
</input>
"""


def run_once(ckpt_dir):
    sys.stdin = io.StringIO(INPUT_XML.format(ckpt=ckpt_dir))
    out = io.StringIO()
    with redirect_stdout(out):
        sgb_taxii.run()
    return out.getvalue()


def summarize(stream_xml, label):
    root = ET.fromstring(stream_xml)
    events = root.findall("event")
    cts, types = {}, {}
    sample = None
    for ev in events:
        data = json.loads(ev.findtext("data"))
        if sample is None:
            sample = data
        cts[data.get("connectiontype")] = cts.get(data.get("connectiontype"), 0) + 1
        types[data.get("type")] = types.get(data.get("type"), 0) + 1
        assert data.get("value"), "value bos: %r" % data
        assert ev.findtext("time"), "time elemani yok"
    print(f"[{label}] event={len(events)} ct={cts} type={types}")
    if sample:
        print(f"[{label}] ornek: " + json.dumps(sample, ensure_ascii=False)[:300])
    return len(events)


with tempfile.TemporaryDirectory() as ckpt:
    n1 = summarize(run_once(ckpt), "ilk pull (full)")
    ckpt_files = os.listdir(ckpt)
    print("checkpoint dosyalari:", ckpt_files)
    assert ckpt_files, "checkpoint yazilmadi"
    print("checkpoint icerik:", open(os.path.join(ckpt, ckpt_files[0])).read())
    n2 = summarize(run_once(ckpt), "ikinci pull (incremental)")
    assert n1 > 0, "ilk pull bos dondu"
    assert n2 < n1, f"incremental calismiyor gibi: ilk={n1} ikinci={n2}"
    print(f"\nSMOKE TEST GECTI: full={n1} event, incremental={n2} event")
