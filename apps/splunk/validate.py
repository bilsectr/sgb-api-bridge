#!/usr/bin/env python3
"""Hizli yerel dogrulama: XML parse, scheme, annotation JSON, conf yapisi.

AppInspect'in tam kapsamini ikame etmez (o CI'da kosar); paketlemeden once
bariz hatalari yakalar.
"""
import contextlib
import configparser
import glob
import io
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
errors = []


def check(label, fn):
    try:
        fn()
        print("OK  " + label)
    except Exception as exc:
        errors.append(f"{label}: {exc}")
        print("ERR " + label + ": " + str(exc))


# 1) UI XML'leri
for f in glob.glob(os.path.join(HERE, "sgb_usecases", "default", "data", "ui", "**", "*.xml"), recursive=True):
    check("xml " + os.path.relpath(f, HERE), lambda f=f: ET.parse(f))

# 2) Modular input scheme XML
def scheme():
    sys.path.insert(0, os.path.join(HERE, "TA-sgb-threat-intel", "bin"))
    import sgb_taxii
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        sgb_taxii.do_scheme()
    ET.fromstring(buf.getvalue())
check("modular input scheme XML", scheme)

# 3) .conf dosyalari parse edilebiliyor mu (line continuation'lari birlestirerek)
def parse_conf(path):
    raw = open(path, encoding="utf-8").read()
    joined = re.sub(r"\\\r?\n", " ", raw)
    cp = configparser.ConfigParser(strict=True, interpolation=None)
    cp.read_string(joined)
    return cp

conf_files = glob.glob(os.path.join(HERE, "*", "default", "*.conf"))
for f in conf_files:
    check("conf " + os.path.relpath(f, HERE), lambda f=f: parse_conf(f))

# 4) Annotation JSON'lari + UC stanza sayisi
def annotations():
    path = os.path.join(HERE, "sgb_usecases", "default", "savedsearches.conf")
    txt = open(path, encoding="utf-8").read()
    found = re.findall(r"^action\.correlationsearch\.annotations = (.+)$", txt, re.M)
    for j in found:
        json.loads(j)
    stanzas = re.findall(r"^\[(SGB - UC-[^\]]+)\]", txt, re.M)
    if len(stanzas) != 25:  # 24 UC; UC-XX-004 iki arama (A + B)
        raise AssertionError(f"beklenen 25 UC stanza, bulunan {len(stanzas)}: {stanzas}")
    if len(found) != len(stanzas):
        raise AssertionError(f"{len(stanzas)} stanza ama {len(found)} annotation")
check("correlation annotations + stanza sayisi", annotations)

# 5) UC aramalarinin kullandigi makrolar tanimli mi
def macros_defined():
    app_macros = parse_conf(os.path.join(HERE, "sgb_usecases", "default", "macros.conf"))
    ta_macros = parse_conf(os.path.join(HERE, "TA-sgb-threat-intel", "default", "macros.conf"))
    defined = set()
    for cp in (app_macros, ta_macros):
        for s in cp.sections():
            defined.add(re.sub(r"\(\d+\)$", "", s))
    used = set()
    for f in glob.glob(os.path.join(HERE, "*", "default", "savedsearches.conf")):
        txt = re.sub(r"\\\r?\n", " ", open(f, encoding="utf-8").read())
        for m in re.finditer(r"`(sgb_[a-z0-9_]+)(?:\([^)]*\))?`", txt):
            used.add(m.group(1))
    missing = used - defined
    if missing:
        raise AssertionError(f"tanimsiz makro: {sorted(missing)}")
check("makro referanslari", macros_defined)

# 6) Lookup referanslari transforms'ta tanimli mi
def lookups_defined():
    cp = parse_conf(os.path.join(HERE, "TA-sgb-threat-intel", "default", "transforms.conf"))
    defined = set(cp.sections())
    used = set()
    for f in glob.glob(os.path.join(HERE, "*", "default", "savedsearches.conf")) + glob.glob(
        os.path.join(HERE, "sgb_usecases", "default", "data", "ui", "views", "*.xml")
    ):
        txt = re.sub(r"\\\r?\n", " ", open(f, encoding="utf-8").read())
        for m in re.finditer(r"(?:\blookup|inputlookup|outputlookup)(?:\s+append=t)?\s+(sgb_[a-z0-9_]+)", txt):
            used.add(m.group(1))
    missing = used - defined
    if missing:
        raise AssertionError(f"tanimsiz lookup: {sorted(missing)}")
check("lookup referanslari", lookups_defined)

print()
if errors:
    print(f"{len(errors)} HATA")
    sys.exit(1)
print("Tum kontroller gecti.")
