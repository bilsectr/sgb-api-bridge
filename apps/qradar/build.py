#!/usr/bin/env python3
"""
QRadar dagitim paketi ureticisi.

CMT (Content Management Tool) export zip'ini dogrulayip dagitim paketine
cevirir: icine README + LICENSE eklenmis bir release zip'i.

    python apps/qradar/build.py --input sgb-usecases-export.zip --version 1.0.0

Cikti: apps/qradar/dist/sgb-qradar-content-<version>.zip
  ├── sgb-usecases-content-<version>.zip   (CMT export'u — QRadar'a IMPORT EDILECEK dosya)
  ├── README.md                            (kurulum adimlari)
  └── LICENSE

Not: CMT zip'inin icine dokunulmaz (QRadar import formatini bozmamak icin);
dagitim paketi onu sarmalayan zarftir. App Exchange'e gonderimde CMT zip'i
tek basina yuklenir.
"""
import argparse
import os
import shutil
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))

INSTALL_README = """# SGB QRadar Content Extension v{version}

SGB (Siber Guvenlik Baskanligi, eski USOM) tehdit feed'i icin 24 hazir
korelasyon kurali. Community projesi — SGB ile resmi baglantisi yoktur.

## Kurulum

1. **TAXII feed'leri + reference set'ler** (extension'a gomulemez):
   https://github.com/bilsectr/sgb-api-bridge/blob/main/apps/qradar/setup_feeds.py
   script'i ile veya elle (docs/integrations/qradar.md Adim 1).
2. **Extension import:** Admin -> Extensions Management -> Add ->
   `sgb-usecases-content-{version}.zip` -> Install. "Replace existing items"
   secenegini ilk kurulumda isaretlemeyin.
3. **Dogrulama:** Offenses -> Rules -> Group: "SGB Use Cases" altinda
   24 kural gorunmeli. Kurallar disabled gelir; devreye alma sirasi icin:
   https://github.com/bilsectr/sgb-api-bridge/blob/main/docs/usecases/README.md#tiers

## Gereksinimler

- QRadar 7.5+ (Threat Intelligence app kurulu, TAXII 2.1 feed'ler "Connected")
- Feed'ler icin dis erisim: sgb-taxii.bilsec.tr:443 (veya self-hosted TAXII)

Dokumantasyon: https://github.com/bilsectr/sgb-api-bridge
Lisans: MIT
"""


def validate_cmt_zip(path):
    """CMT export zip'inin bos/bozuk olmadigini kontrol eder."""
    with zipfile.ZipFile(path) as z:
        bad = z.testzip()
        if bad:
            raise SystemExit(f"bozuk zip girdisi: {bad}")
        names = z.namelist()
        if not names:
            raise SystemExit("zip bos")
        print(f"  girdi: {len(names)} dosya — ornek: {names[:5]}")
        return names


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True, help="CMT export zip yolu")
    p.add_argument("--version", required=True, help="paket surumu, or. 1.0.0")
    args = p.parse_args()

    if not os.path.isfile(args.input):
        raise SystemExit(f"girdi yok: {args.input}")
    validate_cmt_zip(args.input)

    dist = os.path.join(HERE, "dist")
    os.makedirs(dist, exist_ok=True)
    out = os.path.join(dist, f"sgb-qradar-content-{args.version}.zip")
    inner_name = f"sgb-usecases-content-{args.version}.zip"

    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(args.input, inner_name)
        z.writestr("README.md", INSTALL_README.format(version=args.version))
        z.write(os.path.join(ROOT, "LICENSE"), "LICENSE")

    print(f"OK  {out}  ({os.path.getsize(out) / 1024:.0f} KB)")
    print(f"    App Exchange gonderimi icin ic dosyayi kullanin: {inner_name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
