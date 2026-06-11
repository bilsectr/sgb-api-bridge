#!/usr/bin/env python3
"""
QRadar rule worksheet ureticisi.

docs/usecases/UC-*.md dosyalarindan her UC'nin QRadar bolumunu cekip
tier sirasina gore tek bir calisma dokumani (rule-sheet.md) uretir.
Lab'da kural girisi yapan kisi 24 dosya arasinda gezinmek yerine bu
sheet'i bastan sona takip eder; her kuralin onunde checkbox vardir.

Kanonik kaynak docs/usecases/'tir — UC'ler degistiginde bu script
yeniden kosulur (cikti commit edilir):

    python apps/qradar/make_rule_sheet.py
"""
import os
import re
import sys
from datetime import date

HERE = os.path.dirname(os.path.abspath(__file__))
UC_DIR = os.path.normpath(os.path.join(HERE, "..", "..", "docs", "usecases"))
OUT = os.path.join(HERE, "rule-sheet.md")

# Devreye alma sirasi (docs/usecases/README.md#tiers)
TIERS = {
    1: ["UC-XX-004", "UC-PH-001", "UC-PH-002", "UC-PH-003",
        "UC-BC-001", "UC-BC-002", "UC-AC-001", "UC-AC-002"],
    2: ["UC-BC-003", "UC-BC-004", "UC-MF-001", "UC-MF-002",
        "UC-MC-001", "UC-MC-002", "UC-XX-001", "UC-XX-002",
        "UC-XX-005", "UC-XX-006"],
    3: ["UC-EK-001", "UC-EK-002", "UC-MM-001", "UC-MM-002",
        "UC-OT-001", "UC-XX-003"],
}
TIER_DESC = {
    1: "Feed sağlığı + en yüksek hacim/severity. Önce bunlar.",
    2: "Composite/meta kurallar; ek veri kaynaklarına bağımlı.",
    3: "Düşük hacim / bilgilendirme. Maliyetsizse açın.",
}


def rewrite_links(md):
    """UC dosyalarindaki goreli linkleri rule-sheet.md konumuna gore duzeltir.

    UC icerigi docs/usecases/ goreli yazilmistir; sheet apps/qradar/ altinda.
    """
    md = re.sub(r"\]\((UC-[A-Z]{2}-\d{3}\.md)", r"](../../docs/usecases/\1", md)
    md = re.sub(r"\]\(README\.md", "](../../docs/usecases/README.md", md)
    md = re.sub(r"\]\(\.\./", "](../../docs/", md)
    return md


def parse_uc(uc_id):
    path = os.path.join(UC_DIR, uc_id + ".md")
    text = open(path, encoding="utf-8").read()

    title = re.match(r"# (.+)", text).group(1).strip()

    m = re.search(r"^\| Severity[^|]*\|([^|]+)\|", text, re.M)
    severity = m.group(1).strip() if m else "—"

    m = re.search(r"^\| MITRE[^|]*\|([^|]+)\|", text, re.M)
    mitre = m.group(1).strip() if m else "—"

    m = re.search(r"^\| TAXII koleksiyonu \|([^|]+)\|", text, re.M)
    taxii = m.group(1).strip() if m else "—"

    # "## QRadar uygulaması" (veya MM-002'de "## QRadar / Splunk")
    # bolumunu bir sonraki ## basligina kadar al.
    m = re.search(r"^## QRadar[^\n]*\n(.*?)(?=^## |\Z)", text, re.M | re.S)
    if not m:
        raise SystemExit(f"{uc_id}: QRadar bolumu bulunamadi")
    qradar = rewrite_links(m.group(1).strip())

    return {
        "id": uc_id, "title": title,
        "severity": rewrite_links(severity),
        "mitre": rewrite_links(mitre),
        "taxii": rewrite_links(taxii),
        "qradar": qradar,
    }


def main():
    lines = [
        "# QRadar Rule Worksheet — SGB Use Case Kütüphanesi",
        "",
        "> **ÜRETİLMİŞ DOSYA — elle düzenlemeyin.** Kaynak: [docs/usecases/](../../docs/usecases/),",
        "> üretici: [make_rule_sheet.py](make_rule_sheet.py). UC tanımları değişince yeniden üretin.",
        "",
        f"Üretim tarihi: {date.today().isoformat()} · 24 kural · sıra = devreye alma önceliği",
        "",
        "**Ön koşullar:** [setup_feeds.py](setup_feeds.py) ile 8 TAXII feed +",
        "reference set'ler kurulmuş, feed'ler \"Connected\" durumda olmalı",
        "([docs/integrations/qradar.md](../../docs/integrations/qradar.md) Adım 1-2).",
        "",
        "Her kural için ortak ayarlar:",
        "",
        "- Rule grubu: **SGB Use Cases** (yeni grup oluşturun — CMT export'u bu grupla yapılır)",
        "- Severity formülü ve source=IH istisnaları: [usecases/README.md#severity](../../docs/usecases/README.md#severity)",
        "- Offense annotation konvansiyonu: `\"SGB <aciklama> — bkz. <UC-ID>\"`",
        "",
    ]

    for tier in (1, 2, 3):
        lines += [f"---\n\n## Tier {tier} — {TIER_DESC[tier]}", ""]
        for uc_id in TIERS[tier]:
            uc = parse_uc(uc_id)
            lines += [
                f"### [ ] {uc['id']} — {uc['title'].split('—', 1)[-1].strip()}",
                "",
                f"| | |",
                f"|---|---|",
                f"| Severity (base) | {uc['severity']} |",
                f"| MITRE | {uc['mitre']} |",
                f"| TAXII feed | {uc['taxii']} |",
                f"| Kanonik tanım | [docs/usecases/{uc['id']}.md](../../docs/usecases/{uc['id']}.md) |",
                "",
                uc["qradar"],
                "",
            ]

    lines += [
        "---",
        "",
        "## Tamamlandığında: CMT export",
        "",
        "```bash",
        "# Console'da, SGB Use Cases rule grubunu ve bağımlılıklarını export et:",
        "/opt/qradar/bin/contentManagement.pl -a export -c 28 -i <rule_group_id> -t",
        "# veya tüm custom rule'ları alıp UI'dan ayıklamak için: -a export -c 28 -i all",
        "```",
        "",
        "Çıkan zip'i `apps/qradar/build.py --input <export.zip>` ile dağıtım",
        "paketine çevirin (bkz. [README.md](README.md)).",
        "",
    ]

    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines))
    print(f"OK  {OUT} ({sum(len(TIERS[t]) for t in TIERS)} kural)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
