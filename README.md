# SGB API Bridge

[![Last sync](https://img.shields.io/github/last-commit/bilsectr/sgb-api-bridge?label=last%20sync)](https://bilsectr.github.io/sgb-api-bridge/stats.json)
[![Hourly sync](https://github.com/bilsectr/sgb-api-bridge/actions/workflows/sync-delta.yml/badge.svg)](https://github.com/bilsectr/sgb-api-bridge/actions/workflows/sync-delta.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

SGB (Siber Güvenlik Başkanlığı, eski **USOM** — Ulusal Siber Olaylara Müdahale Merkezi) tehdit beslemesini iki farklı tüketim modelinde sunar:

- **Düz metin feed** — güvenlik duvarları için (FortiGate, Sophos, Palo Alto, pfSense, Pi-hole, Squid, MikroTik)
- **TAXII 2.1 servisi** — SIEM, TIP ve XDR ürünleri için (QRadar, Splunk, Sentinel, MISP, OpenCTI, XSOAR, Falcon, Trellix)

> **Not:** USOM, 2026'da Siber Güvenlik Başkanlığı (SGB) bünyesinde yeniden yapılandırıldı. API uç noktası `www.usom.gov.tr` → `siberguvenlik.gov.tr` olarak değişti. Bu proje yeni endpoint'i kullanır.

---

## 1) Engelleme — düz metin feed (GitHub Pages, sıfır kurulum)

Aşağıdaki URL'leri firewall'una doğrudan ver:

| Tür | Adet | URL |
|---|---:|---|
| Domain | ~450K | `https://bilsectr.github.io/sgb-api-bridge/domain-list.txt` |
| IPv4 | ~14K | `https://bilsectr.github.io/sgb-api-bridge/ip-list.txt` |
| URL | ~7K | `https://bilsectr.github.io/sgb-api-bridge/url-list.txt` |
| IPv6 | — | `https://bilsectr.github.io/sgb-api-bridge/ip6-list.txt` |
| IPv6 subnet | — | `https://bilsectr.github.io/sgb-api-bridge/ip6net-list.txt` |
| Stats | — | `https://bilsectr.github.io/sgb-api-bridge/stats.json` |

Cihaz örnekleri (FortiGate, Sophos, Palo Alto, pfSense, Pi-hole, Squid, MikroTik): [docs/index.html](docs/index.html) → "Engelleme" sekmesi.

## 2) İzleme — TAXII 2.1 servisi (SIEM / TIP / XDR)

**Tek URL, kimlik doğrulama yok, anonim public servis:**

```
https://sgb-taxii.bilsec.tr/taxii2/
```

Koleksiyonlar `connectiontype` bazında ayrılmıştır ve [SIEM use case kütüphanesi](docs/usecases/) ile birebir eşleşir:

| Koleksiyon | İçerik | UC prefix |
|---|---|---|
| `sgb-phishing` | Phishing (PH) | `UC-PH-*` |
| `sgb-botnet-cc` | Botnet C&C (BC) | `UC-BC-*` |
| `sgb-apt-cc` | APT C&C (AC) | `UC-AC-*` |
| `sgb-exploit-kit` | Exploit Kit (EK) | `UC-EK-*` |
| `sgb-malware-download` | Malware Download (MF) | `UC-MF-*` |
| `sgb-mining` | Cryptomining (MM) | `UC-MM-*` |
| `sgb-mobile-cc` | Mobile C&C (MC) | `UC-MC-*` |
| `sgb-other` | Diğer (OT) | `UC-OT-*` |

Her SIEM/TIP ürünü kendi built-in TAXII 2.1 client'ı ile bu URL'yi doğrudan tüketir — özel script, push servisi veya artifact build'i gerekmez. Adım-adım kurulum: [docs/setup-taxii.md](docs/setup-taxii.md). Ürün bazlı detaylı rehberler:

| Ürün | Doküman |
|---|---|
| IBM QRadar | [docs/integrations/qradar.md](docs/integrations/qradar.md) |
| Splunk (ES + Core) | [docs/integrations/splunk.md](docs/integrations/splunk.md) — hazır app paketi: [apps/splunk/](apps/splunk/) (TA + 24 UC kuralı + dashboard) |
| Microsoft Sentinel | [docs/integrations/sentinel.md](docs/integrations/sentinel.md) |
| MISP | [docs/integrations/misp.md](docs/integrations/misp.md) |
| OpenCTI | [docs/integrations/opencti.md](docs/integrations/opencti.md) |
| Cortex XSOAR, Trellix XDR, Falcon, Elastic, Suricata, Wazuh | [docs/integrations/generic-stix.md](docs/integrations/generic-stix.md) |

## 3) Self-hosting (opsiyonel)

Public servisi kullanmak yerine kendi altyapınızda çalıştırmak isterseniz:

| Model | Senaryo | Kurulum dokümanı |
|---|---|---|
| **Docker** | Tek konteyner; firewall feed + TAXII servisi birlikte (air-gapped destekler) | [docs/setup-docker.md](docs/setup-docker.md) |
| **Kubernetes** | CronJob + Deployment, kurumsal | [docs/setup-k8s.md](docs/setup-k8s.md) |
| **GitHub Pages** | Public CDN (bu repo'nun kendisi) | [docs/setup-github.md](docs/setup-github.md) |

```bash
# Docker — tek satır
docker run -d --name sgb-api-bridge -p 8080:80 \
  -v sgb-api-bridge-data:/data --restart unless-stopped \
  ghcr.io/bilsectr/sgb-api-bridge:latest
```

---

## Nasıl çalışır?

- **Hourly sync** — saatte bir, SGB API'sinden her tür için (`domain`, `url`, `ip`, `ip6`, `ip6net`) tüm kayıtlar `--per-page=1000` ile sayfalanır (~10 dk). GitHub Actions tarafından otomatik tetiklenir.
- **TAXII rebuild** — her sync sonrası `build_taxii.py` statik TAXII ağacını (`docs/taxii/`) yeniden üretir; Cloudflare Worker bu ağacı edge'de servis eder.

SGB API kayıtları tarih sırasına göre newest-first dönüyor ve ID'ler global monoton artıyor. `sync.py` her tür için tüm sayfaları gezer, SQLite'ı upsert eder ve `docs/*-list.txt` dosyalarını yeniden üretir.

> **Geçmiş veri zaten repo'da.** Bu repo'yu klonlayan / fork eden herkes, `docs/*-list.txt` ve `state/seen_ids.json` dosyalarını hazır alır. SQLite (`sgb.db`) `feeds-latest` release asset'inden indirilebilir.

## STIX 2.1 indicator şeması (özet)

TAXII envelope'unda dönen her objet STIX 2.1 `indicator`'dır. `created_by_ref` SGB identity'sine bağlıdır; deterministik UUIDv5 sayesinde kayıt silinip geri eklense bile aynı id'yi alır. SIEM tarafında duplicate üretmez. Detay + örnek payload: [docs/setup-taxii.md](docs/setup-taxii.md).

## Cihaz konfigürasyon örnekleri (engelleme)

### FortiGate (CLI)

```
config system external-resource
    edit "SGB-Domain"
        set type domain
        set resource "https://bilsectr.github.io/sgb-api-bridge/domain-list.txt"
        set refresh-rate 60
    next
    edit "SGB-IP"
        set type address
        set resource "https://bilsectr.github.io/sgb-api-bridge/ip-list.txt"
        set refresh-rate 60
    next
end
```

Diğer cihazlar için: [docs/index.html](docs/index.html) "Engelleme" sekmesi.

## Kendin koşturmak istersen (CLI)

```bash
git clone https://github.com/bilsectr/sgb-api-bridge
cd sgb-api-bridge
pip install requests
python scripts/sync.py --mode full     # SGB API'sini bastan sona cek (~10 dk, saatlik aksiyonun yaptigi sey)
python scripts/sync.py --mode loop     # docker icin: belirli araliklarla full sync tetikler
python scripts/build_taxii.py          # TAXII statik agacini uretir (docs/taxii/)
```

Environment variables:

| Variable | Default | Açıklama |
|---|---|---|
| `SGB_BRIDGE_ROOT` | repo kökü | State ve docs/'un kök dizini |
| `SGB_BRIDGE_DELTA_INTERVAL_SEC` | `3600` | Loop modunda iki sync arası bekleme (sn) |

## Sorumluluk reddi

Bu proje **SGB / Siber Güvenlik Başkanlığı ile resmi bir bağlantısı olmayan**, kâr amacı gütmeyen, açık kaynak bir araçtır. Üretim sistemlerinde "as-is" kullanılır; veri doğruluğundan SGB sorumludur.

## Lisans

[MIT](LICENSE)

## Yazar

**Sinan ŞAHİN** — [LinkedIn](https://www.linkedin.com/in/sinansh/) · [GitHub](https://github.com/sinansh/)
