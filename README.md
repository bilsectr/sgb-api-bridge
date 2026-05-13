# USOM Bridge

[![Last sync](https://img.shields.io/endpoint?url=https://sinansh.github.io/usom-bridge/badge.json)](https://sinansh.github.io/usom-bridge/stats.json)
[![Delta sync](https://github.com/sinansh/usom-bridge/actions/workflows/sync-delta.yml/badge.svg)](https://github.com/sinansh/usom-bridge/actions/workflows/sync-delta.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

USOM (Ulusal Siber Olaylara Müdahale Merkezi) tehdit beslemesini güvenlik duvarlarının (FortiGate, Sophos, Palo Alto, pfSense, Pi-hole, Squid) doğrudan tüketebileceği **düz metin** formatına dönüştüren açık kaynak proje.

## Hızlı başlangıç

Aşağıdaki URL'leri firewall'una doğrudan ver:

| Tür | Adet | URL |
|---|---:|---|
| Domain | ~450K | `https://sinansh.github.io/usom-bridge/domain-list.txt` |
| IPv4 | ~14K | `https://sinansh.github.io/usom-bridge/ip-list.txt` |
| URL | ~7K | `https://sinansh.github.io/usom-bridge/url-list.txt` |
| IPv6 | — | `https://sinansh.github.io/usom-bridge/ip6-list.txt` |
| IPv6 subnet | — | `https://sinansh.github.io/usom-bridge/ip6net-list.txt` |
| Stats | — | `https://sinansh.github.io/usom-bridge/stats.json` |

GitHub Pages, Fastly CDN üzerinde sunulur — yüksek hacimli istekler GitHub backend'e değil CDN'e düşer.

## Nasıl çalışır?

- **Delta sync** — saatte bir, USOM API'sinden her tür için (`domain`, `url`, `ip`, `ip6`, `ip6net`) yalnız yeni kayıtları çeker (~1-3 dk).
- **Full sync** — pazar 03:00 UTC, tüm kayıtları yeniden çeker (drift düzeltici, ~4 saat).
- Her iki iş de GitHub Actions üzerinde çalışır; çıktılar `docs/` klasörüne commit'lenir ve GitHub Pages otomatik yayımlar.

USOM API kayıtları tarih sırasına göre newest-first dönüyor ve ID'ler global monoton artıyor. Delta job'ı her tür için `state/seen_ids.json`'daki `max_id`'den büyük kayıtlara ulaşana kadar sayfaları dolaşıp, bilinen kayda denk gelince durur.

## Cihaz konfigürasyon örnekleri

### FortiGate (CLI)

```
config system external-resource
    edit "USOM-Domain"
        set type domain
        set resource "https://sinansh.github.io/usom-bridge/domain-list.txt"
        set refresh-rate 60
    next
    edit "USOM-IP"
        set type address
        set resource "https://sinansh.github.io/usom-bridge/ip-list.txt"
        set refresh-rate 60
    next
end
```

### Sophos XG / Firewall

Web Admin → System → Hosts and services → IP host group → **Import from URL**:
`https://sinansh.github.io/usom-bridge/ip-list.txt`

### Palo Alto

```
set external-list USOM-IP type ip url https://sinansh.github.io/usom-bridge/ip-list.txt recurring hourly
set external-list USOM-Domain type domain url https://sinansh.github.io/usom-bridge/domain-list.txt recurring hourly
```

### pfSense (pfBlockerNG)

Firewall → pfBlockerNG → IPv4 → Add → URL alanına `https://sinansh.github.io/usom-bridge/ip-list.txt` gir.

### Pi-hole

```
https://sinansh.github.io/usom-bridge/domain-list.txt
```

Adlist olarak ekle, sonra `pihole -g` ile yenile.

### Squid

```
acl usom_blacklist dstdomain "/etc/squid/usom-domain-list.txt"
http_access deny usom_blacklist
```

```cron
17 * * * * curl -sf https://sinansh.github.io/usom-bridge/domain-list.txt -o /etc/squid/usom-domain-list.txt && systemctl reload squid
```

## Kendin koşturmak istersen

```bash
git clone https://github.com/sinansh/usom-bridge
cd usom-bridge
pip install requests
python scripts/sync.py --mode full     # ~4 saat
python scripts/sync.py --mode delta    # ~1-3 dk
```

## Veri kaynağı

USOM Open Threat Feed API: <https://www.usom.gov.tr/api/address/index>

Kayıt kategorileri (`desc` alanı):

| Kod | Açıklama |
|---|---|
| PH | Oltalama (Phishing) |
| BP | Bankacılık - Oltalama |
| MD / MI / MU | Zararlı yazılım barındıran Domain / IP / URL |
| MC | Komuta-Kontrol Merkezi |
| CA | Siber saldırı (port tarama, brute force vb.) |

## Sorumluluk reddi

Bu proje **USOM ile resmi bir bağlantısı olmayan**, kişisel, kâr amacı gütmeyen, açık kaynak bir araçtır. Üretim sistemlerinde "as-is" kullanılır; veri doğruluğundan USOM sorumludur.

## Lisans

[MIT](LICENSE)
