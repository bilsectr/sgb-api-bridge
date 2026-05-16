# GitHub Pages Kurulumu (fork edip kendi reponda)

Bu rehber, projeyi kendi GitHub hesabına fork edip Pages üzerinden
yayımlaman içindir. Hâlihazırda `bilsectr/sgb-api-bridge` reposunu
kullanıyorsan zaten her şey hazır — direkt aşağıdaki "Feed URL'leri ve
cihaz örnekleri" bölümüne atla.

## Bu kurulum BG Rehberi'nin neyini karşılar?

| Madde | Madde adı | Bu kurulum nasıl katkı sağlar? |
|-------|-----------|--------------------------------|
| **3.1.10.4** ⭐ | Siber Tehdit Bildirimlerinin Yönetilmesi | GitHub Actions saatlik delta sync → her zaman taze feed. |
| **3.1.5.1** | Zararlı Yazılımdan Korunma + Merkezi Yönetim | Otomatik güncel imza/IoC. |
| **3.1.6.4** | Kara Liste Kullanımı | Pages URL'leri firewall/proxy kara liste kaynağı. |
| **3.5.3** | Tedarikçi İlişkileri Güvenliği | Public repo, açık kaynak, denetlenebilir. |
| **3.1.13** | Felaket Kurtarma | GitHub repo + sync tarihçesi git history'sinde — kolay recovery. |

> **Air-gapped kurum için:** GitHub kullanamıyorsanız [setup-gitlab.md](setup-gitlab.md)
> (self-hosted GitLab) veya [setup-docker.md](setup-docker.md) /
> [setup-k8s.md](setup-k8s.md) kullanın.

## Repo'yu hazırla

```bash
gh repo create sgb-api-bridge --public --clone --template bilsectr/sgb-api-bridge
cd sgb-api-bridge
```

Veya manuel fork: GitHub UI'ndan "Fork" → kendi hesabın altına klonla.

## 1. Workflow permission'larını ayarla

Repo → **Settings** → **Actions** → **General** → **Workflow permissions**:

- ✓ **Read and write permissions** seç
- ✓ "Allow GitHub Actions to create and approve pull requests"
  (auto-retrigger için gerekli)
- **Save**

## 2. GitHub Pages'i aç

Repo → **Settings** → **Pages**:

- Source: **Deploy from a branch**
- Branch: `main` / folder: `/docs`
- **Save**

## 3. Delta sync'i etkinleştir

Bu repo'yu fork ettiysen `docs/*-list.txt` ve `state/seen_ids.json` zaten
dolu gelir — **full sync çalıştırman gerekmez.** Delta workflow'u
(`Sync (delta, hourly)`) saatte bir otomatik çalışıp geçmiş veriden devam
eder.

İlk delta'yı hemen tetiklemek istersen: Repo → **Actions** →
**Sync (delta, hourly)** → **Run workflow**.

### (Opsiyonel) Sıfırdan tam re-sync

Yalnızca tamamen yeni bir veri seti çekmek istersen: Repo → **Actions** →
**Sync (full, manual bootstrap only)** → **Run workflow** → branch `main`.

Full sync ~10-15+ saat sürer. SGB rate-limit'i nedeniyle runner timeout'a
takılabilir; son adım otomatik olarak yeni workflow tetikler ve resume
eder. 1-2 zincir sonra `docs/*.txt` tamamen dolar. Zamanlı/haftalık
çalışmaz — tek seferlik manuel iştir.

## 4. Doğrulama

- `https://<USERNAME>.github.io/sgb-api-bridge/` → landing açılır
- `https://<USERNAME>.github.io/sgb-api-bridge/stats.json` →
  `last_update_utc` taze, `in_progress` null
- `https://<USERNAME>.github.io/sgb-api-bridge/domain-list.txt` →
  ~450K satır

## 5. README ve index.html'de URL'leri güncelle

`bilsectr` → `<USERNAME>` ile değiştir:

```bash
grep -rl "bilsectr.github.io" . | xargs sed -i 's|bilsectr.github.io|<USERNAME>.github.io|g'
grep -rl "bilsectr/sgb-api-bridge" . | xargs sed -i 's|bilsectr/sgb-api-bridge|<USERNAME>/sgb-api-bridge|g'
git commit -am "Personalize URLs" && git push
```

## Feed URL'leri ve cihaz örnekleri

| Tür | URL |
|---|---|
| Domain | `https://<USERNAME>.github.io/sgb-api-bridge/domain-list.txt` |
| IPv4 | `https://<USERNAME>.github.io/sgb-api-bridge/ip-list.txt` |
| URL | `https://<USERNAME>.github.io/sgb-api-bridge/url-list.txt` |
| IPv6 | `https://<USERNAME>.github.io/sgb-api-bridge/ip6-list.txt` |
| IPv6 subnet | `https://<USERNAME>.github.io/sgb-api-bridge/ip6net-list.txt` |

Aşağıdaki tüm cihaz konfigürasyon örnekleri BG **3.1.6.4** (Kara Liste
Kullanımı) ve **3.1.6.20** (URL Filtreleri) maddelerinin somut
karşılığıdır.

### FortiGate (CLI)

```
config system external-resource
    edit "SGB-Domain"
        set type domain
        set resource "https://<USERNAME>.github.io/sgb-api-bridge/domain-list.txt"
        set refresh-rate 60
    next
    edit "SGB-IP"
        set type address
        set resource "https://<USERNAME>.github.io/sgb-api-bridge/ip-list.txt"
        set refresh-rate 60
    next
end
```

### Sophos XG / Firewall

Web Admin → System → Hosts and services → IP host group → **Import from URL**
ile URL'leri ekle.

### Palo Alto

```
set external-list SGB-IP type ip url https://<USERNAME>.github.io/sgb-api-bridge/ip-list.txt recurring hourly
set external-list SGB-Domain type domain url https://<USERNAME>.github.io/sgb-api-bridge/domain-list.txt recurring hourly
```

### pfSense (pfBlockerNG)

Firewall → pfBlockerNG → IPv4 → Add → URL alanına IPv4 listesini gir.
DNSBL altına domain listesini ekle.

### Pi-hole

Adlist olarak ekle:

```
https://<USERNAME>.github.io/sgb-api-bridge/domain-list.txt
```

Sonra `pihole -g` ile yenile.

### Squid

```
acl sgb_blacklist dstdomain "/etc/squid/sgb-domain-list.txt"
http_access deny sgb_blacklist
```

```cron
17 * * * * curl -sf https://<USERNAME>.github.io/sgb-api-bridge/domain-list.txt -o /etc/squid/sgb-domain-list.txt && systemctl reload squid
```

## Denetim kayıtları (BG 3.1.8.x)

GitHub Actions her sync için ayrıntılı log üretir; ayrıca her saat git
commit'i oluşur. Bu sayede:

- **3.1.8.4** (Detaylı Kayıt): her sync zaman, indicator sayısı, hata
  durumu workflow log'unda
- **3.1.8.6** (Merkezi Kayıt Yönetimi): GitHub Actions = merkezi log
  noktası
- **Git tarihçesi**: hangi anda hangi indicator eklendi/silindi —
  audit trail

Denetim için: Actions → Workflow run → log'lar her zaman 90 gün
saklanır; daha uzun saklama için artifact'a archive et.

## Sorun giderme

- **Pages 404**: Settings → Pages'te source `/docs` mu, branch `main` mi?
  "GitHub Pages" job'unun Actions'ta yeşil olduğunu kontrol et.
- **Workflow "permission denied"**: 1. adımdaki "Read and write permissions"
  set edilmemiş.
- **Full sync hep timeout yiyor**: SGB çok agresif rate-limit uyguluyor
  demektir. `scripts/sync.py`'da `SLEEP_OK_FULL = 1.0` değerini 2.0'a çıkar,
  push'la.
- **state/seen_ids.json bozulduysa**: dosyayı sil, fresh start için her
  tip'i sıfırla:

  ```json
  {"domain":{"max_id":0,"last_full_sync":null,"last_delta_sync":null}, "url":{...}, ...}
  ```
