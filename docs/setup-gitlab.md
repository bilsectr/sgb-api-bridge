# Self-hosted GitLab Kurulumu

Bu rehber, projeyi kurumun kendi GitLab sunucusuna klonlayıp tamamen
offline (internet'ten bağımsız raw URL ile) çalıştırmanızı sağlar.
**Air-gapped / kurum içi yalnız ortamlar için en uygun seçim.**

## Bu kurulum BG Rehberi'nin neyini karşılar?

| Madde | Madde adı | Bu kurulum nasıl katkı sağlar? |
|-------|-----------|--------------------------------|
| **3.1.10.4** ⭐ | Siber Tehdit Bildirimlerinin Yönetilmesi | Kurum içi GitLab CI saatlik SGB sync. |
| **3.1.5.1** | Zararlı Yazılımdan Korunma + Merkezi Yönetim | Cluster içi/intranet IoC güncelleme. |
| **3.1.6.4 / 3.1.6.5 / 3.1.6.20** | Kara Liste / URL Filtre | GitLab raw URL → firewall/proxy. |
| **3.5.3** | Tedarikçi İlişkileri Güvenliği | Kod kurum içinde, harici servis bağımlılığı yok. |
| **4.3** | Bulut Bilişim Güvenliği | Kurum GitLab on-prem ise bu maddenin "bulutta kalmama" beklentisiyle uyumlu. |
| **3.1.8.6** | Merkezi Kayıt Yönetimi | GitLab CI log'ları kurum içinde, SIEM'e iletilebilir. |

> **Önerilen senaryo:** Kuruma kapalı ortamlarda bu yöntem, kurum
> SOC + IT için en savunulabilir konfigürasyondur.

## Önkoşullar

- Self-hosted GitLab CE/EE (12.0+)
- En az bir GitLab Runner (shell veya docker executor). Normal çalışmada
  delta sync birkaç dakika sürer; yalnızca elle full sync çalıştıracaksan
  runner `timeout`'u yeterli olmalı (`/etc/gitlab-runner/config.toml`
  içinde `timeout = 54000` gibi).
- Runner'ın SGB API'sine (`https://siberguvenlik.gov.tr`) çıkışı olmalı.
  Kurumsal proxy varsa `HTTPS_PROXY` env değişkeni runner config'ine
  eklenmeli.

## 1. Repo'yu klonla

```bash
git clone https://github.com/bilsectr/sgb-api-bridge.git
cd sgb-api-bridge
git remote set-url origin https://gitlab.kurum.local/<group>/sgb-api-bridge.git
git push -u origin main
```

## 2. Project Access Token oluştur

CI'nin commit/push yapabilmesi için bir token gerekiyor:

1. Proje → **Settings** → **Access Tokens** → **Add new token**
2. Name: `sgb-api-bridge-ci`
3. Role: `Maintainer`
4. Scopes: `write_repository`, `api`
5. Token'ı kopyala (bir daha gösterilmez).

## 3. CI/CD variable ekle

1. Proje → **Settings** → **CI/CD** → **Variables** → **Add variable**
2. Key: `GIT_PUSH_TOKEN`
3. Value: (yukarıda kopyaladığın token)
4. **Mask variable**: ✓
5. **Protect variable**: ✓ (sadece protected branch'lerden erişilebilir;
   default branch protected olmalı)

## 4. Pipeline Schedule ekle (sadece delta)

Proje → **Build** → **Pipeline schedules** → **New schedule**

**Delta (saatlik):**

- Description: `SGB delta sync`
- Interval Pattern: `23 * * * *`
- Target Branch: `main`
- Variables: `SYNC_MODE` = `delta`

> **Full sync için schedule kurma.** Full sync 15+ saat sürdüğü için
> zamanlı çalışmaz. Repo geçmiş veriyi zaten içerir; delta bu noktadan
> devam eder.

## 5. (Opsiyonel) İlk full sync'i manuel tetikle

Bu adım **çoğu durumda gerekmez** — klonladığın repo `docs/*-list.txt` ve
`state/seen_ids.json` dosyalarını hazır taşır, delta direkt çalışır.

Yalnızca sıfırdan tam yeni bir veri seti çekmek istersen:

Build → Pipelines → **Run pipeline** → branch `main` → variable
`SYNC_MODE=full` → **Run**.

Full sync ~10-15+ saat sürer. Runner timeout'a takılırsa son aşamada
otomatik yeni pipeline tetiklenir (zincir devam eder). 1-2 zincir sonra
`docs/*.txt` dosyaları tamamen dolu olur.

## 6. Repo görünürlüğü ve feed URL'leri

FortiGate gibi cihazlar dosyaları **anonim** olarak çekecek. Repo'yu uygun
görünürlüğe getir:

- **Public** (internet'e açık): feed'ler herkese açık, hiçbir auth gerekmez
- **Internal** (sadece logged-in GitLab kullanıcıları): cihaz token
  koyamayacağı için çalışmaz; **Pages opsiyonunu kullan** (aşağıda)
- **Private**: yalnızca takım üyeleri; cihaz çekemez. **Pages opsiyonunu
  kullan**.

### Public/Internal+Network-restricted senaryosu — raw URL

Feed'lere bu URL'lerden eriş:

```
https://gitlab.kurum.local/<group>/sgb-api-bridge/-/raw/main/docs/domain-list.txt
https://gitlab.kurum.local/<group>/sgb-api-bridge/-/raw/main/docs/ip-list.txt
https://gitlab.kurum.local/<group>/sgb-api-bridge/-/raw/main/docs/url-list.txt
https://gitlab.kurum.local/<group>/sgb-api-bridge/-/raw/main/docs/ip6-list.txt
https://gitlab.kurum.local/<group>/sgb-api-bridge/-/raw/main/docs/ip6net-list.txt
```

### Private repo senaryosu — GitLab Pages

`.gitlab-ci.yml` dosyasındaki `pages` job'unu yorumdan çıkar, tekrar push
et. Pages'i kullanmak için:

1. Admin: GitLab Pages özelliğinin aktif olduğunu doğrula
2. Proje → Settings → Pages → "Access Control" → **kapalı** (anonim erişim)
3. Feed URL'leri:

   ```
   https://<group>.<pages-domain>/sgb-api-bridge/domain-list.txt
   ```

## 7. FortiGate konfigürasyonu (örnek — BG 3.1.6.4)

```
config system external-resource
    edit "SGB-Domain"
        set type domain
        set resource "https://gitlab.kurum.local/<group>/sgb-api-bridge/-/raw/main/docs/domain-list.txt"
        set refresh-rate 60
    next
    edit "SGB-IP"
        set type address
        set resource "https://gitlab.kurum.local/<group>/sgb-api-bridge/-/raw/main/docs/ip-list.txt"
        set refresh-rate 60
    next
end
```

Bu yapılandırma **3.1.6.4** (Kara Liste Kullanımı) ve **3.1.6.5** (İzin
Verilmeyen Trafiğin Engellenmesi) maddelerinin somut karşılığıdır.

## Denetim kayıtları (BG 3.1.8.x)

GitLab CI her job için ayrıntılı log üretir; her saat git commit'i oluşur:

- **3.1.8.4** Detaylı Kayıt: pipeline log'unda her sync — zaman, sayı, hata
- **3.1.8.6** Merkezi Kayıt: GitLab merkez (zaten kurum içi)
- **Git tarihçesi**: hangi anda hangi indicator eklendi/silindi — audit
  trail

Üretimde: GitLab webhook → Elastic / Splunk / QRadar ile pipeline event'leri
SIEM'inize forward edin. Bu sayede SOC ekibi de SGB sync'in sağlığını
gözleyebilir.

## Önerilen güvenlik sıkılaştırmaları (BG 5.x)

- Runner'ı **dedicated** olarak kurun (paylaşımlı runner riski azaltır).
- `config.toml`'da `privileged = false` (Docker executor için).
- GitLab repository: branch protection on `main`, force push disabled.
- `GIT_PUSH_TOKEN`: 6 ayda bir rotate.

## Sorun giderme

- **`HATA: GIT_PUSH_TOKEN tanimli degil`**: 3. adımı atladın.
- **`remote: HTTP Basic: Access denied`**: Token'ın scope'unda
  `write_repository` yok ya da süresi dolmuş. Yeniden oluştur.
- **Pipeline başladı ama hiçbir şey değişmiyor**: SGB API'ye erişim yok.
  Runner'ın `curl https://siberguvenlik.gov.tr/api/address/index?type=ip`
  ile çıkıp çıkamadığını kontrol et.
- **Runner timeout'a takılıyor ama otomatik tetiklenmiyor**:
  `GIT_PUSH_TOKEN`'a `api` scope'u verilmemiş. Token'ı güncelle.
- **stats.json'da `last_update_utc` 48 saatten eski**: healthcheck adımı
  fail edecek. Pipeline tarihine bak, hangi job'ta takılındı incele.
