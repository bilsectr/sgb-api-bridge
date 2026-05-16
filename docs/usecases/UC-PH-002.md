# UC-PH-002 — Web Proxy Üzerinden SGB Phishing URL'sine HTTP İsteği

> **TL;DR:** Kullanıcının tarayıcısı, SGB'nin oltalama URL'leri listesindeki
> bir adrese HTTP/HTTPS isteği gönderdiğinde alarm üretir. UC-PH-001'den
> farkı: DNS-over-HTTPS veya IP-direkt erişimlerde DNS log alınamaz; proxy
> yine yakalar. İki kural birlikte tam kapsama sağlar.

## Bu use case nedir? (Basit anlatım)

Bir kullanıcı tarayıcıdan bir bağlantıya tıkladığında, çoğu kurumda istek
**web proxy'sinden (SWG)** geçer: Bluecoat, Forcepoint, Zscaler, Squid,
Cisco WSA gibi. Proxy her isteği URL ile birlikte log'lar.

SGB'nin phishing **URL'leri** (sadece domain değil, tam URL —
`/login.php?id=...` gibi) `SGB_PH_URL` lookup olarak SIEM'e yüklenir.
SIEM her proxy log'unu bu lookup ile kontrol eder.

**UC-PH-001 ile ilişkisi:** Saldırgan DNS-over-HTTPS (DoH) kullanıyor veya
direkt IP'ye istek yapıyorsa DNS log'u tetiklenmez. Bu durumda **proxy log
seviyesindeki bu kural** yegane görünürlüktür. İkisi birlikte çalışmalı —
biri DNS, diğeri HTTP katmanında — komplementer kapsama için.

## Senaryo (Hikâye)

- 14:12 — Saldırgan, `https://gizliservis.example/login.php?u=ahmet` URL'sini
  Telegram üzerinden kullanıcıya gönderir.
- 14:13 — Kullanıcı tıklar. DNS sorgusu DoH (Cloudflare 1.1.1.1) ile yapılır
  ve kurum DNS log'una **düşmez** → UC-PH-001 tetiklenmez.
- 14:13:02 — İstek kurum proxy'sine ulaşır; proxy URL'yi log'lar.
- 14:13:03 — SIEM `gizliservis.example/login.php?u=ahmet` URL'sinin
  `SGB_PH_URL` set'inde olduğunu görür → severity 5 alarm.

## BG Rehberi karşılığı

| Madde | Madde adı | Bu UC ne sağlar? |
|-------|-----------|-------------------|
| **3.1.6.20** | A Tabanlı URL Filtreleri Kullanımı | Bu use case tam olarak bu maddenin operasyonel kanıtıdır. |
| **3.1.6.21** | URL Kategori Hizmeti Kullanımı | SGB connectiontype = URL kategorisi (PH = phishing kategorisi). |
| **3.1.6.22** | URL'lerin Kayıt Altına Alınması | URL'ler log'lanır + lookup ile "biliniyor mu?" etiketi eklenir. |
| **3.1.5.1** | Zararlı Yazılımdan Korunma | Phishing URL'leri zararlı içerik ailesidir. |
| **3.1.8.6** | Merkezi Kayıt Yönetimi | Alarm SIEM offense'ı olarak merkezde tutulur. |
| **3.1.8.7** | Kayıt Analizi Araçları (SIEM) | Bu UC SIEM korelasyon kuralıdır. |
| **3.1.10.4** | Siber Tehdit Bildirimlerinin Yönetilmesi | SGB'den çekilen URL listesi → SIEM kuralı. |

## Teknik özet

| Alan | Değer |
|------|-------|
| ID | UC-PH-002 |
| MITRE ATT&CK | TA0001 / T1566.002 Spearphishing Link |
| Connectiontype | PH |
| Severity (base) | 5 |
| Veri kaynakları | Web proxy / SWG (Bluecoat, Forcepoint, Zscaler, Squid, Cisco WSA) |
| Reference / lookup | `SGB_PH_URL` + `SGB_URL_MAP` |
| Response | PB-PH-002 (URL block + kullanıcı bilgilendirme) |

## Tespit mantığı

```text
when proxy event geldi
  AND url alanı SGB_PH_URL set'inde
  AND source network "Trusted"
then offense aç, severity=5, source IP'yi SGB_SUSPECTED_HOSTS'a ekle
```

## QRadar uygulaması

**Kural tipi:** Event Rule

```
when any of these properties (URL, "HTTP URL Host") is contained in
     any of these reference set(s): SGB_PH_URL
  AND when the source network is one of the following: Trusted
```

**Response:**
- Dispatch event "SGB Phishing URL access"
- Severity 5 + criticality modifier
- `SGB_SUSPECTED_HOSTS` set'ine source IP ekle

## Splunk uygulaması

**Saved search:** `SGB - UC-PH-002 - Proxy phishing URL`

```spl
`sgb_proxy_index`
| lookup sgb_url_lookup value AS url OUTPUT connectiontype, criticality_level, source
| where connectiontype="PH"
| stats count by src_ip, url, source, _time
```

## Yanlış pozitif notları

- **SOC analist / threat hunting workstation'ları** araştırma için phishing
  URL'lere erişebilir → exception listesi şart.
- **Email gateway URL rewriting** (Proofpoint, Mimecast) orijinal URL'yi
  gizler. Rewrite'lı URL'yi decode eden parser yoksa kural tetiklenmez —
  parser ekleyin (proxy parser'da `urldefense.com` decoder vb.).
- **SGB IH (ihbar) kayıtları** daha yüksek FP'li → ayrı set veya
  `SGB_SRC != "IH"` filtre.

## Olay müdahale (PB-PH-002)

**Otomatik:**
1. URL'yi proxy block list'e push et.
2. Source IP'yi `SGB_SUSPECTED_HOSTS` set'ine ekle (TTL 7 gün).
3. SOAR ticket aç.

**Manuel:**
1. Tıklayan kullanıcı kim? Asset criticality nedir?
2. Diğer kullanıcılar aynı URL'yi tıkladı mı? (Saatlik aggregate sorgu)
3. EDR taraması başlat, browser cache + form auto-fill geçmişine bak.
4. Eğer credentials girilmişse → IAM ekibine bildir, parola sıfırlama
   ve oturum invalidation.
