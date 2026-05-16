# UC-EK-001 — HTTP İsteği SGB Exploit Kit URL'sine

> **TL;DR:** Tarayıcı, SGB'nin "Exploit Kit (EK) landing page" olarak
> işaretlediği bir URL'ye istek yaptığında alarm. EK URL'sine ulaşma
> = exploit'in tarayıcıya zaten teslim edildiği anlamına gelir.

## Bu use case nedir? (Basit anlatım)

Exploit Kit = saldırganların hazır exploit paketleridir (Magnitude, RIG,
Fallout, vb.). Genelde **drive-by download** yöntemiyle çalışır:
kullanıcı zararlı reklamı veya hack'lenmiş meşru siteyi ziyaret eder,
arka planda EK landing page'e yönlendirilir, EK tarayıcı zafiyetini
sömürür ve zararlı yazılım indirir.

SGB'nin **bilinen EK URL'leri** (`SGB_EK_URL`) proxy log'larında aranır.
Eşleşme = exploit zinciri başlamış demek. Severity 8 yüksektir çünkü
EK'a ulaşıldıktan sonra exploit teslim edilir (vurulmuş sayılır).

UC-EK-002 ile birlikte: IDS'in exploit alarmı + SGB EK URL = composite
"vurgu doğrulandı" sinyali (severity 9).

## Senaryo (Hikâye)

- 16:42 — Kullanıcı `marketing-news.example`'i ziyaret eder; bu site
  malvertising vektörü.
- 16:42:03 — Tarayıcı arka planda iframe yönlendirme ile
  `kit.evilek.example/landing?id=...` URL'sine istek yapar.
- 16:42:03 — Proxy log'u; SIEM `SGB_EK_URL` set match.
- 16:42:04 — Severity 8 alarm. EDR'a "scan now" tetiklenir.

## BG Rehberi karşılığı

| Madde | Madde adı | Bu UC ne sağlar? |
|-------|-----------|-------------------|
| **3.1.5.1** | Zararlı Yazılımdan Korunma | EK landing tespiti zararlı yazılımdan korunmanın network katmanıdır. |
| **3.1.6.20** | A Tabanlı URL Filtreleri | EK URL'leri proxy filter listesinin bileşeni. |
| **3.1.6.28** | Uygulama Seviyesi Saldırıların Engellenmesi (WAF/IPS) | EK exploit'leri uygulama katmanı saldırılarıdır. |
| **3.1.8.7** | Kayıt Analizi Araçları (SIEM) | UC SIEM kuralı. |
| **3.1.10.4** | Siber Tehdit Bildirimlerinin Yönetilmesi | SGB EK feed'i operasyonel kullanım. |

## Teknik özet

| Alan | Değer |
|------|-------|
| ID | UC-EK-001 |
| MITRE | TA0002 Execution / T1203 Exploitation for Client Execution |
| Connectiontype | EK |
| Severity (base) | 8 |
| Veri kaynakları | Web proxy / SWG, browser EDR telemetry |
| Reference / lookup | `SGB_EK_URL`, `SGB_EK_DOMAIN`, `SGB_URL_MAP` |
| Response | PB-EK-001 (EDR full scan + browser process inspection) |

## Tespit mantığı

```text
when proxy event geldi
  AND url alanı SGB_EK_URL set'inde
then offense aç, severity=8
     ek opsiyonel: non-standard UA + EK URL → severity +1
```

## QRadar uygulaması

```
when URL is contained in SGB_EK_URL
```

**Enrichment:** Parse User-Agent; non-standard (kütüphane gibi
`python-requests`, `curl`) UA + EK URL kombinasyonu → severity +1.

**Response:**
- Severity 8 + criticality
- Notify SOC
- Push source IP → `SGB_EXPLOITED_HOSTS`
- EDR scan trigger via SOAR

## Splunk uygulaması

**Saved search:** `SGB - UC-EK-001 - Exploit kit URL request`

```spl
`sgb_proxy_index`
| lookup sgb_url_lookup value AS url OUTPUT connectiontype, criticality_level
| where connectiontype="EK"
| stats count values(url) AS ek_urls by src_ip, user_agent
```

## Yanlış pozitif notları

- **Threat hunting / sandbox detonation** trafiği → exception by source asset.
- **Cached browser request** (eski oturumdan) → düşük sinyal; UA yoksa
  veya referrer yoksa severity'yi düşür (suppress).
- **Search engine indeksleme bot'ları** EK URL'ye tesadüfen ulaşabilir
  ama kurum ağında olmamalı.

## Olay müdahale (PB-EK-001)

**Otomatik:**
1. EDR full scan başlat.
2. Source IP'yi `SGB_EXPLOITED_HOSTS`'a ekle.
3. Browser process tree kaydet (PID, parent, command line).

**Manuel:**
1. Tarayıcı versiyonu + plugin'leri güncel mi? Plugin (Flash/Java) varsa
   acil patch.
2. Aynı landing'e başka host ulaştı mı? (Geniş hunt)
3. EDR scan sonucu pozitifse → UC-MF-001 / UC-MF-002 ile birlikte
   incident escalation.
4. Eğer IDS de aynı pencerede exploit alarmı verdiyse → UC-EK-002.
