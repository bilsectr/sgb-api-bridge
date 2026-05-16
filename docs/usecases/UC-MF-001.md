# UC-MF-001 — Proxy Üzerinden SGB Malware URL'sinden Dosya İndirildi

> **TL;DR:** Bir host, SGB'nin "malware dağıtıcı" olarak işaretlediği
> URL'den HTTP GET ile dosya (200 OK, boyut > 1 KB) indiriyor. İndirme
> ≠ çalıştırma; bu yüzden severity 7. UC-MF-002 (EDR ile composite) ile
> birlikte 9'a çıkar.

## Bu use case nedir? (Basit anlatım)

Malware dağıtım URL'leri = zararlı dosyaların (exe, dll, ps1, jar, swf,
docm, vb.) barındırıldığı yerler. SGB bu URL'leri `MF` (Malware File)
connectiontype'ı ile yayar.

Proxy log'unda:
- HTTP method GET veya POST
- Status code 200 veya 206 (kısmi içerik)
- Response body > 1 KB (header'dan büyük → dosya indiriliyor)
- URL `SGB_MF_URL` set'inde

bu dört koşul doluyorsa kullanıcı bilgisayarına zararlı dosya **indirilmiş
oldu**. Henüz çalıştırılmamış ama disk üzerinde mevcut. EDR ile doğrulama
için UC-MF-002.

## Senaryo (Hikâye)

- 10:33 — Kullanıcı `software-free-download.example/setup.exe` linkine
  tıklar.
- 10:33:02 — Proxy log: GET, status 200, 14 MB indirildi.
- 10:33:03 — SIEM URL'yi `SGB_MF_URL`'de bulur → severity 7 alarm.
- 10:33:05 — EDR'a "scan downloaded file" tetiklenir.
- 10:33:10 — EDR file create event'i de tetiklenirse → UC-MF-002 composite
  alarmı (severity 8).

## BG Rehberi karşılığı

| Madde | Madde adı | Bu UC ne sağlar? |
|-------|-----------|-------------------|
| **3.1.5.1** | Zararlı Yazılımdan Korunma | Malware indirme tespiti = AV/EDR uyumlu kanıt. |
| **3.1.5.6** | Zararlı Yazılım Tespitlerinin Merkezi Tutulması | Alarm SIEM offense merkezde. |
| **3.1.6.20** | A Tabanlı URL Filtreleri | Malware URL'leri proxy filter listesinde olmalı. |
| **3.1.8.7** | Kayıt Analizi Araçları (SIEM) | Proxy log korelasyonu. |
| **3.1.10.4** | Siber Tehdit Bildirimlerinin Yönetilmesi | SGB MF feed → SIEM. |

## Teknik özet

| Alan | Değer |
|------|-------|
| ID | UC-MF-001 |
| MITRE | TA0002 / T1105 Ingress Tool Transfer |
| Connectiontype | MF |
| Severity (base) | 7 |
| Veri kaynakları | Web proxy / SWG |
| Reference / lookup | `SGB_MF_URL`, `SGB_MF_DOMAIN`, `SGB_URL_MAP` |
| Response | PB-MF-001 (EDR scan + dosya karantinaya alma) |

## Tespit mantığı

```text
when proxy event geldi
  AND url in SGB_MF_URL
  AND http_status in (200, 206)
  AND bytes_received > 1024
then offense aç, severity=7
     source IP'yi SGB_DOWNLOADED_MALWARE'a ekle (URL + zaman ile)
```

## QRadar uygulaması

```
when log source type is Proxy/SWG
  AND URL in SGB_MF_URL
  AND HTTP status in (200, 206)
  AND bytes_received > 1024
```

## Splunk uygulaması

**Saved search:** `SGB - UC-MF-001 - Malware URL download`

```spl
`sgb_proxy_index` http_status IN (200,206) bytes_in>1024
| lookup sgb_url_lookup value AS url OUTPUT connectiontype
| where connectiontype="MF"
| stats values(url) AS urls sum(bytes_in) AS total_bytes by src_ip
```

## Yanlış pozitif notları

- **Security research downloads** (sandbox, malware veri tabanı,
  VirusTotal) → exception by source asset.
- **AV vendor pattern download URL'leri** yanlışlıkla feed'de olabilir
  → SOC review whitelist.
- **CDN üzerinden meşru yazılım** (paylaşımlı hosting) → vendor
  domain exception.

## Olay müdahale (PB-MF-001)

**Otomatik:**
1. EDR API: indirilen dosya hash'ini sorgula; sonuç pozitif ise karantina.
2. Source IP'yi `SGB_DOWNLOADED_MALWARE`'a ekle.
3. Proxy: URL'yi block list'e.

**Manuel:**
1. EDR'da file event geldi mi? Çalıştırıldı mı?
2. Hash'i VirusTotal / MISP'te sorgula.
3. Aynı URL'den başka kullanıcı indirdi mi? Geniş arama.
4. Dosya gerçekten zararlı çıkarsa → IR ticket, host disk imaging.
