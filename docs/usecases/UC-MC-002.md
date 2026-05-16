# UC-MC-002 — MDM Application Trafiği SGB Mobile C&C'ye

> **TL;DR:** UC-MC-001'in daha hassas versiyonu: hangi mobil app'in
> SGB MC indicator'ına bağlandığını **app package adıyla** bilebiliyoruz.
> MDM/MTD (Mobile Threat Defense) telemetrisi şart.

## Bu use case nedir? (Basit anlatım)

MDM (Intune, Workspace ONE, Jamf) ve MTD (Lookout, Zimperium, Wandera)
çözümleri her app'in yaptığı ağ isteklerini detaylı log'lar. Bu sayede
"`com.malware.app` paketi `mc.evil.example`'a bağlandı" gibi spesifik
tespit yapılabilir.

UC-MC-001'den fark: oradan jenerik mobil trafikten yakalıyoruz; burada
**app package + indicator** korelasyonu var. App'i MDM ile remote
kaldırabiliriz; cihazı retire-trigger ile sıfırlayabiliriz.

## Senaryo (Hikâye)

- 09:12 — Çalışanın Android'inde `com.weather.fakeapp` paketi
  `mc-server.evil.example` domain'ine bağlanıyor (Lookout MTD görüyor).
- 09:12:01 — SIEM MDM + MTD log birleşik korelasyon → severity 7.
- 09:12:05 — MDM API: app blacklist'e ekle + uninstall push.

## BG Rehberi karşılığı

| Madde | Madde adı | Bu UC ne sağlar? |
|-------|-----------|-------------------|
| **3.3.1** | Akıllı Telefon ve Tablet Güvenliği | Doğrudan karşılık. |
| **3.3.1.3** | Kullanıcılara Uygulama İzinleri | Spesifik app'i hedef alır. |
| **3.1.10.4** | Siber Tehdit Bildirimlerinin Yönetilmesi | SGB MC feed kullanımı. |
| **3.1.8.7** | Kayıt Analizi Araçları (SIEM) | MDM/MTD korelasyonu. |

## Teknik özet

| Alan | Değer |
|------|-------|
| ID | UC-MC-002 |
| MITRE | TA0011 / T1437 + T1474 Supply Chain |
| Connectiontype | MC |
| Severity (base) | 7 |
| Veri kaynakları | MDM app telemetry (Intune, Workspace ONE), MTD (Lookout, Zimperium) |
| Reference / lookup | `SGB_MC_DOMAIN`, `SGB_MC_IP` |
| Response | PB-MC-002 (MDM app blacklist + device retire trigger) |

## Tespit mantığı

```text
when MDM/MTD event geldi
  AND mobile_app_package alanı dolu
  AND request_destination in SGB_MC_*
then alarm, severity=7, MDM API ile app blacklist
```

## QRadar uygulaması

Custom event property: `Mobile App Package` (com.example.pkg).

```
when log source type in (Intune, Lookout, Zimperium)
  AND request_destination in SGB_MC_*
```

**Response:** severity 7, MDM API ile app blacklist + device retire-trigger
(manuel onaylı).

## Splunk uygulaması

**Saved search:** `SGB - UC-MC-002 - MDM app C2`

```spl
sourcetype IN ("intune:app", "lookout", "zimperium")
| lookup sgb_domain_lookup value AS query OUTPUT connectiontype
| where connectiontype="MC"
| stats count by device_id, user, mobile_app_package, query
```

## Yanlış pozitif notları

- **Yeni install edilmiş güvenlik araştırma app'i** → dev/research device
  exception.
- **Cloud DNS resolver bias** (8.8.8.8 vs SGB MC DNS C&C IP'si feed'de
  yanlışlıkla) → SOC review whitelist.

## Olay müdahale (PB-MC-002)

**Otomatik:**
1. MDM API: app blacklist (`mobile_app_package`).
2. Tüm cihazlarda uninstall push.

**Manuel:**
1. App orijini neresi? (Resmi store vs side-load vs internal kurum app)
2. Kaç cihazda var? Etki analizi.
3. Side-load ise → user re-training + USB block policy değerlendir.
4. App geliştirici tedarikçi ise → supply-chain incident response.
