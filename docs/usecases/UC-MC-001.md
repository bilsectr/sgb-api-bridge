# UC-MC-001 — Mobil/VPN Trafiği SGB Mobile C&C Indicator'ına

> **TL;DR:** Kurum mobil cihazlarından (MDM yönetimli telefon/tablet) SGB
> mobil C&C indicator'ına trafik. Sadece mobil-sınıfı log kaynaklarında
> çalışır. Kurum desktop'larında BC/AC kuralları zaten kapsar.

## Bu use case nedir? (Basit anlatım)

Mobile malware (örn. Pegasus, Cerberus, Anubis) PC malware'inden farklı
C&C alt yapısı kullanır. SGB **MC** connectiontype'ı bu mobil-spesifik
indicator'ları işaretler.

Kural yalnızca **Mobile / MDM log source group** üzerinde çalışmalı —
yoksa kurum desktop trafiği bu rule'la karışır. MDM (Intune, Workspace
ONE) device_id ile kullanıcı kimliği eşleştirilebilir.

## Senaryo (Hikâye)

- 17:30 — Çalışanın iPhone'u kurum mobil VPN'i (GlobalProtect mobile)
  üzerinden `mc.spyware.example` domain'ine bağlanıyor.
- 17:30:01 — SIEM mobile log source + SGB_MC_DOMAIN match → severity 7.
- 17:30:05 — MDM admin'e bildirim; cihaz uzaktan inceleme prosedürüne
  alınır.

## BG Rehberi karşılığı

| Madde | Madde adı | Bu UC ne sağlar? |
|-------|-----------|-------------------|
| **3.3.1** | Akıllı Telefon ve Tablet Güvenliği | Mobil cihaz IoC tespiti. |
| **3.1.6.4** | Kara Liste Kullanımı | MC indicator'ları MDM kara listesinde. |
| **3.1.8.7** | Kayıt Analizi Araçları (SIEM) | Mobile log korelasyonu. |
| **3.1.10.4** | Siber Tehdit Bildirimlerinin Yönetilmesi | SGB MC feed kullanımı. |

## Teknik özet

| Alan | Değer |
|------|-------|
| ID | UC-MC-001 |
| MITRE | TA0011 / T1437 Mobile Application Layer Protocol |
| Connectiontype | MC |
| Severity (base) | 7 |
| Veri kaynakları | Mobile VPN (GlobalProtect mobile, Pulse mobile), MDM (Intune, Workspace ONE), Mobile gateway |
| Reference / lookup | `SGB_MC_IP`, `SGB_MC_DOMAIN`, `SGB_MC_URL` |
| Response | PB-MC-001 (MDM remote inspect + container wipe değerlendir) |

## Tespit mantığı

```text
when log source group = "Mobile / MDM"
  AND dest_ip in SGB_MC_IP OR query in SGB_MC_DOMAIN OR url in SGB_MC_URL
then alarm (severity=7), notify MDM admin, add device to SGB_MC_DEVICES
```

## QRadar uygulaması

```
when Log Source Group = "Mobile / MDM"
  AND dest_ip in SGB_MC_IP OR query in SGB_MC_DOMAIN OR url in SGB_MC_URL
```

## Splunk uygulaması

**Saved search:** `SGB - UC-MC-001 - Mobile C2 indicator`

```spl
(index=mobile_vpn OR index=mdm OR sourcetype=intune)
| lookup sgb_domain_lookup value AS query   OUTPUT connectiontype AS ct_dom
| lookup sgb_ip_lookup     value AS dest_ip OUTPUT connectiontype AS ct_ip
| where ct_dom="MC" OR ct_ip="MC"
| stats count by device_id, user, dest_ip, query
```

## Yanlış pozitif notları

- **BYOD personal traffic** VPN içine sızabilir → personal subnet
  exception.
- **Mobile APT simulation** → simulation device tag exception.

## Olay müdahale (PB-MC-001)

**Otomatik:**
1. MDM API: device'a "remote inspect" tetikle.
2. Cihazı `SGB_MC_DEVICES`'a ekle.

**Manuel:**
1. Hangi app trafiği üretiyor? MDM app inventory.
2. App store kaynağı meşru mu? (Resmi store vs side-load)
3. Container wipe değerlendir (kurumsal veri temizliği).
4. Kullanıcıyı bilgilendir.
