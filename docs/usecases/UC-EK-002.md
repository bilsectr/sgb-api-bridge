# UC-EK-002 — IDS Exploit Alarmı + SGB EK IP/URL Eşleşmesi (Composite)

> **TL;DR:** IDS/IPS sistemi (Snort, Suricata, Palo Alto Threat) bir
> exploit alarmı veriyor + AYNI source/destination çiftine 5 dakika
> içinde SGB EK indicator eşleşmesi var → yüksek hassasiyetli composite
> alarm (severity 9).

## Bu use case nedir? (Basit anlatım)

IDS tek başına çok yanlış pozitif üretir (özellikle imza tabanlı
sistemler). SGB EK feed tek başına da yanlış pozitif yapabilir
(threat hunting trafiği). Ama **iki sinyali aynı pencerede aynı host
çiftinde** birleştirmek false positive olasılığını çok azaltır.

Bu pattern'e SOC dünyasında **multi-source correlation** denir ve
BG Rehberi 3.1.8.7'nin "korelasyon kuralları doğrultusunda tespit"
ifadesinin tam karşılığıdır.

## Senaryo (Hikâye)

- 09:55 — Suricata "ET WEB-CLIENT Possible Magnitude EK"
  imzası tetikler: `10.X → 185.Y:80`.
- 09:55:03 — Aynı host çifti arasında proxy log'da
  `185.Y/exploit.swf` URL'si SGB EK URL eşleşmesi.
- 09:55:04 — UC-EK-002 koşulu sağlandı: IDS alert + SGB EK match
  / aynı src+dst / 5 dk pencere.
- 09:55:04 — Severity 9 alarm. SOC + IR.

## BG Rehberi karşılığı

| Madde | Madde adı | Bu UC ne sağlar? |
|-------|-----------|-------------------|
| **3.1.6.18** | A Tabanlı Saldırı Tespit/Engelleme Sistemi | IDS sinyali + IoC enrichment. |
| **3.1.6.28** | Uygulama Seviyesi Saldırıların Engellenmesi | EK exploit'leri uygulama katmanı. |
| **3.1.8.7** | Kayıt Analizi Araçları (SIEM) | Klasik multi-source korelasyon. |
| **3.1.5.1** | Zararlı Yazılımdan Korunma | Composite signal güçlü tespittir. |
| **3.1.10.4** | Siber Tehdit Bildirimlerinin Yönetilmesi | SGB EK feed kullanımı. |
| **3.1.10.8** | Siber Olay Puanlama ve Önceliklendirme | Composite → yüksek puan. |

## Teknik özet

| Alan | Değer |
|------|-------|
| ID | UC-EK-002 |
| MITRE | TA0002 / T1190 + T1203 |
| Connectiontype | EK (composite) |
| Severity (base) | 9 |
| Veri kaynakları | IDS/IPS (Snort, Suricata, Palo Alto Threat) + Web proxy |
| Reference / lookup | `SGB_EK_IP`, `SGB_EK_URL` |
| Response | PB-EK-002 (host isolation + IR fast track) |

## Tespit mantığı

```text
window = 5 dakika
condition:
  IDS event in category (browser-exploit, file-flash-exploit,
                        client-side-vulnerability)
  AND aynı (src_ip, dest_ip) çiftinde
  AND any of dest_ip / url IN (SGB_EK_IP, SGB_EK_URL)
=> escalate, severity=9
```

## QRadar uygulaması

**Kural tipi:** Common Rule (cross-source aggregator)

```
when IDS exploit category event happens
  AND SGB_EK_* set match happens
  on the same source IP and destination IP
  within 300 seconds
```

**Response:**
- Severity 9
- Dispatch "SGB EK + IDS confirmed"
- Auto-trigger host isolation (severity 9 threshold)

## Splunk uygulaması

**Saved search:** `SGB - UC-EK-002 - IDS + SGB EK composite`

```spl
((`sgb_ids_index` category IN (browser-exploit, client-vuln))
 OR (`sgb_proxy_index`))
| transaction src_ip dest_ip maxspan=5m
| where (signature="*exploit*") AND (sgb_url_ct="EK" OR sgb_dest_ct="EK")
```

## Yanlış pozitif notları

- **IDS false positive + irrelevant EK match:** yine de incelenmeli ama
  otomatik response yapma; SOC review queue'ya at, severity'yi tampon
  olarak 7'ye düşür.
- **Vulnerability scanner trafiği** IDS exploit alarmları üretebilir →
  scanner asset exception listesi.

## Olay müdahale (PB-EK-002)

**Otomatik:**
1. Host isolate (severity 9 eşiği).
2. Packet capture başlat.
3. IR P2 ticket.

**Manuel:**
1. IDS imzası hangi CVE'ye karşılık? Patch geldi mi?
2. EDR'da exploit sonrası persistance / privesc denemesi var mı?
3. Aynı CVE için kurum genelinde geniş tarama (vulnerability scanner ile).
