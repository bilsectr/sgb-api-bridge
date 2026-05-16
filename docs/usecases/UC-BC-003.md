# UC-BC-003 — SGB IP'sine Periyodik Beacon Trafiği (NetFlow)

> **TL;DR:** Bot, C&C ile "ben hala buradayım" şeklinde periyodik (her
> 30-60 saniyede bir) küçük paketler gönderir — buna **beacon** denir.
> Bu UC: NetFlow/IPFIX log'larında periyodik paterni + SGB IP eşleşmesi
> bulduğunda alarm üretir.

## Bu use case nedir? (Basit anlatım)

Tek bir bağlantı tek tek bakıldığında masum görünebilir. Ama bir host
SGB botnet C&C IP'sine **eşit aralıklarla, küçük boyutlu, çok sayıda**
flow üretiyorsa bu **beacon paternidir** ve botnet aktivitesinin
neredeyse kesin göstergesidir.

UC-BC-001 tek hit'te bile alarm verir; bu UC paterni doğrular: 5+ flow,
düşük standart sapmalı inter-arrival time, küçük byte sayısı + SGB BC IP.

Bu kombinasyon SOC için "false positive değil, gerçek bot" kanıtıdır.

## Senaryo (Hikâye)

- 02:00 - 03:00 arasında `WIN-LAB-07` her 45±5 saniyede bir
  `185.X.X.X:8443`'e ~512 byte boyutlu TCP flow üretir.
- 03:00:15 — SIEM saatlik flow aggregate: 80 flow, median 45s, stdev 5s,
  avg bytes 530.
- 03:00:15 — Destination IP `SGB_BC_IP`'de → UC-BC-003 koşulu sağlandı,
  alarm.

## BG Rehberi karşılığı

| Madde | Madde adı | Bu UC ne sağlar? |
|-------|-----------|-------------------|
| **3.1.6.4** | Kara Liste Kullanımı | SGB IP kara listesi NetFlow analizinde kullanılır. |
| **3.1.6.18** | A Tabanlı Saldırı Tespit/Engelleme Sistemi | NetFlow + IoC = network-bazlı IDS davranışı. |
| **3.1.8.7** | Kayıt Analizi Araçları (SIEM) | NetFlow log korelasyonu. |
| **3.1.8.8** | SIEM Düzenli Yapılandırma | Beacon threshold'ları sürekli kalibre edilmeli. |
| **3.1.10.4** | Siber Tehdit Bildirimlerinin Yönetilmesi | SGB IP feed'i + davranışsal analiz. |
| **3.1.10.8** | Siber Olay Puanlama ve Önceliklendirme | Beacon paterni teyit edilmiş olay → öncelik artırılır. |

## Teknik özet

| Alan | Değer |
|------|-------|
| ID | UC-BC-003 |
| MITRE | TA0011 / T1071 + T1029 Scheduled Transfer |
| Connectiontype | BC |
| Severity (base) | 8 |
| Veri kaynakları | NetFlow v5/v9, sFlow, IPFIX, firewall flow log |
| Reference / lookup | `SGB_BC_IP` |
| Response | PB-BC-003 (host isolation + memory dump + IR) |

## Tespit mantığı

```text
window = 1 saat
group_by = (source_ip, destination_ip)
condition:
  flow_count >= 5
  AND median_inter_arrival < 60 saniye
  AND stddev(inter_arrival) < 20 saniye
  AND dest_ip in SGB_BC_IP
  AND avg_bytes_per_flow < 4096
=> alarm
```

## QRadar uygulaması

**Kural tipi:** Flow Rule + custom property "Avg Flow Interval"

Aggregator: "Bu kural aynı source IP + dest IP'de 1 saat içinde en az 5
kez match etti."

```
when flow event matches:
  destination IP in SGB_BC_IP
  AND flow byte count < 4096
THEN match must occur at least 5 times in 1 hour
     on the same source IP and destination IP
```

**Response:**
- Severity 8 + criticality
- Annotate offense "SGB Botnet Beacon Pattern"
- SOAR host isolate

## Splunk uygulaması

**Saved search:** `SGB - UC-BC-003 - Beacon pattern SGB IP`

```spl
`sgb_netflow_index` earliest=-1h
| lookup sgb_ip_lookup value AS dest_ip OUTPUT connectiontype
| where connectiontype="BC"
| sort 0 src_ip dest_ip _time
| streamstats current=f window=1 last(_time) AS prev_time by src_ip, dest_ip
| eval interval=_time-prev_time
| stats count AS flows median(interval) AS med stdev(interval) AS sd
        avg(bytes) AS avg_b values(dest_ip) AS dst by src_ip
| where flows>=5 AND med<60 AND sd<20 AND avg_b<4096
```

## Yanlış pozitif notları

- **SaaS heartbeat** (Slack, Teams, Datadog agent) normalde SGB IP'ye
  düşmez; ama feed yanlışlıkla bir bulut IP'sini içerirse → SOC review
  süreci, exception listesi.
- **Monitoring probe'ları** (Nagios, Zabbix) periyodik bağlantı yapar;
  ama dest IP'ler tanımlı internal'dır → external SGB IP eşleşmesi
  monitoring değildir.
- **Cron-based business job'lar** (ör. saatlik fatura sync) → exception
  by source asset role.

## Olay müdahale (PB-BC-003)

**Otomatik:**
1. Host isolate (EDR).
2. Packet capture başlat.
3. Memory dump talebi IR ticket'ına otomatik eklenir.

**Manuel:**
1. Process tree analizi: hangi process'in beacon yaptığı.
2. Persistence mechanism araştır (registry run keys, scheduled tasks,
   services).
3. Lateral hareket kontrolü: aynı C&C'ye bağlanan başka host var mı.
4. SGB raporlama input'u hazırla.
