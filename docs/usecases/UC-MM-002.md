# UC-MM-002 — CPU Yükü Yüksek + SGB MM Eşleşmesi (Composite)

> **TL;DR:** UC-MM-001 sadece "mining IP'sine bağlanıyor" der.
> UC-MM-002: bağlanma + aynı zamanda CPU sürekli %85+ + ağ çıkışının
> %20+'sı mining destination'ına → aktif mining'in kanıtı. Severity 5.

## Bu use case nedir? (Basit anlatım)

Mining yapıyorsa belirti:
1. Mining pool'a sürekli bağlantı (UC-MM-001 yakalar).
2. CPU yüksek kalır (mining hesaplama yapar).
3. Bandwidth küçük ama sürekli (job/result paketleri).

EDR/OS metric (perf telemetry) ile SGB MM hit composite olunca aktif
mining kesinleşir. Severity 5 — politika dışı resource kullanımı + ciddi
performans etkisi.

## Senaryo (Hikâye)

- 14:00-15:00 — `LIN-PROD-09` üzerinde CPU avg %92 (baseline %15).
- Aynı pencerede 80% network egress mining pool IP'sine.
- 15:00:15 — Composite alarm: severity 5, IR ticket P3.

## BG Rehberi karşılığı

| Madde | Madde adı | Bu UC ne sağlar? |
|-------|-----------|-------------------|
| **3.1.5.1** | Zararlı Yazılımdan Korunma | Cryptojacking aktif → EDR doğrulamalı kanıt. |
| **3.1.8.7** | Kayıt Analizi Araçları (SIEM) | Perf + network korelasyonu. |
| **3.1.10.8** | Siber Olay Puanlama ve Önceliklendirme | Composite → puan yükseltilir. |

## Teknik özet

| Alan | Değer |
|------|-------|
| ID | UC-MM-002 |
| MITRE | TA0040 / T1496 |
| Connectiontype | MM (composite) |
| Severity (base) | 5 |
| Veri kaynakları | EDR perf telemetry / OS metrics + UC-MM-001 (SGB MM hit) |
| Reference / lookup | `SGB_MM_IP`, `SGB_MM_DOMAIN` |

## Tespit mantığı

```text
window = 1 saat
condition:
  same host AND SGB_MM_* hit (within last 5 min)
  AND avg CPU pct > 85 (vs baseline)
  AND % egress to mining_destination > 20
=> escalate
```

## QRadar / Splunk

**QRadar:** Common Rule combining UC-MM-001 + EDR custom event
"high CPU asset"; time correlation 1 saat, same asset.

**Splunk:** Saved search joining EDR perf index + `sgb_dest_ct="MM"`.

```spl
`sgb_edr_perf_index` earliest=-1h
| stats avg(cpu_pct) AS avg_cpu by host
| where avg_cpu > 85
| join host [search `sgb_notable_index` sgb_ct="MM" earliest=-5m | stats count by host]
```

## Yanlış pozitif notları

- **ML training, video render, build server** → exception by asset role.
- **Sintetik load test** → exception when scheduled.

## Olay müdahale (PB-MM-002)

**Otomatik:**
1. Process kill (eğer policy izin veriyorsa).
2. IR ticket P3.

**Manuel:**
1. Mining binary nerede? Persistence var mı?
2. Imaj/container ise → registry malware kontrolü.
3. Aynı imajdan başka host çalışıyor mu? Geniş tarama.
