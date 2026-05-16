# UC-MF-002 — EDR'de Dosya Yazıldı + Aynı Process SGB Malware Host'undan Çekti (Composite)

> **TL;DR:** EDR tarafından "process diske dosya yazdı" + aynı process'in
> network'te SGB MF host'una bağlandığı tespit edildi → diskte zararlı
> dosya **kesinlikle var**. Severity 8. Otomatik EDR isolate uygun.

## Bu use case nedir? (Basit anlatım)

UC-MF-001 proxy log seviyesinde "bir şeyler indirildi" der ama dosyanın
diske düşüp düşmediğini bilemez. EDR (CrowdStrike, SentinelOne, Defender
for Endpoint, Carbon Black) bu boşluğu doldurur:
- `process_network_connection` event'i: process X, SGB MF host'una bağlandı.
- `file_create` event'i: aynı process X, diske dosya yazdı (60 saniye içinde).

İki event aynı `process_guid` üzerinde → composite kanıt. Bu yüksek
güvenilirlikli sinyaldir; otomatik host isolation tetiklenebilir.

## Senaryo (Hikâye)

- 11:18:01 — `WIN-DEV-22`'de `powershell.exe` (PID 4912) network
  bağlantısı: `payload.evilmf.example:443`.
- 11:18:03 — Aynı PID 4912 diske `C:\Users\Public\update.exe` yazdı.
- 11:18:04 — SIEM composite kuralı: aynı `process_guid`, 60s pencere,
  destination SGB MF set'inde → alarm.
- 11:18:05 — EDR API: host isolate, dosya karantinaya al, memory dump.

## BG Rehberi karşılığı

| Madde | Madde adı | Bu UC ne sağlar? |
|-------|-----------|-------------------|
| **3.1.5.1** | Zararlı Yazılımdan Korunma | EDR + IoC composite = "anti-malware uygulamasının" gelişmiş hali. |
| **3.1.5.6** | Tespitlerin Merkezi Tutulması | EDR + SIEM birleşik kayıt. |
| **3.3.2** | Taşınabilir Bilgisayar Güvenliği | Notebook'larda EDR + bu UC. |
| **3.1.8.7** | Kayıt Analizi Araçları (SIEM) | Multi-source korelasyon. |
| **3.1.10.4** | Siber Tehdit Bildirimlerinin Yönetilmesi | SGB MF feed + EDR. |

## Teknik özet

| Alan | Değer |
|------|-------|
| ID | UC-MF-002 |
| MITRE | TA0002 / T1105 + TA0005 Defense Evasion |
| Connectiontype | MF (composite) |
| Severity (base) | 8 |
| Veri kaynakları | EDR (file_create + process_network) + opsiyonel Proxy |
| Reference / lookup | `SGB_MF_DOMAIN`, `SGB_MF_IP`, `SGB_MF_URL` |
| Response | PB-MF-002 (auto-isolate + forensic snapshot + IR) |

## Tespit mantığı

```text
window = 60 saniye
condition:
  EDR process_network event (dest_host in SGB_MF_DOMAIN OR
                              dest_ip in SGB_MF_IP)
  AND EDR file_create event by same process_guid
=> escalate, severity=8
```

## QRadar uygulaması

```
when EDR sourcetype event "Process Network Connection"
  AND destination host in SGB_MF_DOMAIN
  AND within 60 seconds
  AND EDR sourcetype event "File Create" by same process_guid
```

**Response:**
- EDR isolate API call (SOAR)
- Forensic snapshot
- Memory dump

## Splunk uygulaması

**Saved search:** `SGB - UC-MF-002 - EDR malware file fetched`

```spl
`sgb_edr_index` (action=process_network OR action=file_create)
| stats values(action) AS actions values(dest_host) AS dest_hosts
        values(file_path) AS files min(_time) AS t_min by process_guid, host
| where mvcount(actions)=2
| eval has_sgb=if(match(dest_hosts, "(SGB_MF_lookup pattern)"), 1, 0)
| where has_sgb=1
```

## Yanlış pozitif notları

- **Yazılım güncelleme** (Microsoft Update, Adobe, vendor patcher) →
  trusted publisher signing exception.
- **Sandbox / detonation ortamı** → dedicated host group exception.

## Olay müdahale (PB-MF-002)

**Otomatik:**
1. EDR isolate.
2. Dosya hash karantina + EDR vendor cloud submit.
3. Memory snapshot.
4. IR ticket (P2).

**Manuel:**
1. Process zinciri (parent, child) — kim çağırdı powershell.exe'yi?
2. Persistence kontrolü (autoruns, services).
3. Geniş arama: aynı dosya hash başka host'larda var mı?
4. Disk imaging.
