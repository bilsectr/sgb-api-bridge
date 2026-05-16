# UC-BC-001 — Kurum İçinden SGB Botnet C&C IP'sine Giden Bağlantı

> **TL;DR:** Bir kurum bilgisayarı, SGB'nin "Botnet C&C (Komuta Kontrol)"
> olarak işaretlediği bir IP'ye dışa doğru bağlantı kurduğunda alarm
> üretir. C&C bağlantısı = makinenin botnet ağına dahil olduğunun
> neredeyse kesin göstergesi.

## Bu use case nedir? (Basit anlatım)

Botnet = zararlı yazılım bulaşmış cihazların oluşturduğu, dışarıdan
komuta-kontrol (C&C / C2) sunucusu tarafından yönetilen ağ. Bot, periyodik
olarak C&C'ye bağlanır ve komut bekler.

SGB'nin botnet C&C **IP listesi** (`SGB_BC_IP`) firewall, NetFlow ve proxy
log'larındaki **destination IP** alanı ile karşılaştırılır. Eşleşme
varsa: kurum içi bir host'tan SGB'nin "Burası bilinen botnet C&C" dediği
adrese trafik var → ciddi compromise sinyali.

PH'ten farkı: PH = "bir tıklama, henüz infekte olmayabilir". BC = "host
zaten infekte, dış dünyaya komut için bağlanıyor".

## Senaryo (Hikâye)

- 11:23 — Önceden TrickBot bulaşmış olan `WIN-FIN-04` adlı muhasebe PC'si
  periyodik C&C bağlantısı dener: `tcp/443 → 185.X.X.X` (SGB botnet IP).
- 11:23:01 — Firewall log: `permit, 10.20.30.40 → 185.X.X.X:443`.
- 11:23:02 — SIEM destination IP'yi `SGB_BC_IP` set'inde bulur.
- 11:23:02 — Severity base 8 + asset criticality (8) = nihai 10. P1 alarm.
- 11:23:05 — SOAR otomatik: host'u network'ten izole et (EDR / 802.1x
  quarantine VLAN), tam diski snapshot al, IR ekibini çağır.

## BG Rehberi karşılığı

| Madde | Madde adı | Bu UC ne sağlar? |
|-------|-----------|-------------------|
| **3.1.5.1** | Zararlı Yazılımdan Korunma + Merkezi Yönetim | Botnet C&C tespiti = zararlı yazılımdan korunmanın network katmanı kanıtı. |
| **3.1.5.6** | Zararlı Yazılım Tespit Kayıtlarının Merkezi Tutulması | Bu UC'nin ürettiği alarm tam olarak merkezde tutulan tespit kaydıdır. |
| **3.1.6.4** | Kara Liste veya Beyaz Liste Kullanımı | SGB botnet IP listesi firewall kara listesinin **ulusal/onaylı** bileşenidir. |
| **3.1.6.5** | İzin Verilmeyen Trafiğin Engellenmesi | Hit = engelleme kuralının düzgün çalışmadığının kanıtı; reactive engelleme + güvenlik duvarı kuralı incelemesi gerek. |
| **3.1.8.6** | Merkezi Kayıt Yönetimi | Alarm SIEM offense'ı olarak merkezde tutulur. |
| **3.1.8.7** | Kayıt Analizi Araçları (SIEM) | UC bizatihi SIEM kuralıdır. |
| **3.1.10.4** | Siber Tehdit Bildirimlerinin Yönetilmesi | SGB botnet feed'i → operasyonel önlem. |
| **3.1.10.5** | Siber Olay Raporlarının Standardize Edilmesi | BC seviyesi olay raporu için zorunlu vaka. |

## Teknik özet

| Alan | Değer |
|------|-------|
| ID | UC-BC-001 |
| MITRE | TA0011 Command & Control / T1071 Application Layer Protocol C2 |
| Connectiontype | BC |
| Severity (base) | 8 (criticality ile 10'a çıkar) |
| Veri kaynakları | Firewall (Palo Alto, Fortinet, Cisco ASA), NetFlow/sFlow/IPFIX, Proxy |
| Reference / lookup | `SGB_BC_IP` + `SGB_IP_MAP` |
| Response | PB-BC-001 (host isolation + packet capture + IR ticket) |

## Tespit mantığı

```text
when firewall permit / proxy allow / netflow accepted event geldi
  AND destination_ip alanı SGB_BC_IP set'inde
  AND source network "Trusted"
then offense aç, severity=8 + criticality modifier
     source IP'yi SGB_INFECTED_HOSTS'a ekle (TTL 7 gün)
     SOAR webhook tetikle (host isolation)
```

## QRadar uygulaması

**Kural tipi:** Event Rule + Flow Rule (paralel çalışsın; her ikisi de
hit aldığında deduplication QRadar tarafında halledilir).

**Event side:**
```
when the event QID is one of the following: Firewall Permit, Proxy Allow
  AND when any of (Destination IP) is contained in any of: SGB_BC_IP
  AND when the source network is one of: Trusted
```

**Flow side:** Aynı mantık `destinationip` için.

**Response:**
- Dispatch new event "SGB Botnet C2 Outbound"
- Magnitude severity: 8 → AQL action ile criticality lookup
- Annotate offense + add to `SGB_INFECTED_HOSTS` (TTL 7 gün)
- Forward to SOAR (webhook / syslog CEF)

## Splunk uygulaması

**Saved search:** `SGB - UC-BC-001 - Botnet C2 outbound`

```spl
(`sgb_firewall_index` action=allowed) OR (`sgb_netflow_index`)
| lookup sgb_ip_lookup value AS dest_ip OUTPUT connectiontype, criticality_level, source
| where connectiontype="BC"
| eval severity=8 + criticality_level
| stats count values(dest_ip) AS dest_ips by src_ip, source, severity
```

## Yanlış pozitif notları

- **BC base severity zaten yüksek;** `source=IH` olsa bile alarm açın.
  Botnet IP'leri IH'de bile çoğu zaman güvenilirdir.
- **Cloud egress NAT'larını exception edin:** aksi halde tek bir NAT
  gateway'in tüm trafiği "compromised host" gösterilir.
- **SOC sandbox / detonation host'ları** kasten botnet IP'ye bağlanır →
  exception listesi (`SGB_BC_EXEMPT_ASSETS`).

## Olay müdahale (PB-BC-001)

**Otomatik:**
1. EDR API: host izole (network only — kullanıcı IR uzmanı bağlanabilsin).
2. Firewall: `src_ip` için TCP/UDP dış trafik engelle (geçici 4 saat).
3. Packet capture başlat (firewall mirror port veya host-side).
4. P1 ticket SOAR'da aç, IR yöneticisi pager.

**Manuel:**
1. Hangi process bağlanıyor? EDR process tree çıkar.
2. Aynı C&C IP'sine bağlanan başka host var mı? Geniş sorgu.
3. Disk imaging başlat (öncelik: %SystemRoot%, %Temp%, AppData).
4. SGB raporlaması (3.1.10.5): olay numarası ile birlikte raporu hazırla.
