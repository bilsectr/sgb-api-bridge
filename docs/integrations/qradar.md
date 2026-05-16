# Entegrasyon: IBM QRadar

**Hedef:** SGB indicator'lari QRadar reference set + map olarak yuklensin,
3 baslangic use case rule'u aktiflessin, 1 gunluk rapor calissin.

**Tuketilen artifact:** `siem/qradar/out/` (build_pack.py uretir)

## On kosullar

- QRadar v7.4+ (REST API v15.0 minimum)
- Authorized service token (Admin > Authorized Services > Add Token)
  - Yetki: `Admin` veya en az `Reference Sets` + `Maps` yazma izni
- Network erisimi: builder (sizin host) -> QRadar Console TCP 443
- Python 3.10+ + `requests`

## Adim 1 — Pack'i uret

```bash
# DB hazirsa (sync.py --mode full bir kez calisti)
python scripts/build_pack.py
# Cikti: siem/qradar/out/
#   reference_sets/SGB_<CT>_<TYPE>.csv  (PH, BC, AC, EK, MF, MM, MC, OT)
#   reference_maps/SGB_<TYPE>_MAP.csv   (IP, Domain, URL, IP6, IP6NET)
#   manifest.json
```

Manifest'i kontrol edin (set/map sayilari beklediginiz gibi mi?):

```bash
python -c "import json; m=json.load(open('siem/qradar/out/manifest.json')); \
  print('sets:', len(m['reference_sets']), 'maps:', len(m['reference_maps']))"
```

## Adim 2 — QRadar'a push

```bash
export SGB_QRADAR_HOST=qradar.kurum.local
export SGB_QRADAR_TOKEN=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# Ilk olarak tek bir set ile sinayin (lab/uretim ayrimi)
python scripts/push_to_qradar.py --pack siem/qradar/out --only SGB_PH_DOMAIN

# Tum pack'i push'la
python scripts/push_to_qradar.py --pack siem/qradar/out

# (Lab: self-signed sertifika)
python scripts/push_to_qradar.py --pack siem/qradar/out --insecure
```

Push script idempotent: set/map mevcut ise atlar (HTTP 409), bulk_load merge yapar.

## Adim 3 — Set/map'leri UI'da dogrula

1. Admin > Reference Set Management
2. Filter: `SGB_` -> beklediginiz tum set/map'leri gormelisiniz
3. Birine cift tikla -> entry count + TTL = 25 hours

Veya REST ile:

```bash
curl -s -k -H "SEC: $SGB_QRADAR_TOKEN" \
  "https://$SGB_QRADAR_HOST/api/reference_data/sets?filter=name+startswith+'SGB_'" \
  | jq '.[] | {name, element_type, number_of_elements}'
```

## Adim 4 — Use case rule'larini kur

Kanonik tanimlar [docs/usecases/](../usecases/) altinda. Baslangic icin:

- [UC-PH-001](../usecases/UC-PH-001.md) — DNS phishing
- [UC-BC-001](../usecases/UC-BC-001.md) — Botnet C2 outbound
- [UC-AC-001](../usecases/UC-AC-001.md) — APT C2 (any match)

Her use case'in markdown'inda **QRadar** bolumunde rule tanimi adim-adim
verilmistir. UI'dan kurulum:

1. Offenses > Rules > Actions > New Event Rule
2. Use case markdown'indaki "QRadar Rule" bloguna gore test bloklarini sec
3. Reference set/map adlarini birebir kopyala
4. Severity formulu icin [severity-matrix.md](../../siem/qradar/severity-matrix.md)

## Adim 5 — AQL ile dogrulama

```aql
-- Son 1 saatte SGB_PH_DOMAIN'a hit alan kac event var?
SELECT COUNT(*) AS hits
FROM events
WHERE REFERENCESETCONTAINS('SGB_PH_DOMAIN', "URL") = TRUE
  AND starttime > NOW() - INTERVAL '1' HOUR
```

Hazir AQL'ler: [siem/qradar/aql/](../../siem/qradar/aql/)
- `uc-ph-001-test.aql`
- `uc-bc-001-test.aql`
- `report-daily-sgb-summary.aql` (cron raporu)

## Adim 6 — Periyodik yenileme

```bash
# Saatlik delta sonrasi
python scripts/sync.py --mode delta
python scripts/build_pack.py
python scripts/push_to_qradar.py --pack siem/qradar/out
```

Push yapilmazsa entry'ler 25 saatte TTL ile dusup rule'lar sessize gomulur
(bu kasitli — durmus pipeline'i fark etmek icin healthcheck).

Onerilen cron (Linux):

```cron
17 * * * * cd /opt/sgb && python scripts/sync.py --mode delta && \
           python scripts/build_pack.py && \
           python scripts/push_to_qradar.py --pack siem/qradar/out >> /var/log/sgb-push.log 2>&1
```

## Troubleshooting

| Belirti | Sebep | Cozum |
|---------|-------|-------|
| Push HTTP 401 | Token gecersiz/expire | Yeni token uret |
| Push HTTP 422 | Element type uyumsuz | Set'i sil ve yeniden olustur (rule referanslarini koru) |
| Set count beklenenden az | Bulk_load body limit | `--only` ile chunk'la push, veya QRadar config'ten max_request_size artir |
| Rule hic tetiklenmiyor | Log source property mapping eksik | DSM Editor'da DNS Query / URL property'lerini map'le |
| TTL sonrasi entry'ler dustu, push acik | Cron calismiyor | systemd timer / GitHub Actions log'lari kontrol |
