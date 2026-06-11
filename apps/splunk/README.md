# SGB Splunk Uygulamaları

SGB tehdit feed'i için Splunkbase hedefli iki paket. [SIEM use case
kütüphanesinin](../../docs/usecases/) Splunk'a paketlenmiş hâlidir —
kullanıcı 24 kuralı tek tek yazmak yerine uygulamayı kurup makroları
ayarlar ve kuralları tier sırasına göre enable eder.

| Paket | Rol |
|---|---|
| [`TA-sgb-threat-intel`](TA-sgb-threat-intel/) | Add-on: TAXII 2.1 modular input → STIX indicator ingest + domain/IP/URL lookup üretimi |
| [`sgb_usecases`](sgb_usecases/) | App: 24 use case saved search (UC-* kütüphanesiyle birebir) + 3 dashboard |

## Mimari

```
SGB TAXII 2.1 (sgb-taxii.bilsec.tr veya self-hosted)
        │  sgb_taxii modular input (saatlik, added_after incremental)
        ▼
index=sgb_ti  (sourcetype=sgb:stix:indicator, JSON event'ler)
        │  "SGB TA - Lookup Gen - *" scheduled search'leri (saatlik)
        ▼
sgb_indicators / sgb_domain_lookup / sgb_ip_lookup / sgb_url_lookup (CSV)
        │  UC saved search'leri (sgb_usecases app)
        ▼
index=sgb_summary  (alarm çıktıları; UC-XX-* meta kuralları ve
                    dashboard'lar buradan beslenir)
```

## Kurulum

1. **Index'leri oluşturun:** `sgb_ti` (STIX event'leri, ~470K event ilk
   dolumda) ve `sgb_summary` (alarm çıktıları). Farklı ad kullanacaksanız
   TA'daki `sgb_ti_index` ve app'teki `sgb_notable_index` makrolarını ve
   `inputs.conf` / `action.summary_index._name` değerlerini güncelleyin.
2. **İki paketi kurun** (önce TA): `python apps/splunk/build.py` çıktısı
   olan `.tar.gz`'leri *Manage Apps → Install app from file* ile yükleyin.
3. **TA input'larını enable edin:** *Settings → Data inputs → SGB TAXII
   2.1 Threat Feed* — 8 koleksiyon. İlk full pull ~470K indicator çeker
   (birkaç dakika); sonrası saatlik incremental.
   - Air-gapped / self-hosted: `discovery_url`'i kendi TAXII host'unuza
     çevirin ([setup-docker](../../docs/setup-docker.md), [setup-k8s](../../docs/setup-k8s.md)).
4. **Lookup'ları doğrulayın** (ilk saat başından sonra):
   `| inputlookup sgb_indicators | stats count by connectiontype`
5. **Veri kaynağı makrolarını ortamınıza çevirin:** `sgb_usecases`
   app'indeki `sgb_dns_index`, `sgb_proxy_index`, … makroları
   (*Settings → Advanced search → Search macros*).
6. **Kuralları tier sırasına göre enable edin**
   ([usecases/README.md#tiers](../../docs/usecases/README.md#tiers)):
   önce UC-XX-004 (A+B) + UC-PH-001/002/003 + UC-BC-001/002 + UC-AC-001/002.

## Enterprise Security notları

- Saved search'ler `action.correlationsearch.*` annotation'ları taşır
  (MITRE ATT&CK + BG Rehberi maddeleri) — ES Content Management /
  Use Case Library'de görünür.
- Notable üretmek isterseniz ilgili kuralda `action.notable`'ı açın;
  varsayılan teslimat ES'siz ortamda da çalışsın diye summary index'tir.
- Alternatif: ES Threat Intelligence Manager'a TAXII feed'i doğrudan da
  tanıtabilirsiniz ([docs/integrations/splunk.md](../../docs/integrations/splunk.md)
  Yöntem A); bu uygulamalar onu ikame etmez, kural+dashboard katmanını ekler.

## Bilinen sınırlamalar

- **Silinen indicator'lar lookup'tan otomatik düşmez** (TAXII incremental
  polling silme bilgisi taşımaz; SGB'de silme nadirdir). Tam mutabakat
  için: input'u durdurun, checkpoint dosyasını silin
  (`$SPLUNK_HOME/var/lib/splunk/modinputs/sgb_taxii/`), `sgb_ti`
  index'ini temizleyin/yeni index verin ve full re-pull yapın.
- UC-XX-005 retro-hunt subsearch'ü günde ~10K'dan fazla yeni domain
  geldiğinde sessizce kırpılır (Splunk subsearch limiti).
- UC SPL'lerindeki alan adları (`src_ip`, `query`, `url`, `action`, …)
  CIM benzeri varsayımlardır; kendi sourcetype'larınıza göre uyarlayın.

## Paketleme ve doğrulama

```bash
python apps/splunk/build.py        # dist/*.tar.gz üretir
pip install splunk-appinspect
splunk-appinspect inspect apps/splunk/dist/TA-sgb-threat-intel-1.0.0.tar.gz --mode precert
```

CI: [.github/workflows/splunk-appinspect.yml](../../.github/workflows/splunk-appinspect.yml)
her PR'da iki paketi build edip AppInspect'ten geçirir (cloud tag'leri dahil).

## Splunkbase yayın notları

- İki paket ayrı Splunkbase girdisi olarak yayınlanır (TA + App);
  App, TA'yı dependency olarak belirtir.
- Uygulama dış servise (`sgb-taxii.bilsec.tr`) bağlanır — Splunkbase
  açıklamasında ve cloud vetting formunda beyan edin; URL kullanıcı
  tarafından değiştirilebilir.
- SGB resmi bir kurumdur; açıklamada "community project, not affiliated
  with SGB" feragati korunmalı.
