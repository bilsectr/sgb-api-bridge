# SGB QRadar Content Extension

UC kütüphanesinin QRadar paketi. Splunk'tan farklı olarak QRadar kuralları
dosya formatında elle yazılamaz — kurallar **lab QRadar'ında UI ile bir kez
oluşturulur**, Content Management Tool (CMT) ile export edilir ve çıkan zip
dağıtılır. Bu dizin o akışın araçlarını içerir.

## İş akışı

```
1. setup_feeds.py          8 TAXII feed + reference set'leri REST ile kur
2. rule-sheet.md           24 kuralı tier sırasıyla lab UI'da oluştur
                           (tek doküman; UC dosyalarından üretilir)
3. CMT export              /opt/qradar/bin/contentManagement.pl -a export -c 28 -i <grup>
4. build.py                export zip'ini dağıtım paketine çevir (dist/)
5. Yayın                   App Exchange (IBM partner gerekli) veya kendi site
```

| Dosya | Ne yapar |
|---|---|
| [setup_feeds.py](setup_feeds.py) | TI app'e 8 TAXII feed + UC response'larının reference set'lerini kurar (idempotent, `--dry-run` destekli) |
| [make_rule_sheet.py](make_rule_sheet.py) | `docs/usecases/`'ten [rule-sheet.md](rule-sheet.md)'yi üretir |
| [rule-sheet.md](rule-sheet.md) | Lab'da kural girişi için tier sıralı çalışma dokümanı (üretilmiş dosya) |
| [build.py](build.py) | CMT export zip'ini README+LICENSE ile dağıtım paketine sarar |

## Lab kurulum adımları

1. QRadar 7.5+ console'da **authorized service token** alın
   (Admin → Authorized Services; Threat Intelligence + Reference Data +
   Rules yetkili rol).
2. Feed + set kurulumu:

   ```powershell
   $env:QRADAR_TOKEN = "..."
   python apps/qradar/setup_feeds.py --host qradar.lab.local --dry-run   # önce payload'ları gör
   python apps/qradar/setup_feeds.py --host qradar.lab.local --insecure  # lab self-signed ise
   ```

   > `POST /api/threat_intelligence/feeds` endpoint'i TI app sürümüne göre
   > alan adı değiştirebilir — `--dry-run` çıktısındaki payload'ı app'in
   > Interactive API docs'uyla (`/api_doc`) karşılaştırın, gerekirse
   > `FEED_PAYLOAD_TEMPLATE`'i uyarlayın. HATA alırsanız feed'leri UI'dan
   > ekleyin ([docs/integrations/qradar.md](../../docs/integrations/qradar.md) Adım 1).

3. Feed'lerin "Connected" olduğunu ve indicator saydığını doğrulayın
   (Adım 2, qradar.md).
4. **"SGB Use Cases" rule grubu** oluşturun; [rule-sheet.md](rule-sheet.md)'yi
   baştan sona takip ederek 24 kuralı girin (Tier 1 → 2 → 3). Kuralları
   **disabled** bırakın — enable kararı kuruluma aittir.
5. Test: AQL doğrulama sorguları (qradar.md Adım 4) + örnek event'lerle
   rule test (DSM Editor → test events).

## Export ve paketleme

```bash
# Console'da (rule grubunun id'sini -i ile verin; -t bağımlılıkları da alır):
/opt/qradar/bin/contentManagement.pl -a export -c 28 -i <rule_group_id> -t

# Lokal:
python apps/qradar/build.py --input <export.zip> --version 1.0.0
```

`dist/sgb-qradar-content-<version>.zip` çıkar; içindeki
`sgb-usecases-content-<version>.zip` QRadar'a import edilen dosyadır.

## Yayın seçenekleri

| Kanal | Koşul | Not |
|---|---|---|
| **Kendi site / GitHub Release** | yok | Dağıtım paketini release asset olarak yayınla; README'de import adımları hazır |
| **IBM App Exchange** | IBM Business/Technology Partner hesabı | Validation 4-8 hafta; CMT zip'i tek başına yüklenir; "not affiliated with SGB" feragati açıklamada kalmalı |

## Extension'ın kapsamadıkları (bilinçli)

- **TAXII feed tanımları** — QRadar content extension formatı TI app feed
  config'ini taşımaz; `setup_feeds.py` veya UI ile kurulur.
- **Pulse dashboard** — ilk sürümde yok; kurallar offense ürettiği için
  standart Offenses görünümleri yeterli. İkinci sürümde Pulse dashboard
  JSON'u eklenebilir.
