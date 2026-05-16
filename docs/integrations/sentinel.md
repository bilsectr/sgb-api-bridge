# Entegrasyon: Microsoft Sentinel

> **Hedef:** SGB STIX 2.1 indicator'ları Sentinel Threat Intelligence
> blade'ine ingest et; analytics rule'lar bu TI'ı kullanarak alarm
> üretebilsin.

**Tüketilen artifact:** `feeds/stix/sgb-{type}.stix2.json`

## BG Rehberi karşılığı

| Madde | Madde adı | Bu entegrasyon nasıl karşılar? |
|-------|-----------|--------------------------------|
| **3.1.8.6** | Merkezi Kayıt Yönetimi | Sentinel = bulut SIEM. |
| **3.1.8.7** ⭐ | Kayıt Analizi Araçları (SIEM) | KQL analytics rule'lar = korelasyon. |
| **3.1.10.4** ⭐ | Siber Tehdit Bildirimlerinin Yönetilmesi | SGB STIX → Sentinel TI blade. |
| **4.3** | Bulut Bilişim Güvenliği | Bulut SIEM kullanımı bu bölüm kapsamındadır. |
| **3.1.11.1** | Sızma Testleri ve Güvenlik Denetimleri | Sentinel "indicator backsearch" pattern'i sürekli geriye dönük tarama yapar = sızma testinin sürekli versiyonu. |

## Ön koşullar

- Azure Sentinel (Microsoft Sentinel)
- Log Analytics Workspace + Sentinel etkin
- "Microsoft Sentinel Contributor" rolü (rule oluşturma)
- Threat Intelligence Upload API kullanılacaksa: App registration + secret +
  `ThreatIndicators.ReadWrite.OwnedBy` permission (Microsoft Graph API)

## Yöntem A — Logic App ile STIX → TI Upload API (önerilen)

### Mimari

```
SGB feeds/stix/sgb-*.stix2.json
        |
        | (HTTP GET, scheduled hourly)
        v
Azure Logic App
   - Parse STIX bundle
   - Map STIX indicator -> TI API format
   - POST to Microsoft Graph TI Upload API
        |
        v
Sentinel Threat Intelligence (Indicators blade)
```

### Adım 1 — App registration

Azure AD'de yeni app:

- API permissions: **Microsoft Graph** > `ThreatIndicators.ReadWrite.OwnedBy`
- Grant admin consent
- Client secret oluştur

### Adım 2 — Logic App

`siem/sentinel/logic-app-sgb-stix.json` (commit'li şablon; özelleştir):

```json
{
  "definition": {
    "triggers": {
      "Recurrence": { "type": "Recurrence",
        "recurrence": { "frequency": "Hour", "interval": 1 } }
    },
    "actions": {
      "ForEach_Type": {
        "type": "Foreach",
        "foreach": ["domain", "url", "ip", "ip6", "ip6net"],
        "actions": {
          "HTTP_Get_Bundle": {
            "type": "Http",
            "inputs": {
              "method": "GET",
              "uri": "https://github.com/bilsectr/sgb-api-bridge/releases/download/feeds-latest/sgb-@{item()}.stix2.json"
            }
          },
          "Submit_to_TI_API": {
            "type": "Http",
            "inputs": {
              "method": "POST",
              "uri": "https://graph.microsoft.com/v1.0/security/threatIntelligence/sourceIndicators/microsoftEmergingThreatFeed/uploadIndicatorsAsStix",
              "headers": { "Content-Type": "application/json" },
              "authentication": {
                "type": "ActiveDirectoryOAuth",
                "tenant": "<TENANT_ID>",
                "audience": "https://graph.microsoft.com",
                "clientId": "<APP_ID>",
                "secret": "@{parameters('client_secret')}"
              },
              "body": "@body('HTTP_Get_Bundle')"
            }
          }
        }
      }
    }
  }
}
```

Deploy:

```bash
az logic workflow create --resource-group sgb-rg \
  --name sgb-stix-ingest \
  --definition @siem/sentinel/logic-app-sgb-stix.json \
  --location westeurope
```

### Adım 3 — Doğrulama

Sentinel UI > **Threat Intelligence** > Filter: `Source = "sgb"` (veya
benzeri). Indicator'lar listelenmeli; her birinin TI properties'inde
`x_sgb_*` custom field'larımız görülür.

KQL test:

```kusto
ThreatIntelligenceIndicator
| where SourceSystem == "Microsoft Emerging Threat Feed"
| where Description has "SGB"
| summarize count() by ThreatType, ConfidenceScore
```

## Yöntem B — TAXII connector (TAXII 2.1 server'ımız olursa)

Sentinel'in built-in **Threat Intelligence - TAXII** data connector'ı
TAXII 2.0/2.1 collection'larını destekler. SGB tarafından TAXII server
(medallion gibi) ayağa kaldırılırsa:

1. Sentinel > Data connectors > **Threat Intelligence - TAXII**
2. Friendly name: `SGB`
3. API root URL: `https://taxii.bilsectr.github.io/...`
4. Collection ID: `sgb-all` (veya per-type)
5. Username/Password: (varsa)
6. Polling frequency: 1 hour

**Henüz uygulanmadı.**

## Yöntem C — Custom analytics rule (lookup, TI'sız)

TI ingest yapmadan da SGB master CSV'sini direkt KQL'de kullanmak mümkün
(daha hızlı POC):

```kusto
// CSV master Release artifact'inden (sgb-feeds.tar.gz içinden çıkarılıp
// blob storage'a/azure storage account'a yüklenmiş varsayılır):
let SgbIp = externaldata(value:string, ct:string, desc:string, crit:int, src:string, fs:datetime)
    [@"https://<your-storage>.blob.core.windows.net/sgb/by-connectiontype/bc-ip.txt"]
    with (format="txt", ignoreFirstRecord=false);
CommonSecurityLog
| where TimeGenerated > ago(1h)
| where DestinationIP in (SgbIp | project value)
| extend SgbCt = "BC"
| project TimeGenerated, SourceIP, DestinationIP, DeviceVendor, Activity, SgbCt
```

Scheduled analytics rule olarak yeni kural ekleyin (Severity = High).

## Analytics rule önerileri (TI ingest sonrası)

Built-in template: **"TI map IP entity to AzureActivity"** (ve diğer
"TI map ..." rule'ları). Bunlar otomatik olarak ingest edilen
indicator'lara karşı log'ları tarar — extra iş yok, sadece enable et.

Manuel custom rule (UC-BC-001 muadili):

```kusto
let sgb_ti = ThreatIntelligenceIndicator
    | where ConfidenceScore >= 60
    | where ThreatType in ("Botnet", "C2");
sgb_ti
| join kind=inner (CommonSecurityLog | where TimeGenerated > ago(1h))
    on $left.NetworkIP == $right.DestinationIP
| project TimeGenerated, SourceIP, DestinationIP, ThreatType, ConfidenceScore, Description
```

## Lifecycle / expiration

Microsoft Graph TI Upload API `expirationDateTime` alanı gerektirir.
Logic App'te her indicator'a `now + 25h` set edin (SGB push cadence ile
uyumlu):

```
expirationDateTime = addHours(utcNow(), 25)
```

Böylece SGB feed'inden silinen indicator'lar 25 saat sonra otomatik
düşer, manuel temizlik gerekmez.

## Indicator backsearch (BG 3.1.11.1 ile bağlantı)

Sentinel her yeni indicator için **geçmiş 14 güne kadar geriye dönük**
log tarar (Threat Intelligence built-in rule'lar bu davranışı default
olarak yapar). Bu özellik BG **3.1.11.1**'in "düzenli sızma testleri /
güvenlik denetimleri" beklentisinin **sürekli** versiyonudur: SGB feed'inde
yeni indicator çıktığında geçmişteki tüm log'lar otomatik taranır →
"bunu daha önce hiç görmüşmüyüz?" sorusunun cevabı sürekli güncel.

## Troubleshooting

| Belirti | Sebep | Çözüm |
|---------|-------|-------|
| Logic App 401 | Token expired / permission missing | App permissions + admin consent kontrol |
| Indicator yok ama log başarılı | Body STIX 2.1 spec'e uymuyor | Bundle'ı [stix-validator](https://github.com/oasis-open/cti-stix-validator) ile doğrula |
| ConfidenceScore 0 | TI API confidence map yanlış | Logic App'te STIX `confidence` → TI `confidenceScore` map kontrol |
| Duplicate indicators | Determinitsik UUID değil | `feeds/stix/*` bundle'larında STIX_NS sabit olduğundan emin (export.py'da hardcoded) |
