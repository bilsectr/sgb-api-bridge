# Entegrasyon: Microsoft Sentinel

**Hedef:** SGB STIX 2.1 indicator'larini Sentinel Threat Intelligence
blade'ine ingest et; analytics rule'lar bu ti'i kullanarak alarm uretebilsin.

**Tuketilen artifact:** `feeds/stix/sgb-{type}.stix2.json`

## On kosullar

- Azure Sentinel (Microsoft Sentinel)
- Log Analytics Workspace + Sentinel etkin
- "Microsoft Sentinel Contributor" rolu (rule olusturma)
- Threat Intelligence Upload API kullanilacaksa: App registration + secret +
  `ThreatIndicators.ReadWrite.OwnedBy` permission (Microsoft Graph API)

## Yontem A — Logic App ile STIX → TI Upload API (onerilen)

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

### Adim 1 — App registration

Azure AD'de yeni app:
- API permissions: **Microsoft Graph** > `ThreatIndicators.ReadWrite.OwnedBy`
- Grant admin consent
- Client secret olustur

### Adim 2 — Logic App

`siem/sentinel/logic-app-sgb-stix.json` (commit'li sablon; ozellestir):

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
              "uri": "https://github.com/bilsectr/sgb-api-bridge/releases/latest/download/sgb-@{item()}.stix2.json"
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

### Adim 3 — Dogrulama

Sentinel UI > **Threat Intelligence** > Filter: `Source = "sgb"` (veya
benzeri). Indicator'lar listelenmeli; her birinin TI properties'inde
`x_sgb_*` custom field'larimiz gorulur.

KQL test:

```kusto
ThreatIntelligenceIndicator
| where SourceSystem == "Microsoft Emerging Threat Feed"
| where Description has "SGB"
| summarize count() by ThreatType, ConfidenceScore
```

## Yontem B — TAXII connector (TAXII 2.1 server'imiz olursa)

Sentinel'in built-in **Threat Intelligence - TAXII** data connector'i TAXII
2.0/2.1 collection'larini destekler. SGB tarafindan TAXII server (medallion
gibi) ayaga kaldirilirsa:

1. Sentinel > Data connectors > **Threat Intelligence - TAXII**
2. Friendly name: `SGB`
3. API root URL: `https://taxii.bilsectr.github.io/...`
4. Collection ID: `sgb-all` (veya per-type)
5. Username/Password: (varsa)
6. Polling frequency: 1 hour

**Henuz uygulanmadi.**

## Yontem C — Custom analytics rule (lookup, ti'siz)

TI ingest yapmadan da SGB master CSV'sini direkt KQL'de kullanmak mumkun
(daha hizli POC):

```kusto
// CSV master Release artifact'inden (sgb-feeds.tar.gz icinden çıkarılıp
// blob storage'a/azure storage account'a yuklenmis varsayilir):
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

## Analytics rule onerileri (TI ingest sonrasi)

Built-in template: **"TI map IP entity to AzureActivity"** (ve diger
"TI map ..." rule'lari). Bunlar otomatik olarak ingest edilen indicator'lara
karsi log'lari tarar — extra is yok, sadece enable et.

Manuel custom rule:

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

Microsoft Graph TI Upload API `expirationDateTime` alani gerektirir.
Logic App'te her indicator'a `now + 25h` set edin (SGB push cadence ile uyumlu):

```
expirationDateTime = addHours(utcNow(), 25)
```

Boylece SGB feed'inden silinen indicator'lar 25 saat sonra otomatik
duser, manuel temizlik gerekmez.

## Troubleshooting

| Belirti | Sebep | Cozum |
|---------|-------|-------|
| Logic App 401 | Token expired / permission missing | App permissions + admin consent kontrol |
| Indicator yok ama log basarili | Body STIX 2.1 spec'e uymuyor | Bundle'i [stix-validator](https://github.com/oasis-open/cti-stix-validator) ile dogrula |
| ConfidenceScore 0 | TI API confidence map yanlis | Logic App'te STIX `confidence` -> TI `confidenceScore` map kontrol |
| Duplicate indicators | Determinitsik UUID degil | `feeds/stix/*` bundle'larinda STIX_NS sabit oldugundan emin (export.py'da hardcoded) |
