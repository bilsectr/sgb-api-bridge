# TA-sgb-threat-intel

TAXII 2.1 add-on for the SGB (Siber Güvenlik Başkanlığı, formerly USOM)
public threat intelligence feed. Community project — **not affiliated
with SGB**.

## What it does

- `sgb_taxii` modular input polls the SGB TAXII 2.1 service
  (`https://sgb-taxii.bilsec.tr/taxii2/` by default, self-hosted
  endpoints supported) and indexes STIX 2.1 indicators as JSON events
  (`sourcetype=sgb:stix:indicator`, default index `sgb_ti`).
- Hourly scheduled searches maintain CSV lookups consumed by the
  **SGB Use Cases** app (`sgb_usecases`):
  `sgb_indicators` (master), `sgb_domain_lookup`, `sgb_ip_lookup`
  (CIDR match), `sgb_url_lookup`, `sgb_feed_count_history`.

## Setup

1. Create the `sgb_ti` index (or change `index=` in the inputs and the
   `sgb_ti_index` macro).
2. Enable the 8 `sgb_taxii://SGB-*` inputs under
   *Settings → Data inputs*. First run performs a full pull
   (~470K indicators); subsequent runs are incremental (`added_after`).
3. Verify: `| inputlookup sgb_indicators | stats count by connectiontype`

## Event fields

`value`, `type` (domain/url/ip/ip6/ip6net), `connectiontype`
(PH/BC/AC/EK/MF/MM/MC/OT), `criticality_level`, `sgb_source`
(US/SB/SO/RS/IH), `confidence`, `category`, `created`, `modified`,
`stix_id`, `pattern`, `labels`.

## Maintenance

Deleted feed entries are not removed from lookups automatically (rare).
To fully reconcile: disable inputs, delete checkpoints under
`$SPLUNK_HOME/var/lib/splunk/modinputs/sgb_taxii/`, clean the index,
re-enable inputs.

Docs & source: https://github.com/bilsectr/sgb-api-bridge
License: MIT
