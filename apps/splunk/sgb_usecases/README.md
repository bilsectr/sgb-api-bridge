# SGB Use Cases for Splunk

24 ready-to-enable detection searches and 3 dashboards for the SGB
(Siber Güvenlik Başkanlığı, formerly USOM) threat feed. Mirrors the
vendor-neutral SGB SIEM use case library (UC-PH/BC/AC/EK/MF/MM/MC/OT/XX)
one-to-one, including MITRE ATT&CK and BG Rehberi annotations.
Community project — **not affiliated with SGB**.

**Requires:** [TA-sgb-threat-intel](../TA-sgb-threat-intel/) (provides
the TAXII input and the `sgb_*` lookups).

## Setup

1. Install and configure TA-sgb-threat-intel first.
2. Create the `sgb_summary` index (alert outputs; meta rules and
   dashboards read from it).
3. Point the data source macros at your environment
   (*Settings → Advanced search → Search macros*): `sgb_dns_index`,
   `sgb_proxy_index`, `sgb_firewall_index`, `sgb_netflow_index`,
   `sgb_edr_index`, `sgb_mail_index`, `sgb_ids_index`, `sgb_vpn_index`,
   `sgb_auth_index`, `sgb_waf_index`, `sgb_mdm_index`, …
4. Enable searches by tier (all ship disabled):
   - **Tier 1:** UC-XX-004 (A+B), UC-PH-001/002/003, UC-BC-001/002, UC-AC-001/002
   - **Tier 2:** UC-BC-003/004, UC-MF-*, UC-MC-*, UC-XX-001/002/005/006
   - **Tier 3:** UC-EK-*, UC-MM-*, UC-OT-001, UC-XX-003

## Dashboards

- **SGB - Genel Bakış** — feed totals, 24h match trend, top assets
- **SGB - Use Case Aktivitesi** — per-UC breakdown with CT filter
- **SGB - Feed Sağlığı** — ingest lag, count history, drop detection
  (operational rule UC-XX-004 visualized)

## Enterprise Security

Correlation-search annotations (MITRE ATT&CK, BG Rehberi) are included
and surface in the ES Use Case Library. Enable `action.notable` per
search if you want notables; default delivery uses a summary index so
the app also works without ES.

Canonical use case definitions, FP notes and response playbooks:
https://github.com/bilsectr/sgb-api-bridge/tree/main/docs/usecases
License: MIT
