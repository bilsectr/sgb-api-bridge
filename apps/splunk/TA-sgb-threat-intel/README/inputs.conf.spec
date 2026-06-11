[sgb_taxii://<name>]
discovery_url = <value>
* TAXII 2.1 discovery endpoint URL.
* Default: https://sgb-taxii.bilsec.tr/taxii2/
* Self-hosted deployments: point this at your own TAXII base, e.g.
  http://sgb-taxii.example.local/taxii2/

api_root = <value>
* Optional. Full API root URL. When omitted, the API root is resolved
  from the discovery document ("default" entry).

collection = <value>
* Required. TAXII collection alias to poll, one of:
  sgb-phishing, sgb-botnet-cc, sgb-apt-cc, sgb-exploit-kit,
  sgb-malware-download, sgb-mining, sgb-mobile-cc, sgb-other, sgb-all

page_limit = <value>
* Optional. Objects requested per page. Default: 5000.
