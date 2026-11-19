# OPTIMJACK: third-party JavaScript supply-chain detections

Nine Elastic Security rules for the November 2026 Optimizely Web Experimentation compromise. An attacker abused a signup-flow flaw to edit customers' Project JavaScript, and the vendor's CDN then served a card skimmer, crypto-address swapper and iOS exploit-kit loader to visitors of 178+ organisations.

These files are copies. The source of truth, with the attack analysis, telemetry design, synthetic test data and CI, is **[optimjack-detection-engineering](https://github.com/Bhavya2-4/optimjack-detection-engineering)**. Rules are validated there with Kibana's ES|QL parser, Elastic's EQL and KQL libraries, 11 test scenarios and mutation testing.

| File | Detection | Type | Severity | Telemetry |
|------|-----------|------|----------|-----------|
| [det01_unapproved_third_party_script_content.toml](det01_unapproved_third_party_script_content.toml) | Served vendor script changed to an unapproved hash, scored by what it added | ES\|QL | medium | Script inventory |
| [det02_projectjs_change_without_idp_session.toml](det02_projectjs_change_without_idp_session.toml) | Vendor config edited by an employee with no corporate IdP sign-in | ES\|QL | high | Vendor audit + IdP |
| [det02_projectjs_change_outside_change_window.toml](det02_projectjs_change_outside_change_window.toml) | Vendor config edited outside an approved change window | ES\|QL | medium | Vendor audit + change calendar |
| [det03_eval_after_blocked_script_load.toml](det03_eval_after_blocked_script_load.toml) | Blocked external load, then large eval from the same script within 30 s | EQL | high | Browser runtime |
| [det03_new_eval_sample_from_vendor_script.toml](det03_new_eval_sample_from_vendor_script.toml) | Never-seen eval sample on a sensitive page (CSP Report-Only as a sensor) | New terms (KQL) | medium | CSP reports |
| [det04_csp_reports_unapproved_destination.toml](det04_csp_reports_unapproved_destination.toml) | Visitors' browsers reaching unapproved hosts across pages | ES\|QL | high | CSP reports |
| [det04_proxy_browser_post_unapproved_destination.toml](det04_proxy_browser_post_unapproved_destination.toml) | Employee browsers POSTing from our site to unapproved hosts | ES\|QL | medium | Proxy |
| [det05_hidden_iframe_unapproved_origin.toml](det05_hidden_iframe_unapproved_origin.toml) | Hidden iframe from an unapproved origin (iOS exploit delivery) | KQL | high | DOM monitor |
| [det05_third_party_script_alters_sensitive_value.toml](det05_third_party_script_alters_sensitive_value.toml) | Third-party script rewrites a wallet-address or payment field | EQL | critical | DOM monitor |

**Requirements:** Elastic 9.2+ (ES|QL `LOOKUP JOIN`). None of these rules runs on EDR or Windows event logs alone. Each file's `setup` field states its data dependency.
