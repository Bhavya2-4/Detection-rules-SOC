# Detection Rules for SOC

Elastic detection rules I've written for specific threats, each with the behaviour it targets and the reasoning behind the logic.

| Rule | Threat | Platform | Telemetry |
|------|--------|----------|-----------|
| [OPTIMJACK third-party JavaScript supply chain (9 rules)](optimjack-third-party-javascript/) | Vendor-served JS skimmer, crypto clipper, iOS exploit delivery (Nov 2026) | Web / browser | Script inventory, vendor audit, IdP, CSP reports, browser runtime, proxy. ES\|QL, EQL and KQL. |
| [Apache ActiveMQ exploitation leading to LockBit](apache-activemq-cve-2023-46604-lockbit.md) | CVE-2023-46604 RCE, post-exploitation tooling, LockBit staging | Windows | Process events (`java.exe` child processes, certutil, AnyDesk) |
| [GRIDTIDE backdoor activity](gridtide-backdoor-activity.md) | Linux backdoor using systemd persistence and Google Sheets API for C2 | Linux | Process, file and network events |

## Conventions

- Queries use Elastic Common Schema (ECS) field names.
- Each behaviour is a separate query that a single event can match. Correlation across behaviours belongs in an EQL sequence or alert grouping, not in one large KQL expression.
- Before production use, tune the path and process exclusions against your own baseline.

## Related work

- [optimjack-detection-engineering](https://github.com/Bhavya2-4/optimjack-detection-engineering): detection-as-code project with ES|QL, EQL and KQL rules, synthetic test data, CI validation and a live Elasticsearch test job.
- [Threat-hunting-Reports](https://github.com/Bhavya2-4/Threat-hunting-Reports): the hunt reports several of these rules came from.
