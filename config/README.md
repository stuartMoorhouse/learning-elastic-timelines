# config/

Elastic solution-layer content for the Timelines demo, framed for an MDR/SOC and threat-hunting provider (Cparta-style: signals not alert volume, discretion, critical-infrastructure clients). Target stack: Elastic 9.5.3. The Fleet agent policy and Elastic Defend integration are defined in Terraform, not here.

All timeline content is synthetic. Client codes (CLIENT-A, CLIENT-B, CLIENT-C) are invented. The hunts run on invented OT telemetry that is shaped like real Elastic integrations and uses ECS fields: Zeek on an OT network sensor (Modbus and connection logs), Windows Security events, Elastic Defend, and a PAN-OS firewall. It is injected by `scripts/inject-ot-telemetry.sh` into data streams `logs-<dataset>-ot`. The demo VM and its attack run are not part of the timeline story.

Uncertainty flags (read before deploy):
- The Timeline NDJSON schema was written from knowledge of recent Kibana versions. Import was tested against the 9.5.3 stack (providers, including is one of and is not one of, plus pins and notes, are stored), but the timelines have not all been opened in the UI.
- The OT telemetry is invented. Fields are ECS where ECS has one. The rest are custom fields modelled the way the ECS custom-fields guidance recommends: nested under a proper name (`zeek.*`, `winlog.*`, as the real integrations do) or under ECS's own `labels` field (`labels.bus_type` and `labels.dos_name` on processes launched from a USB device, an enrichment that Elastic Defend does not write itself). `scripts/check_ot_ecs.py` checks the generated data against the official ECS field list. Zeek's Modbus log holds the function name only, so notes make no claim about register addresses or values.
- If columns do not resolve in the Timeline, refresh the fields of the `security-solution-default` data view (it must cover `logs-*`).

## Files

| File | Purpose | Target API |
|---|---|---|
| `apt29-rules.json` | Prebuilt detection rules (by name, with MITRE technique) to enable for the chain. Entries with `verify: true` are uncertain; `alternates` lists fallback names. | `GET /api/detection_engine/rules/_find` then `POST /api/detection_engine/rules/_bulk_action` (enable) |
| `apt29-atomics.json` | Ordered Atomic Red Team tests the chain runs, with the expected rule per test. Mirrors `scripts/vm/Invoke-APT29.ps1`. | none (read by the VM script) |
| `timelines/ot-hunts.ndjson` | Six OT hunts. The detection logic is in the query builder (data providers, using AND chains, is one of and is not one of); the KQL bar and the filter bar are empty. Three closed true positives (unauthorised Modbus writes, RDP to the HMI from the IT network, USB-launched executables), one open handover (unknown device scanning controllers), one accepted behaviour (engineering software sessions to a controller in a change window), one clean negative result (C2 egress from the OT zone). Pins and event notes on four of them. | `POST /api/timeline/_import` |
| `timelines/ot-templates.ndjson` | Five templates: four alert-free OT hunt templates (writes outside the allowlist, remote access, controller scan, removable media), each with a `{destination.ip}` or `{host.name}` placeholder provider where it makes sense (the scan template has none) and the logic chained to it, and one alert-driven OT template. | `POST /api/timeline/_import` |
| `../scripts/ot_telemetry.py` | Generator for the invented OT telemetry as ECS bulk NDJSON (one function per scenario, fixed `_id`s so timelines can pin events). `../scripts/check_ot_ecs.py` validates its fields against ECS. | none (called by `inject-ot-telemetry.sh`) |
| `workflows/`, `agent-builder/`, `report/` | Weekly situation-report Workflow (`workflows/situation-report.yaml`) and Agent Builder agent (`agent-builder/`), built separately. They read the timeline notes via the Kibana notes API. | Kibana Workflows / Agent Builder APIs |

Each NDJSON file has one timeline per line. Import uses multipart form field `file`, with header `kbn-xsrf: true`.

## Naming convention

`YYYY-MM-DD | <client-or-env> | <hunt or technique> | <status> | TLP:<colour>`

Example: `2026-10-28 | CLIENT-B | Hunt: C2 beaconing and ingress tool transfer (T1071.001, T1105) | Closed - Clean, no adversary activity found | TLP:AMBER`

Status values: `Open - Handover`, `Escalated - Handover`, `Closed - True Positive`, `Closed - Accepted Behaviour`, `Closed - Clean, no adversary activity found`. TLP values: `TLP:CLEAR`, `TLP:GREEN`, `TLP:AMBER`, `TLP:RED`. Templates start with `TEMPLATE |`.

Timelines have no tag field in the import schema, so keywords live in the description as a final `Keywords: a, b, c` list (for example `hunt`, `accepted-behaviour`, `true-positive`, `handover`, `negative-result`) and the status and TLP live in the title. The Timelines list search finds both.

## Note structure (consumed by the situation-report workflow)

Every default timeline has one global note with these sections, in this order: TLP and client line, Hypothesis, Scope and data, Queries run, Findings, Incident handling (NIST SP 800-61 phases: Detect, Analyse, Contain, Eradicate, Recover), NIS2 reporting (an example of use, not a compliance claim: `Reportable?`, `Clock started at:`, early warning 24h, notification 72h, final report 1 month), Handover, then `Keywords:` and `Report-ready summary:`.

Contract for the report workflow: each timeline's global note contains exactly one line starting `Report-ready summary:`. It is one sentence: what was hunted, where, outcome, TLP. The report can take these lines directly and use the rest of the note for detail.

## Placeholder contract (for `scripts/load-timelines.sh`)

| Token | Meaning | How resolved |
|---|---|---|
| `__RUN_DATE__` | Date of the demo run, `YYYY-MM-DD` | `date -u +%F`, or `RUN_DATE` |

The OT timelines pin events by fixed `_id` (`ot-s1-w1` and so on), so no alert ids are needed. Context tokens are substituted before the idempotency check, so re-running does not duplicate.

The timelines use a 2026-10-01 to 2026-12-31 date range. The telemetry is stamped relative to the last run of `scripts/inject-ot-telemetry.sh`, so run it shortly before the demo.

## Detection logic (what each timeline finds, in the query builder)

| Hunt | Query builder (data providers) | Source | Events |
|---|---|---|---|
| Modbus writes (T0836) | `zeek.modbus.function` is one of WRITE_SINGLE_COIL, WRITE_SINGLE_REGISTER, WRITE_MULTIPLE_COILS, WRITE_MULTIPLE_REGISTERS AND `source.ip` is not one of 10.50.1.20, 10.50.2.10 | Zeek modbus | 6 |
| RDP to the HMI (T0886) | `winlog.logon.type` is RemoteInteractive AND `event.code` is one of 4624, 4625 AND `source.ip` is not 10.50.0.5 | Windows Security | 6 |
| Controller scan (T0846) | `destination.port` is one of 502, 102, 44818 AND `source.ip` is not one of 10.50.1.20, 10.50.2.10, 10.50.2.30 | Zeek connection | 72 |
| Engineering software sessions (T0843, T0858) | `process.name` is Siemens.Automation.Portal.exe AND `destination.port` is 102 | Elastic Defend network | 3 |
| USB-launched executables (T0847) | `labels.bus_type` is usb (pivot from the results to the dropped binary and its children) | Elastic Defend process | 2 |
| C2 egress (T0885) | `network.direction` is outbound AND `destination.ip` is not 10.0.0.0/8 | PAN-OS firewall | 18 |

## Loading order

1. `scripts/inject-ot-telemetry.sh` (creates the `logs-*-ot` data streams: zeek.modbus, zeek.connection, system.security, endpoint.events.process, .network and .file, and panw.panos).
2. `scripts/load-timelines.sh` imports `ot-templates.ndjson` and `ot-hunts.ndjson`. If the import returns schema errors on 9.5.3, export a timeline from the Kibana UI, diff its fields against these files, and adjust the files rather than the loader.

## Demo talk-track (60 minutes)

Before the session: run `scripts/inject-ot-telemetry.sh`, then `scripts/load-timelines.sh`. Have a TLP and standards note ready (see Standards and handling).

1. **Framing (0-5 min).** Signals, not alert volume. Hunts are hypotheses, and their value is in the record: what was asked, what was found, what was ruled out. Notes in chat and documents are lost at handover.
2. **Hypothesis and hunt (5-15 min).** Open the controller-writes hunt template, set `destination.ip` to the controller, and state the hypothesis in the note. Run the query and show the Modbus writes from hosts outside the allowlist. Switch to the remote access template for the RDP logons (failures then a success, source not the jump host). Point out there is no alert driving either hunt.
3. **Pin and investigate (15-30 min).** Open the Modbus writes investigation. Show the Pinned tab: the setpoint change, the zeroed alarm threshold, the coil write, each with an event note and IOC. Show the global note: hypothesis, queries, findings, NIST phases, TLP. Show the query builder and how the investigation steps are written down as they happen, not afterwards.
4. **Handover and searchable history (30-40 min).** Show the naming convention. Search the Timelines list for `Handover`, `Accepted Behaviour`, `TLP:AMBER`, `Clean`. Open the clean negative-result hunt (C2 egress): events are returned, but each is explained as a scheduled, documented flow, and the scope and gaps are recorded so the clean result can be defended. Open the accepted-behaviour hunt (engineering software sessions) and show how it justifies an exception. Open the open handover (unknown device scanning controllers) as the next-shift starting point.
5. **Templating (40-47 min).** Show the four OT hunt templates and the OT alert template. Apply a hunt template to a new sensor or host, and apply the alert template to a fresh alert. Show the provider pre-filled and the note skeleton (hypothesis, NIST phases, NIS2 fields, report-ready summary) ready to complete.
6. **From notes to weekly situation report (47-55 min).** Trigger the Workflow (`config/workflows/situation-report.yaml`) that pulls the timeline notes through the Kibana notes API and drafts the weekly situation report from the `Report-ready summary:` lines and detail. Ask the Agent Builder agent (`config/agent-builder/`) about the week. Show that the summary lines and TLP markings carry through. Reviewer approves before it goes to the client.
7. **Standards, handling and Q&A (55-60 min).** See below.

## Standards and handling

- MITRE ATT&CK: technique IDs in titles, queries and notes (ATT&CK for ICS: T0836, T0886, T0846, T0858, T0843, T0847, T0885).
- TLP (FIRST Traffic Light Protocol): every timeline and report carries a TLP marking, in the title and the first line of the note.
- NIST SP 800-61: notes follow Detect, Analyse, Contain, Eradicate, Recover.
- NIS2 reporting: the note has fields for reportability and the reporting clock (early warning 24h, notification 72h, final report 1 month). This shows how a timeline can hold the evidence for those decisions. It is an example of use, not a compliance claim; the client decides reportability.
- Data: everything shown is synthetic. State this on screen.
- LLM: the situation-report step sends timeline notes to an LLM. State which connector and region processes the notes; Elastic Managed LLM (Claude on the Elastic Inference Service) is used, with inference restricted to EU through Region preferences. Confirm the model's inference regions and retention on the EIS supported-models page before making claims to a client.
