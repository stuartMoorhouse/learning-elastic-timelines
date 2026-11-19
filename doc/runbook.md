# Demo runbook

For the person running the demo. The slides in `lessons/` are for the audience and contain no click steps, prep or fallbacks. All data is synthetic.

Audience framing: an MDR/SOC and threat-hunting provider (signals not alert volume, discretion, client handovers). Use this to colour what you say, not what is on the slides.

## Preparation

1. Run `scripts/inject-ot-telemetry.sh` shortly before the demo. It rebuilds the OT telemetry with times relative to now, so the story is always from the last few hours.
2. Run `scripts/load-timelines.sh` (templates and the six hunts). The hunt titles start with the date it ran.
3. Run `REPORT_PERIOD_DAYS=30 scripts/configure-reports.sh`. Without the variable the look-back is 7 days.
4. Pre-run reports with `scripts/run-report.sh`. Run any scoped examples first, and run the unfiltered one last (no `REPORT_CLIENT` or `REPORT_KEYWORDS`), because the agent's "latest reports" tool returns the newest report. If a scoped report is the newest, lesson 8's answers will cover only that scope.
5. Run `scripts/demo-check.sh`. It should end with 0 failed.
6. Confirm EIS Region preferences restrict inference to the EU (manual step in Kibana).
7. Optional, for the lesson 6 alert step only: run `scripts/attack.sh` so a few alerts exist. The OT telemetry itself raises no alerts.
8. If a Timeline column shows as unknown, refresh the fields of the `security-solution-default` data view (it must cover `logs-*`).
9. Cases created by the workflow are Security cases. Open them under Security > Cases, not Observability or Stack Management.

## Keeping the demo simple

Timelines look complicated when the presenter shows every option. Show one path and name the rest once.

- Use the query builder only. The detection logic sits there and the KQL bar is empty. Mention the ES|QL and Correlation (EQL) tabs in one sentence. The Modbus timeline has an EQL sequence saved in its Correlation tab, open it only if asked.
- Say once, while building a query: side by side means AND, stacked means OR.
- Save the Timeline before adding notes, and say why: notes need a saved Timeline. Save before leaving the page.
- Start every live Timeline from a template, never a blank one.
- The timelines already have a fixed date range. If a query is slow, use the saved hunt and describe the query.
- Do not apologise for the interface or call anything tricky. State what to do and do it.

## Demo data

The telemetry is invented but shaped like real Elastic integrations, with ECS fields (`scripts/check_ot_ecs.py` checks this). It sits in data streams named `logs-<dataset>-ot`: Zeek Modbus and connection logs, Windows Security events, Elastic Defend process, network and file events, and a PAN-OS firewall. `labels.bus_type` (on the two USB processes) is a custom field. Elastic Defend does not write it itself, so do not present it as Defend output.

The six hunts, as they appear in Security > Timelines (titles start with the load date):

| Hunt | Client | Status | TLP | Source | Events | Pins |
|---|---|---|---|---|---|---|
| unauthorised Modbus writes to line 2 controller (T0836) | CLIENT-A | Closed - True Positive | AMBER | Zeek Modbus | 6 | 3 |
| remote desktop logons to the HMI from the IT network (T0886) | CLIENT-A | Closed - True Positive | AMBER | Windows Security | 6 | 3 |
| unknown device scanning OT controllers (T0846) | CLIENT-C | Open - Handover | AMBER | Zeek connection | 72 | 3 |
| engineering software sessions to a controller (T0843, T0858) | CLIENT-B | Closed - Accepted Behaviour | GREEN | Elastic Defend network | 3 | 0 |
| executables run from removable media on the engineering workstation (T0847) | CLIENT-B | Closed - True Positive | AMBER | Elastic Defend process | 2 | 3 |
| C2 egress from the OT zone (T0885) | CLIENT-C | Closed - Clean, no adversary activity found | AMBER | PAN-OS firewall | 18 | 0 |

The five templates:

- `TEMPLATE | Hunt | Controller writes outside the allowlist (T0836) | {destination.ip} | TLP:AMBER`
- `TEMPLATE | Hunt | Remote access to an OT host (T0886) | {host.name} | TLP:AMBER`
- `TEMPLATE | Hunt | Scan of OT controllers (T0846) | TLP:AMBER`
- `TEMPLATE | Hunt | Removable media on an engineering workstation (T0847) | {host.name} | TLP:AMBER`
- `TEMPLATE | OT alert | {host.name} | {kibana.alert.rule.name}`

| Item | Source |
|---|---|
| Six hunts, five templates | `config/timelines/ot-hunts.ndjson`, `ot-templates.ndjson` |
| OT telemetry generator and loader | `scripts/ot_telemetry.py`, `scripts/inject-ot-telemetry.sh` |
| Weekly Situation Report workflow | `config/workflows/situation-report.yaml` |
| Situation Report Analyst agent | `config/agent-builder/agent.json` |
| Situation reports data view | created by `scripts/create-report-data-view.sh` |

Client codes CLIENT-A, CLIENT-B, CLIENT-C are invented.

## Open items

- Not verified in the Kibana UI: how the saved timelines render (providers, columns, pins), the exact labels of the pivot and disable actions, and whether the CIDR value `10.0.0.0/8` in the C2 egress hunt matches as an IP range. Open each timeline you plan to show before the demo.
- `scripts/demo-check.sh` covers the data, the timelines and the report pipeline, not the UI.

## Lesson 1: The problem (5 min)

Open Security > Timelines
Say: "Everything on screen is synthetic"
Show the Timelines list with the six OT hunts. Do not open any
Say: "Imagine each of these as a chat thread and a document instead. Now imagine finding one in six weeks"
Notice: the list is already a shared, searchable history

Notes:
- No live clicking beyond the list.
- If asked about MISP: no MISP instance is part of this demo; the report carries a plain IOC table.
- Slides: problem slide (four unanswered questions), Timeline definition slide, roadmap slide.

## Lesson 2: Timeline basics (7 min)

Open the Removable media hunt template (T0847): `TEMPLATE | Hunt | Removable media on an engineering workstation (T0847) | {host.name} | TLP:AMBER`
Create a Timeline from it and set host.name to ot-eng-ws-01
Run the query: two processes launched from a USB drive (autorun.exe, update.exe)
Pivot to the parent, then to the child (see "How to pivot" below)
Save the Timeline (notes need a saved Timeline)
State the hypothesis in one line in the Notes tab
Notice: no alert drives this hunt, and the query is saved with it

How to pivot (say: "A pivot is a follow-up question built from a value I just found"):
1. Parent. In the results, find update.exe. Its Parent column (process.parent.name) says autorun.exe. Expand the query builder, click + Add field, choose process.name, enter autorun.exe, and drop it on a new row below the existing one (stacked rows are OR, side by side is AND). Temporarily disable the first row so only the new question shows (click the pill and choose Temporarily disable). Result: autorun.exe's own start event. Its parent is explorer.exe: a person launched it by hand from the USB drive.
2. Child. Change the new row to process.parent.name = update.exe. Result: svchost32.exe starting from C:\Users\Public, unsigned. This is what the USB executable started next.
3. Same process. Change the row to process.name = update.exe. Result: its own start and the file it created, C:\Users\Public\svchost32.exe.
4. Re-enable the first row. Delete the pivot row before saving unless you want it kept in the record.

Notes:
- Prep: `scripts/inject-ot-telemetry.sh` and `scripts/load-timelines.sh` done.
- Pivot meaning: moving from one thing you found to the events around it. It answers "who started this", "what did it start" and "what else did it do". Each step is a new query built from a value already on screen.
- The template's columns include process.parent.name, so the parent is visible in the results.
- Real Elastic Defend data also carries process.entity_id and process.parent.entity_id. Pivot on those when you can, because process names repeat. The demo data links processes by name only.
- Verified in the data: the three pivots return autorun.exe (parent explorer.exe), svchost32.exe (parent update.exe), and update.exe plus its file creation. Not verified in the Kibana UI: the exact labels of the drag and disable actions. The docs say fields can be dragged or sent into the query builder, and that a filter can be temporarily disabled.
- Risk: if the drag does not work, use + Add field in the query builder.
- Fallback: open the saved hunt `<date> | CLIENT-B | Hunt: executables run from removable media on the engineering workstation (T0847) | Closed - True Positive | TLP:AMBER` and describe the pivots from its pinned events.
- Slides: annotated screenshot of the Timeline layout, "Four things to know before you start" (query builder first, AND/OR layout, save early, start from a template), run-the-hunt screenshot, a pivot diagram (process, its parent, its child), saved Timeline.

## Lesson 3: Pinning and IOCs (8 min)

Open the worked example: `<date> | CLIENT-A | Hunt: unauthorised Modbus writes to line 2 controller (T0836) | Closed - True Positive | TLP:AMBER`
Query tab: show the saved query (Modbus write functions, from sources that are not the two authorised writers) and the chosen columns
Pinned tab: walk the three pins top to bottom (first write request, WRITE_MULTIPLE_REGISTERS, WRITE_SINGLE_COIL)
Open one pinned event's note and read the IOC line (source.ip 10.50.2.30, with the reason)
Live: in the Query tab, pin one more of the six events (pin icon) and add an event note with the same IOC and a reason
Return to the Pinned tab and show the new event in the set
Notice: pins hold the evidence, notes hold the reasoning and the IOC, technique IDs make the record searchable

Notes:
- The story: the historian (ot-hist-01, 10.50.2.30), which only ever reads, sends six Modbus write requests to the line 2 controller (plc-line2-01, 10.50.3.11) over about seven minutes. Pins: the first write, a WRITE_MULTIPLE_REGISTERS, a WRITE_SINGLE_COIL.
- The Zeek Modbus log records the function but not register addresses or values. Say so if asked what was changed: the note tells the plant owner to check the controller or a packet capture.
- The Correlation tab has an EQL sequence (a read followed by a write from the same source to the same controller). Show it only if asked.
- A second pinned chain, if time allows: the removable-media hunt pins `autorun.exe` starting from the USB drive, the file drop `C:\Users\Public\svchost32.exe`, and the `svchost32.exe` start. The RDP and unknown device hunts also have three pins each.
- Pins are fixed event ids, so no alerts or attack run are needed. If the Pinned tab is empty, re-run `scripts/inject-ot-telemetry.sh` then `scripts/load-timelines.sh`.
- A note added from an event is attached to the event and, by default, to the Timeline. Leave "Attach to current Timeline" ticked so the note shows in the Notes tab.
- A pin points at an event, it does not copy fields. The IOC is captured by writing it in the note.
- Slides: the six writes in order, Pinned tab screenshot with a note open.

## Lesson 4: Structured notes (7 min)

Open the clean negative-result hunt: `<date> | CLIENT-C | Hunt: C2 egress from the OT zone (T0885) | Closed - Clean, no adversary activity found | TLP:AMBER`
Open the Notes tab and scroll the global note section by section
Stop at Findings and Scope. Say: "The result is explained, and the scope and gaps are recorded, so nobody repeats this hunt blindly"
Show the NIS2 block (Reportable? No, n/a clocks) and the last two lines (Keywords:, Report-ready summary:)
Live: on the removable-media Timeline from lesson 2, paste the note skeleton into a global note and fill Hypothesis and one Query line
Notice: a negative result is a valid record, and every note ends with one summary line

Notes:
- The hunt returns 18 events: hourly NTP from the time server and half-hourly historian replication to a vendor cloud, each matching a named firewall rule (OT-DMZ-NTP-OUT, OT-DMZ-HIST-REPL). The clean finding is that nothing else leaves the zone. The gap is that the only visibility is the firewall, with no DNS or proxy logs.
- Do not read the whole note aloud; scroll and pause on three sections.
- NIS2 reporting stages (24 h early warning, 72 h notification, one month final report) and TLP are shown as examples of use, not compliance claims.
- Slides: list of note sections (the contract), screenshot of the clean hunt note.

## Lesson 5: Naming and handovers (10 min)

In the Timelines list, search `Handover` (one result: the unknown device scan)
Open `<date> | CLIENT-C | Hunt: unknown device scanning OT controllers (T0846) | Open - Handover | TLP:AMBER`
Read the Handover section as if starting the next shift
Search `Accepted Behaviour` and open the engineering software sessions hunt (T0843, T0858)
Read Findings and Handover: the change record match and the proposed exception
Search `Clean` and open the C2 egress hunt (T0885)
Read the Scope line and the gap in the Handover section
Search `true-positive` (three results) to show the Keywords line is searchable, then `TLP:AMBER` to show the list narrowing
Live: rename the Timeline saved in lesson 2 to follow the convention, with status Open - Handover
Notice: the next analyst can start from the record, and search works as well as the titles do

Notes:
- Longest lesson. If short on time, skip the `TLP:AMBER` search.
- The keyword search in this lesson is the same search the workflow uses in lesson 7.
- Slides: convention broken into labelled parts, search terms and results, handover screenshot.

## Lesson 6: Templates (7 min)

Security > Timelines > Templates: show the five templates (four hunt templates and one alert template)
Alert-free: open the Remote access to an OT host hunt template (T0886) and create a Timeline
Set host.name to ot-hmi-01
Show the query: RDP logons that do not come from the jump host (six events)
Point at the empty hypothesis placeholder in the note
Alert-driven: Security > Alerts, pick an alert and open it in a Timeline using the OT alert template
Show host.name and user.name filled in from the alert, and the note skeleton ready
Notice: same note headings, different starting point

Notes:
- Templates: one alert template (`TEMPLATE | OT alert | {host.name} | {kibana.alert.rule.name}`) and four hunt templates: Controller writes outside the allowlist (T0836), Remote access to an OT host (T0886), Scan of OT controllers (T0846), Removable media on an engineering workstation (T0847).
- Risk: the OT telemetry raises no alerts. The alert step uses an alert from the VM attack run (`scripts/attack.sh`). If there are none, show the alert template and describe how it fills in.
- When a template becomes a Timeline, providers with a placeholder (for example `host.name: {host.name}`) are disabled until you give them a value. Set host.name first, then run the query.
- Slides: five templates grouped as alert and alert-free, before/after of a blank vs templated note.

## Lesson 7: Workflow (8 min)

Open the Weekly Situation Report Workflow in Kibana
Show the steps, not the whole prompt: get_timelines, get_notes, write_report
Run it (manual trigger). In the Run modal set client to CLIENT-B and keywords to true-positive, then watch the execution steps complete
Open the result: the report covers one timeline only (the removable-media hunt). Say: "Same search as the Timelines list, so the keywords we typed in the descriptions now pick what goes into a report"
Open the Situation reports data view in Discover and filter `keywords : "removable-media"` or `filter_client : "CLIENT-B"` to show reports filtered the same way
In Security > Cases, filter by the tag `scope:...` to see one case per report scope
Walk the report: TLP line, executive summary, incidents, IOC table, NIS2 status, sources
Point at the sections that read "No information in the source notes for this period". Say: "It does not invent content"
Trace one IOC in the report back to the event note from lesson 3
Notice: every claim traces to a source timeline, and the Report-ready summary lines are the backbone

Notes:
- Report first line is `**TLP:AMBER**` (the most restrictive source; an unmarked source counts as TLP:AMBER).
- Stages: fetch timelines (filtered by the run inputs) and notes, LLM writes the report, index into `situation-reports`, create or update a case tagged `situation-report` and `scope:<date>:<client or all>:<keywords or any>`.
- Run inputs: `client` (a code from the titles, e.g. CLIENT-B) and `keywords` (words from the Keywords line, all must match, e.g. `true-positive modbus`). Both optional. Filtering is done by the Timelines list search before the model sees the notes, so it is not left to the model.
- Useful scopes in the demo data: each client on its own (CLIENT-A two true positives; CLIENT-B an accepted behaviour and a true positive; CLIENT-C an open handover and a clean result), `true-positive` across clients (internal view, three incidents), `handover` (open items for the next shift), `clean` or `accepted-behaviour` (what was ruled out). `ics` is on five of six timelines and `hunt` on all six, so neither narrows anything.
- From the command line: `REPORT_CLIENT=CLIENT-B REPORT_KEYWORDS=true-positive scripts/run-report.sh`.
- Runs checked on 9.5.3: client plus keywords (CLIENT-B and true-positive), keywords only (handover) and client only (CLIENT-A). The all-clients scope has not been run with the current workflow.
- Cases are found by their scope tag, not by title, so a scoped report does not overwrite another scope's case.
- LLM is the Elastic Managed LLM connector (Claude on the Elastic Inference Service), inference restricted to the EU.
- Prep: `REPORT_PERIOD_DAYS=30`; pre-run `scripts/run-report.sh` once, with the unfiltered run last. The LLM call can take time; use the pre-run result if it stalls.
- Data handling statement: notes go only to the Elastic Managed LLM, region preferences restricted to EU. Confirm the model's regions and retention on the EIS supported-models page before making stronger client claims.
- Slides: flow diagram (notes, Workflow, LLM, index, case), report screenshot with TLP header and IOC table highlighted.

## Lesson 8: Agent Builder and wrap-up (8 min: 3 agent, 5 wrap-up and Q&A)

Open the Situation Report Analyst agent
Ask: "What incidents were open at the end of the week, and who needs to pick them up?" (expect the unknown device scan, CLIENT-C)
Check the answer starts with the TLP and cites the source timelines
Ask: "Which indicators were found, and where?" and check it matches the IOC table
Ask: "Was anything reportable under NIS2?" and check it answers only from the notes
Optional: ask "Which detection rules fired the most?" (alert summary tool)
Optional: ask the agent to generate a fresh report and read it back
Notice: every answer names its sources, and "not stated in notes" when the notes are silent

Notes:
- Agent tools: latest reports, search over reports, alert summary, and a tool that runs the Workflow.
- The agent answers from the newest report. If the newest one is a scoped report, answers cover only that scope. Run the unfiltered report last before the demo.
- The alert summary tool counts alerts in the security alerts index. Those alerts come from the VM attack run (if you ran it), not from the OT scenarios, so do not present them as part of the OT story.
- Q&A to expect: where notes are sent (EU-restricted managed LLM); what if the notes are wrong (human review, the report cites sources); scheduled reports (yes, enable the scheduled trigger after the flow is proven); MISP (not built, plain IOC table).
- Reminder: a reviewer approves reports before they reach the client.
- After the demo: run `terraform destroy` to remove all resources.
- Slides: agent Q&A screenshot, summary slide (three lines), closing slide with next steps.
