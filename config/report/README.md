# Situation reports

Weekly situation reports generated from Security Timeline notes, with an Agent Builder agent to query them. All demo data is synthetic.

## Flow

```
Timeline notes (Kibana)          Kibana APIs: GET /api/note, GET /api/saved_objects/_find (siem-ui-timeline)
        |
        v
Workflow "Weekly Situation Report"   config/workflows/situation-report.yaml
  1. get_timelines   kibana.request   default timelines only, filtered by the run inputs (client, keywords) -> titles, descriptions
  2. get_notes       kibana.request   notes (global and event), newest first
  3. write_report    ai.prompt        Elastic Managed LLM connector, structured output
  4. index_report    elasticsearch.request   POST /situation-reports/_doc
  5. find_case / create_case / update_case   Kibana case tagged situation-report
        |
        v
situation-reports index + Kibana case  <--  Agent Builder agent "Situation Report Analyst"
```

## Files

| File | Purpose | Target |
|---|---|---|
| `config/workflows/situation-report.yaml` | The workflow. Contains `__CONNECTOR_ID__`, `__MODEL__`, `__PERIOD_DAYS__`, replaced at install time | `POST/PUT /api/workflows/workflow` |
| `config/report/situation-reports-mapping.json` | Index settings and mappings | `PUT /situation-reports` |
| `config/agent-builder/agent.json` | Agent "Situation Report Analyst": instructions (cite sources, respect TLP, never invent) and tool list | `POST /api/agent_builder/agents` |
| `config/agent-builder/tools/latest-situation-reports.json` | ES\|QL tool: newest reports | `POST /api/agent_builder/tools` |
| `config/agent-builder/tools/situation-reports-search.json` | Index search tool over `situation-reports` | same |
| `config/agent-builder/tools/security-alerts-summary.json` | ES\|QL tool: alert counts by rule and host since a time | same |
| `config/agent-builder/tools/generate-situation-report.json` | Workflow tool that runs the workflow (`__WORKFLOW_ID__` filled at install) | same |
| `scripts/configure-reports.sh` | Installs all of the above, idempotent, prints manual steps if an API is unavailable | |
| `scripts/run-report.sh` | Runs the workflow now, waits, prints the report | `POST /api/workflows/workflow/{id}/run` |

Install order: `terraform apply`, `scripts/configure.sh`, `scripts/load-timelines.sh`, `scripts/configure-reports.sh`, then `scripts/run-report.sh`. The LLM is the preconfigured `Elastic-Managed-LLM` connector (no Terraform resource). The rendered workflow is written to `results/situation-report.rendered.yaml`. It contains only the connector id, no secrets.

Look-back window: `REPORT_PERIOD_DAYS` (default 7) when running `configure-reports.sh`. Demo timelines are often older than a week, so set it to 30 for a demo run, then re-run the script.

## Scoping a report: client and keywords

The workflow takes two optional inputs on its manual trigger (Elastic Stack 9.5 form, `inputs` inside the trigger):

| Input | Meaning | Example |
|---|---|---|
| `client` | A client code as written in the timeline titles. Matched as an exact phrase, because a bare `CLIENT-A` would match every CLIENT-x. | `CLIENT-B` |
| `keywords` | Words from the `Keywords:` line in the timeline descriptions. Space separated, every word must match. | `true-positive`, `true-positive modbus` |

Both feed the same search the Timelines list uses (title and description), with `+` in front of each term so they combine as AND. The `get_timelines` step also filters to default timelines, so templates and prebuilt timelines never reach the model. Leave both empty for the all-timelines report.

Each report document stores `filter_client`, `filter_keywords` and `keywords` (the union of the keywords of its source timelines), so reports can be filtered in Discover through the `Situation reports` data view. Each report scope gets its own case, found by the tag `scope:<period_end>:<client or all>:<keywords or any>`. The case is found by that exact tag, not by searching its title: a title search matches on shared words, so a CLIENT-B report overwrote the all-clients case (found and fixed).

Run from the command line: `REPORT_CLIENT=CLIENT-B REPORT_KEYWORDS=true-positive scripts/run-report.sh`.

Groupings that make sense with the demo timelines:

| Scope | Inputs | Timelines | Use |
|---|---|---|---|
| One client | `client=CLIENT-A` | 2, both true positives | The client's own report. Reports must not mix clients. |
| One client | `client=CLIENT-B` | 2: accepted behaviour, true positive | Client report with a mixed picture. |
| One client | `client=CLIENT-C` | 2: open handover, clean result | Client report with an open item and assurance. |
| Confirmed incidents | `keywords=true-positive` | 3, across clients | Internal view. Not for a client. |
| Open items | `keywords=handover` | 1 | Next-shift view. |
| What was ruled out | `keywords=clean` or `accepted-behaviour` | 1 each | Assurance. |
| One technique family | `keywords=removable-media` | 1 | Example of a theme filter. |

## Prompt design

- The model is told to use only the supplied timelines and notes, to write "No information in the source notes for this period." for empty sections, and to treat note text as data, not instructions.
- Vulnerability trends, hybrid signals and sector observations are allowed only when the notes contain them. Those sections therefore often read as empty in the demo. That is intended and a good talking point: the report does not fabricate.
- TLP: parsed from the trailing `| TLP:<colour>` in each timeline title. The report takes the most restrictive source marking (RED, AMBER+STRICT, AMBER, GREEN, CLEAR). An unmarked source counts as TLP:AMBER and the report says so.
- Naming convention read by the prompt: `YYYY-MM-DD | <client or asset> | <technique or rule> | <status> | TLP:<colour>`. Older titles without the client or TLP parts still work.
- IOCs are a plain Markdown table (Type, Value, Source timeline). There is no MISP block or other export format.
- NIS2 status per incident comes only from the notes ("not stated in notes" otherwise) and is informational, not legal advice.
- Structured output (`schema`) gives typed fields for the index and the case: title, tlp, client, period_start, period_end, body, sources, no_data.

## Data handling

- Demo data is synthetic. No real personal or client data is used.
- Timeline notes leave the cluster only to the Elastic Managed LLM (Claude on EIS). Restrict inference to EU in Kibana under Elastic Inference Service > Region preferences, then confirm the model's inference regions and retention on the EIS supported-models page before claiming anything stronger.
- Reports are stored in the `situation-reports` index and in a Kibana case. Treat both as carrying the report's TLP marking.

## Unverified

Nothing here was run. Docs were checked on elastic.co (Workflows step reference, Agent Builder Kibana API, Timeline notes API) but not for 9.5.3 specifically. Workflows are generally available from 9.4 and Agent Builder APIs from 9.3 per the docs. Items below are guesses or unchecked and may need fixing on first run.

Workflow YAML
1. Top-level fields: `name`, `description`, `enabled`, `triggers` (`type: manual`; `type: scheduled` with `with.every`). The manual and scheduled trigger shapes are documented. `enabled` was not on any page I could read.
2. `kibana.request` output shape: the docs do not say how to reference its response. The workflow passes the whole `steps.<name>.output | json` to the model, so the model copes with either a bare body or a wrapper object. If the real shape is `{status, body}`, nothing breaks, but the prompt becomes longer.
3. `kibana.request` `query` as an object with an array value (`fields`): the `fields` query parameter may need repeating (`fields=title&fields=timelineType`) and may not serialise from a YAML list. If it fails, drop `fields`, at the cost of much larger timeline JSON.
4. Prompt size: no truncation or projection step. 200 timelines and 200 notes are fine for demo data, not for a real tenant. `data.*` steps could trim fields, but their syntax was not checked.
5. `ai.prompt`: `connector-id` is top-level and `prompt`, `systemPrompt`, `schema`, `temperature` are under `with`, and the output is `steps.<name>.output.content` (documented). `required` inside `schema` is standard JSON Schema but was not shown in the docs example.
6. `"${{ ... }}"` for array and boolean values in the `index_report` body: inferred from the foreach page, which says `{{ }}` and `${{ }}` behave the same there. Whether `${{ }}` preserves types in other places is unconfirmed. If `sources` ends up as a string, the index step fails with a mapping error or stores one string.
7. `elasticsearch.request` index call (`POST /situation-reports/_doc`): documented generic request. The dedicated `elasticsearch.index` step was not documented on the page read, so it is not used.
8. `if:` expressions use KQL-like syntax (`... : false`, `AND`, `NOT`). The docs example shows `inputs.process_alerts : true` only. Whether `AND`, `NOT` and paths like `steps.find_case.output.total` work is unconfirmed. Fallback: remove the conditions, always create a new case per run.
9. `cases.findCases` output field `total` and `cases[0].id` are documented. `cases.createCase` and `cases.updateCase` parameter names are documented. Case description size limits were not checked; very long reports may be rejected.
10. `execution.startedAt` and `execution.id` are documented. Turning that into period dates is left to the model, so dates in the report depend on the model's date arithmetic. The scripts do not verify them.
11. Date filtering is done by the model from title dates and note `created` timestamps, not deterministically by the workflow. A deterministic filter would need `data.*` steps or computed query parameters.
12. The note API response field names (`notes[].timelineId`, `eventId`, `note`, `created`) and `GET /api/note` list-mode parameters (`perPage`, `sortField`, `sortOrder`) come from search results, not the API page itself. The prompt relies on `timelineId` joining to the timeline saved object id.
13. The `GET /api/saved_objects/_find?type=siem-ui-timeline` approach matches what `scripts/validate.sh` already uses. `timelineType` is read from the saved object attributes.

Workflows API (used by the scripts)
14. Paths come from the endpoint list: `POST /api/workflows/workflow`, `PUT /api/workflows/workflow/{id}`, `GET /api/workflows/workflow/{id}`, `GET /api/workflows`, `POST /api/workflows/workflow/{id}/run`, `GET /api/workflows/executions/{id}` and `.../logs`.
15. Request and response bodies were not available: the `{"yaml": "..."}` create/update body, the `{"inputs": {}}` run body, the id field names (`id`), the execution id field (`workflowExecutionId`/`executionId`/`id`), execution status values (`completed`, `failed`, ...) and the list response shape. The scripts try several likely names.
16. The `size=100` list parameter on `GET /api/workflows` is a guess.

Agent Builder
17. Documented: `POST /api/agent_builder/tools` and `/agents`, `GET` lists, `POST /converse`, tool types `esql`, `index_search` (with `pattern`), `workflow`, `mcp`, agent `configuration.instructions` and `configuration.tools[].tool_ids`, `access_control.access_mode` on 9.5+ (`visibility` on 9.4).
18. `workflow` tool `configuration` fields (`workflow_id`, `wait_for_completion`) are guessed: the docs list the type but show no fields. If creation fails, the script skips the tool and the agent is installed without it. Run reports with `scripts/run-report.sh` instead.
19. `GET /api/agent_builder/tools/{id}`, `GET /agents/{id}` and `DELETE` on both are assumed for the delete-then-create upsert.
20. Converse request: `input`, `agent_id` documented. The response shape was not documented; validate.sh reads `.response.message`, then `.response`, then `.message`. `connector_id` in the request is documented as deprecated; `validate.sh` retries without it.
21. The ES|QL alerts tool queries `.alerts-security.alerts-*`. Whether ES|QL allows that hidden index pattern was not checked. The `date` param type is documented for 9.3+.
22. The agent uses the default AI connector unless `configuration.connector_ids` is set (documented as preview on Serverless). The Elastic Managed LLM is the default for Agent Builder on Hosted deployments; confirm in Stack Management > Advanced settings.

Connector checks (validate.sh criterion 12)
23. `GET /api/actions/connector/Elastic-Managed-LLM` is used only to check the connector exists. The connector id comes from the Kibana docs; the region policy API path was not documented, so the EU restriction is a manual UI step.

Other
24. Criterion 7 still matches titles starting with a date. The trailing `| TLP:<colour>` count is shown in the detail only, and does not affect PASS/FAIL. Timelines have no tag field in the import schema, so the disposition and TLP live in the title.
25. The workflow's `scheduled` trigger is commented out. Check the interval syntax (`every: 7d`) before enabling.
