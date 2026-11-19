# Lesson 7: Workflow: from notes to situation report

Time: 8 minutes. Theme: the value of a Workflow in collating notes.

## Learning objective

Explain how a Workflow turns structured Timeline notes into a TLP-marked weekly report.

## Tell: the concept

- Writing a periodic report by hand means opening every Timeline and copying notes. That is the manual documentation bottleneck.
- Because notes are structured and named consistently, a **Workflow** can do the collation. The Weekly Situation Report Workflow has four stages:
  1. Fetch Timelines and their notes through the Kibana APIs.
  2. Ask an LLM to write the report from those notes only.
  3. Index the report into Elasticsearch.
  4. Create or update a Kibana case.
- Guardrails:
  - Only what is in the notes. Empty sections say so.
  - The report TLP is the most restrictive TLP among its sources.
  - Note text is treated as data, not instructions.
  - A human reviews the report before it is shared.

## Show: what to look for

- The report starts with its TLP marking.
- Each incident names its source Timeline.
- The IOC table traces back to event notes.
- Empty sections read "No information in the source notes for this period." The report does not invent content.

## Tell: the recap

- Structure the notes once, and a Workflow does the collation in a minute.
- One idea to keep: the report is generated from work already done, not written again.
- Next: asking questions of the report.
