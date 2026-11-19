# Lesson 8: Agent Builder and wrap-up

Time: 8 minutes (3 for the agent, 5 for wrap-up and Q&A). Theme: the value of a Workflow in collating notes.

## Learning objective

Explain how an agent answers questions from the generated report, and restate how Timelines plus a Workflow remove the documentation bottleneck.

## Tell: the concept

- The report is stored in an index, so it can be asked about. An **agent** in Agent Builder answers questions using **tools**, here a search over the report index and an alert summary.
- Agent rules:
  - Answer only from tool results. Never invent incidents, IOCs, hosts or dates.
  - Cite the report and its source Timelines.
  - State the TLP of the report used, and never lower a marking.
  - If the notes do not say, say so.

## Show: what to look for

- Every answer starts with a TLP and names its sources.
- The IOC answer matches the report's IOC table.
- Where the notes are silent, the agent says "not stated in notes".

## Tell: the recap (wrap-up)

1. **Investigate and note in the Timeline**: query, pinned events, IOCs, structured note (lessons 2 to 4).
2. **Name and template**: searchable history, clean handovers, reusable structure (lessons 5 and 6).
3. **Collate with a Workflow**: weekly TLP-marked report from the notes, queryable by an agent (lessons 7 and 8).

The problem, answered: analyst notes are shared, searchable and reusable instead of scattered.

ATT&CK, TLP, NIST SP 800-61 and NIS2 appear as examples of use, not compliance claims. All data is synthetic.
