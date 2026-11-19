# Lesson 2: Timeline basics

Time: 7 minutes. Theme: pinning and investigating.

## Learning objective

Describe the parts of a Timeline and explain why the query is part of the record.

## Tell: the concept

- A hunt starts with a hypothesis, not an alert. Example: "Something other than an authorised writer is changing process values on the line 2 controller."
- A Timeline turns that hypothesis into a workspace with four parts:
  - **Query bar**: KQL or another query language, with a time range. This is the question.
  - **Query builder (data providers)**: drag-and-drop conditions such as `source.ip` or `zeek.modbus.function`, combined with AND and OR. The detection logic sits here.
  - **Results grid**: the events, with columns you choose.
  - **Tabs**: Query, Correlation, Notes, Pinned.
- A **pivot** takes one value you have just found and asks a new question about it. It is how an investigation moves from one event to the events around it.
  - **To the parent**: who or what started this process? A parent of `explorer.exe` means a person launched it by hand. A script host or a service means something automated did.
  - **To the children**: what did this process start next?
  - **To the same process**: what else did it do, such as files it wrote or connections it made?
  - Each pivot is a new query built from a value already on screen, so the analyst follows the evidence instead of guessing.
- A Timeline is a saved object. Closing the browser does not lose the work, and a colleague can open the same Timeline.

## Show: what to look for

- The query, results and notes sit in one place.
- No alert is behind this hunt. The analyst brought the question.
- The query is saved, so the next analyst starts from the question, not a blank screen.
- A pivot from a suspicious process to its parent and its child shows the chain of what ran, step by step.

## Tell: the recap

- A Timeline is the hunt workspace: query, results and notes together, saved and shareable.
- A pivot turns one finding into the next question.
- One idea to keep: the query is part of the record.
- Next: marking the events that matter.
