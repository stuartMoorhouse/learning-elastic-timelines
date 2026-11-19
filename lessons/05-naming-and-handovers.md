# Lesson 5: Naming and handovers

Time: 10 minutes. Theme: team collaboration and handovers.

## Learning objective

Show how a naming convention turns the Timelines list into a searchable history, and how a handover can live in the Timeline itself.

## Tell: the concept

- Timelines are shared, so the Timelines list can double as a case history. A consistent title is what makes it searchable.
- One convention that works:

  `YYYY-MM-DD | <client-or-env> | <hunt or technique> | <status> | TLP:<colour>`

  Example: `2026-11-18 | CLIENT-C | Hunt: unknown device scanning OT controllers (T0846) | Open - Handover | TLP:AMBER`
- The status says where a record stands, for example `Open - Handover`, `Escalated - Handover`, `Closed - True Positive`, `Closed - Accepted Behaviour` or `Closed - Clean, no adversary activity found`.
- The TLP colour (`CLEAR`, `GREEN`, `AMBER`, `RED`) says how far the record can be shared.
- Timelines have no tag field. A final `Keywords:` line in the description gives the search something extra to match, because the list searches both title and description.
- Three kinds of record are worth keeping:
  - **Handover**: what has been checked, and what comes next.
  - **Accepted behaviour**: why something is not malicious here, which can back an exception.
  - **Negative result**: what was ruled out, and with what visibility.

## Show: what to look for

- Searching by status, TLP colour or keyword narrows the list quickly.
- An open handover reads as a starting point for the next shift.
- A clean result records its scope and its gaps, so it can be defended later.

## Tell: the recap

- A handover saved in the Timeline travels with the evidence, so the next analyst picks up the record, not a message about it.
- Next: starting each new record from a template.
