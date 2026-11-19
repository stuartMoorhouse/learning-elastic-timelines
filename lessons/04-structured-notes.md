# Lesson 4: Structured notes

Time: 7 minutes. Theme: pinning and investigating.

## Learning objective

Describe a global note with a fixed structure that any analyst, and later a Workflow, can read.

## Tell: the concept

- Every Timeline has a **global note**: the overall story of the investigation.
- Free-text notes are the problem from lesson 1. Fixed headings fix it.
- The note has the same sections in the same order:
  1. TLP and client line
  2. Hypothesis
  3. Scope and data
  4. Queries run
  5. Findings
  6. Incident handling, using the NIST SP 800-61 phases: Detect, Analyse, Contain, Eradicate, Recover
  7. NIS2 reporting: `Reportable?`, `Clock started at:`
  8. Handover
  9. `Keywords:` line
  10. `Report-ready summary:` one sentence
- Why each part exists:
  - Hypothesis and queries make the work repeatable.
  - NIST phases give a shared language for where the case stands.
  - NIS2 fields record the facts behind a reportability decision. They are an example of use, not a compliance claim.
  - The report-ready summary is one line that automation can lift directly (lesson 7).

## Show: what to look for

- A negative result is a valid record: the empty result is the finding, and the scope and gaps are written down.
- The same headings appear every time.
- The note ends with `Keywords:` and `Report-ready summary:`.

## Tell: the recap

- Structured notes make every record readable in 30 seconds, by people and by automation.
- One idea to keep: the same headings every time.
- Next: making records easy to find.
