# Lesson 6: Templates

Time: 7 minutes. Theme: templating.

## Learning objective

Show how Timeline templates give a new record a ready-made starting point.

## Tell: the concept

- A **Timeline template** can hold a query, columns and a note skeleton, so a recurring hunt or alert type starts from something prepared.
- Elastic offers two kinds:
  - **Alert template**: tied to an alert type. Placeholders such as `{host.name}` fill in from the alert.
  - **Hunt template**: not tied to an alert. It starts from the analyst's own hypothesis.
- Templates can carry the note headings from lesson 4. Titling them `TEMPLATE | ...` keeps them apart from real records in the list.

## Show: what to look for

- A hunt template and an alert template start in different places but open with the same note headings.
- The specifics, such as the hypothesis and the findings, are left to fill in.

## Tell: the recap

- A template is a head start, and shared headings are what let notes be read together later.
- Next: what can be done with all those notes.
