# Lesson 3: Pinning events and capturing IOCs

Time: 8 minutes. Theme: pinning and investigating.

## Learning objective

Explain how pinned events and event notes record an attack path and its indicators of compromise (IOCs).

## Tell: the concept

- A query returns hundreds of events. The finding is a handful.
- **Pinning** marks the events that matter. Pins survive any later change to the query.
- An **event note** is attached to one event. It explains why the event matters and records IOCs: file paths, registry keys, accounts, IPs, domains, hashes.
- Adding the MITRE ATT&CK technique ID (for example T0836) to the note makes the record searchable by technique.
- Result: the Pinned tab is the attack path in order. The next analyst reads it without re-running anything.

## Show: what to look for

- The Pinned tab reads as the attack chain, top to bottom.
- The pins hold the evidence. The notes hold the reasoning.
- An event note carries an IOC and a technique ID.

## Tell: the recap

- Pin the events that prove the finding. Note each one with the IOC and technique ID.
- One idea to keep: investigation steps are written as they happen, not reconstructed afterwards.
- Next: the overall story, in a consistent structure.
