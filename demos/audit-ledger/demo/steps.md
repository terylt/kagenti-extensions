# Audit ledger demo: video script

The captions here are the video's script. `demo/caption_bar.py` reads this
table, so a caption changed here changes the video. The walkthrough runs the
scenarios in this order; `demo/record.sh --check` fails if the two disagree.

Audience: executives. No protocol names on screen or in the voiceover. Say
"tamper-evident" or "any change is caught", never "tamper-proof": the file can
be edited, it cannot be edited undetected.

| # | Act | Scenario | Caption |
|---|-----|----------|---------|
| 1 | A normal day | `01-hr-allowed.sh` | Bob in HR asks his AI copilot for an employee's salary. It's checked against policy, allowed, and recorded with an independent receipt. |
| 2 | A normal day | `02-engineer-denied.sh` | Alice, an engineer, asks the same copilot. Agents get exactly the access of the person they work for, so she is refused before the HR system ever sees it. |
| 3 | The attack | `03-injection-blocked.sh` | A hidden instruction in a wiki page tells Bob's agent to email salaries outside the company. The agent obeys. Cortex blocks it, and the record shows why. |
| 4 | The attack | `04-ssn-redacted.sh` | Eve in HR has no clearance for social security numbers. The number is removed in flight, and the record proves it without ever storing it. |
| 5 | The cover-up | `05-tamper.sh` | Now an insider edits the log so Alice's refused request reads "Allowed". It's caught at once: the signature breaks, and the independent ledger still holds the original. |
| 6 | The cover-up | `06-delete.sh` | Deleting the record doesn't work either. The gap shows, and the ledger kept a copy of what was removed. |
| 7 | The cover-up | `07-restart.sh` | And when the gateway crashes, the record says so. A crash looks like a crash, never like a cover-up. |

Title: Your AI agents act on your behalf. Can you prove what they did?
Closing: Every action an AI agent takes: enforced, on the record, and provable to an auditor who doesn't have to trust us.

## Voiceover beats

- Open: agents are moving from answering questions to taking actions. When
  something goes wrong, the board or the auditor asks what the agent did, who
  allowed it, and how you know the record is true.
- After 3: agents can't tell instructions from data, so the control has to sit
  outside the agent.
- Before 5: controls are table stakes. The hard question is what happens when
  someone on the inside wants to hide something.
- Pause on the red row in 5. It is the moment the video is for. The pane then
  opens the record: because the ledger kept its own copy, it shows exactly
  what the insider changed, Denied to Allowed. Without an independent copy you
  would know only that something changed.
- In 6 the pane opens the gap: the ledger's copy is the blocked email to the
  outside address, the evidence of the attack the insider tried to erase. The
  record holds the decision, not the email itself, so say the address aloud.
- Close: three words. Control, evidence, independence.

## Recording

```bash
./run.sh up                      # once
demo/record.sh                   # resets the demo, records, writes .cast, .gif, .mp4
demo/record.sh --check           # the scenarios and this table agree
```
