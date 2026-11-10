# Audit ledger demo

Every policy verdict cortex makes, allow, deny or redact, leaves as a signed,
hash-chained OCSF record. An independent ledger receipts each one, and
agentop's audit pane checks every record itself, from its bytes, the
gateway's public key and the ledger's copy. Cortex serves the records and
never says whether they verify.

It is the HR copilot of praxis-proxy/demos `policy-engine-audit`, on a
laptop cortex instead of a Praxis gateway: the policy runs in cortex's cpex
plugin, the `ocsf-audit` sink writes through its `file` exporter, and the ARE
ledger runs in Docker.

```text
agent.py ──MCP──▶ cortex :47800 (cpex plugin, ocsf-audit sink) ──▶ HR server :47810
                    │ appends signed records
                    ▼
        .state/home/.cortex/audit/records.ndjson
           │                         │
           ▼                         ▼
   cortex GET /v1/audit      shipper ──▶ ARE ledger :47820
           │                         │
           └──────▶ agentop audit pane ◀──────┘
                   (verifies; compares receipts)
```

## Build

A cortex with the audit sink, which needs a libcpex_ffi.a that carries it
(see the `cortex-audit-ffi` wrapper crate):

```bash
make cortex-cpex CPEX_FFI_DIR=<dir with the audit libcpex_ffi.a> CORTEX_CPEX_TAGS=cortexaudit
```

Also needed: Docker, python3, openssl, jq, curl, lsof, git, Go (agentop is
built on first `observe`).

## Run

```bash
./run.sh up          # ledger, HR server, cortex, shipper
./run.sh observe     # second terminal: agentop on this demo; press V
./run.sh scenarios   # the four HR scenarios
```

| Scene | Command | What the audit pane shows |
|---|---|---|
| HR reads a salary | `scenarios` (01) | allow records, `✓ signed`, `✓ linked`, `✓ #N` receipts |
| Engineer denied | `scenarios` (02) | a signed deny naming alice and the rule |
| Prompt injection | `scenarios` (03) | the doc read, the salary read, the refused email (`session_tainted_secret`); the HR server sent nothing |
| SSN redacted | `scenarios` (04) | eve gets `[REDACTED]`; the SSN is nowhere in the records |
| Insider edits the log | `tamper` | alice's deny now reads Allowed: `✗ tampered`, `✗ differs` from the ledger, the next record `✗ broken` |
| Insider deletes a record | `delete` | a red `⚠ 1 MISSING` row with `ledger: Denied`, the next record `⚠ gap` |
| Gateway crash | `restart`, then `scenarios` | `── NEW EPOCH ──`, the chain starting over at `● start`, not a gap |

`tamper` and `delete` stop cortex, rewrite the records file in place as an
insider with write access would, and start cortex again so its store re-reads
the file; agentop refetches when its stream reconnects. The shipper never
re-sends a record it has receipted, so the ledger keeps what it first got.

`./run.sh down` stops everything and removes the ledger's data;
`./run.sh down --purge` also deletes `.state/`.

## The video

`demo/steps.md` is the script: one caption per scene, the title and closing
cards, and voiceover beats, written for an executive audience.
`./run.sh walkthrough` plays the whole story in order, pausing for Enter
between scenes. To record it:

```bash
brew install tmux asciinema agg ffmpeg   # once
demo/record.sh                           # about 2 minutes; writes demo/out/audit-ledger.{cast,gif,mp4}
demo/record.sh --check                   # the scenes and the captions agree
```

The recorder resets the demo, lays out the caption bar, agentop's audit pane,
the agent and a policy slide in one tmux window, plays the walkthrough on a timer
(`--pace`, `--hold`), and renders the take. It hides agentop's identity-check
rows (`i`) so the pane shows decisions; a flagged record shows regardless.

The policy slide (`demo/policy_slide.py`) shows the rule behind each scene of
the first two acts, read from `config/cpex-policy.yaml` between `# slide:`
and `# end-slide`, and lights the deciding rule red or green when the agent's
call returns. In the third act no rule fires, so the slide says how the edit
was caught instead.

## What stays untouched

Cortex and agentop run with `HOME=.state/home`, so `~/.cortex`, an installed
cortex service on 4760x and its sessions are never read or written; `run.sh`
checks that the process on :47600 is the same before and after. Everything
listens on loopback ports 478xx. Tokens, keys and the content-digest secret
are generated under `.state/`.

## Limits

- The cortex build links a locally built CPEX FFI and PPE from a branch, not
  released artifacts; see the plan in praxis-proxy/policy
  `docs/plans/2026-10-17-001-feat-audit-serializer-exporter-plan.md`.
- Writes are on the request path; queued delivery is praxis-proxy/policy#165.
- Each tool call yields four records (identity and authorize on the way in,
  identity and response on the way out); the pane shows them all.
