#!/usr/bin/env python3
"""Show the policy rule behind each scene, and how the cover-up was caught.

    policy_slide.py 02-engineer-denied              print one slide
    policy_slide.py 02-engineer-denied --verdict deny
    policy_slide.py --watch FILE                    follow FILE: scene on line 1, verdict on line 2

Acts 1 and 2 show the policy excerpt that decides the scene, dimmed until the
agent's call returns and then lit with ALLOW or DENY. The excerpts are read
from config/cpex-policy.yaml between `# slide: <name>` and `# end-slide`, so
the slide always shows the policy the demo runs. Act 3 has no rule to show:
nothing in policy fires when someone edits the log. Its scenes show how the
edit was caught instead.
"""

import argparse
import re
import shutil
import sys
import textwrap
import time
from pathlib import Path

DEMO_DIR = Path(__file__).resolve().parent.parent
POLICY = DEMO_DIR / "config" / "cpex-policy.yaml"
BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"
GREEN, RED, CYAN, YELLOW = "\033[1;32m", "\033[1;31m", "\033[1;36m", "\033[1;33m"

# scene -> (heading, excerpt name or None, the rule that decides, what it says, lines for a card)
SLIDES = {
    "01-hr-allowed": ("who may read salaries", "hr-only", "require(role.hr)",
                      "Only HR may read compensation. Reading it marks the session as having seen secret data.", []),
    "02-engineer-denied": ("who may read salaries", "hr-only", "require(role.hr)",
                           "Alice is not in HR, so this rule refuses her.", []),
    "03-injection-blocked": ("what a marked session may send", "tainted", "security.labels",
                             "This session read a salary, so it is marked. A marked session sends no email.", []),
    "04-ssn-redacted": ("who may see a social security number", "redact", "redact(",
                        "Without the view_ssn permission, the number is removed from the result.", []),
    "05-tamper": ("how the edit was caught", None, "", "", [
        "The record's signature no longer matches its contents.",
        "The next record's link to it breaks.",
        "The ledger received the original, and still has it: Denied.",
        "",
        "Nobody holding the log can re-sign it: the key stays with the gateway.",
    ]),
    "06-delete": ("how the deletion was caught", None, "", "", [
        "Every record is numbered, so a missing one leaves a gap.",
        "The next record points at a record that is no longer there.",
        "The ledger kept the deleted record, and shows what it said.",
        "Its fingerprint is the one the next record names: it is the deleted record.",
    ]),
    "07-restart": ("why a crash is not a gap", None, "", "", [
        "A restarted gateway opens a new epoch, numbered from zero.",
        "Its first record links to nothing: a fresh start, marked as one.",
        "Records missing inside an epoch are loss. A new epoch is not.",
    ]),
}


def excerpt(name):
    text = POLICY.read_text()
    m = re.search(rf"^[ ]*# slide: {re.escape(name)}\n(.*?)^[ ]*# end-slide", text, re.S | re.M)
    if not m:
        return [f"(no slide {name!r} in {POLICY.name})"]
    # Comments and the identity plumbing are left out: the slide is about the rule.
    lines = [line for line in m.group(1).splitlines()
             if not line.strip().startswith(("#", "authentication:"))]
    indent = min(len(line) - len(line.lstrip()) for line in lines if line.strip())
    return [line[indent:] for line in lines]


def render(scene, verdict):
    width = shutil.get_terminal_size((72, 12)).columns
    out = ["\033[H\033[2J"]
    if scene not in SLIDES:
        sys.stdout.write("".join(out))
        sys.stdout.flush()
        return
    heading, name, rule, says, card = SLIDES[scene]
    out.append(f"{CYAN}{heading.upper()}{RESET}\n")
    if name:
        lit = verdict in ("allow", "deny")
        for line in excerpt(name):
            # Before the verdict everything is dim. After it, the deciding rule lights in the
            # verdict's colour and the rest stays dim, so the eye goes to the one line.
            if lit and rule in line:
                style = RED if verdict == "deny" else GREEN
            else:
                style = DIM
            # Wrapped, not cut: a rule's reason is the part worth reading.
            pad = " " * (len(line) - len(line.lstrip()) + 4)
            for piece in textwrap.wrap(line, width - 1, subsequent_indent=pad, drop_whitespace=False) or [""]:
                out.append(style + piece + RESET + "\n")
        out.append("\n")
        for line in textwrap.wrap(says, width - 1):
            out.append((RESET if lit else DIM) + line + RESET + "\n")
        if verdict == "allow":
            out.append(f"\n{GREEN}ALLOW{RESET}\n")
        elif verdict == "deny":
            out.append(f"\n{RED}DENY{RESET}\n")
    else:
        for line in card:
            for wrapped in textwrap.wrap(line, width - 3) or [""]:
                out.append((f"{YELLOW}▸{RESET} " if wrapped and line.startswith(wrapped) else "  ") + wrapped + "\n")
    sys.stdout.write("".join(out))
    sys.stdout.flush()


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("scene", nargs="?")
    p.add_argument("--verdict", default="")
    p.add_argument("--watch")
    a = p.parse_args()
    if a.watch:
        sys.stdout.write("\033[?25l")
        last = None
        while True:
            try:
                lines = Path(a.watch).read_text().splitlines()
            except OSError:
                lines = []
            state = (lines[0].strip() if lines else "", lines[1].strip() if len(lines) > 1 else "")
            if state != last:
                render(*state)
                last = state
            time.sleep(0.1)
    render(a.scene or "", a.verdict)


if __name__ == "__main__":
    main()
