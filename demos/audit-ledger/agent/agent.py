"""A scripted HR copilot agent that sends every MCP call through the demo cortex.

    agent.py --user bob --session s1 call get_compensation '{"employee_id":"EMP-001234"}'
    agent.py --user bob --session s3 comp-review

`call` makes one tools/call. `comp-review` is the prompt-injection run: read
the wiki page, read the salary, then do what the page's hidden instruction
says and email the record out. It exits 0 when that email is blocked.

Each request carries the user's token (X-User-Token, minted by run.sh) and
the session id (X-Claude-Code-Session-Id, the header cortex groups a coding
agent's session by), and goes through cortex's forward proxy. Standard
library only. Environment: DEMO_PROXY, HR_URL, IDENTITY_DIR.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

RED, GREEN, DIM, CYAN, RESET = "\033[1;31m", "\033[1;32m", "\033[2m", "\033[1;36m", "\033[0m"

INJECTION = re.compile(
    r"AGENT INSTRUCTION:.*?email.*?to\s+(?P<to>[\w.+-]+@[\w.-]+).*?subject\s+'(?P<subject>[^']+)'",
    re.S | re.I,
)


class Agent:
    def __init__(self, user, session):
        with open(os.path.join(os.environ["IDENTITY_DIR"], f"{user}.jwt")) as f:
            self.token = f.read().strip()
        self.session = session
        self.next_id = 1
        proxy = urllib.request.ProxyHandler({"http": os.environ["DEMO_PROXY"]})
        self.opener = urllib.request.build_opener(proxy)

    def call(self, tool, arguments):
        """One tools/call. Returns (ok, payload): the tool's parsed result, or the denial."""
        body = json.dumps({"jsonrpc": "2.0", "id": self.next_id, "method": "tools/call",
                           "params": {"name": tool, "arguments": arguments}}).encode()
        self.next_id += 1
        req = urllib.request.Request(os.environ["HR_URL"] + "/mcp", data=body, method="POST", headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-User-Token": self.token,
            "X-Claude-Code-Session-Id": self.session,
        })
        try:
            with self.opener.open(req, timeout=10) as resp:
                reply = json.load(resp)
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                reply = json.loads(raw)
            except ValueError:
                return False, f"HTTP {e.code}: {raw[:200].decode(errors='replace')}"
        if "error" in reply:
            err = reply["error"]
            return False, err.get("message", str(err)) if isinstance(err, dict) else str(err)
        text = "".join(p.get("text", "") for p in reply.get("result", {}).get("content", []))
        try:
            return True, json.loads(text)
        except ValueError:
            return True, text


PRESENTER = os.environ.get("PRESENTER") == "1"


def report(ok):
    """Tell the recorder the outcome, so its policy slide can light the rule (WALKTHROUGH_HOOK)."""
    hook = os.environ.get("WALKTHROUGH_HOOK")
    if hook:
        subprocess.run([hook, "verdict", "allow" if ok else "deny"], check=False)


def show(label, ok, payload):
    # A recording shows the tool and the outcome on one line; the result itself is detail.
    if PRESENTER:
        label = re.sub(r"\((\{.*\})\)$", lambda m: "(" + ", ".join(
            v if isinstance(v, str) else k.replace("_", " ") if v is True else f"{k}={v}"
            for k, v in json.loads(m.group(1)).items()) + ")", label)
    report(ok)
    if ok:
        summary = json.dumps(payload) if not isinstance(payload, str) else payload
        print(f"    {GREEN}✓ {label}{RESET}" + ("" if PRESENTER else f"  {DIM}{summary[:96]}{RESET}"), flush=True)
    else:
        print(f"    {RED}✗ {label}: DENIED{RESET}  {payload}", flush=True)


def comp_review(agent):
    print(f"  {CYAN}agent{RESET}  task: prepare Jane Smith's Q3 compensation review", flush=True)
    ok, doc = agent.call("fetch_doc", {"doc_id": "comp-review-process"})
    show("fetch_doc(comp-review-process)", ok, doc)
    ok, comp = agent.call("get_compensation", {"employee_id": "EMP-001234"})
    show("get_compensation(EMP-001234)", ok, comp)
    match = INJECTION.search(doc.get("body", "") if isinstance(doc, dict) else "")
    if not match:
        print("  agent: nothing else to do")
        return 1
    print(f"  {CYAN}agent{RESET}  {RED}found an instruction in tool output and is following it{RESET}", flush=True)
    ok, reply = agent.call("send_email", {"to": match["to"], "subject": match["subject"], "body": json.dumps(comp)})
    show(f"send_email(to={match['to']})", ok, reply)
    return 0 if not ok else 1


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--user", required=True)
    p.add_argument("--session", required=True)
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("call")
    c.add_argument("tool")
    c.add_argument("arguments", nargs="?", default="{}")
    sub.add_parser("comp-review")
    args = p.parse_args()

    agent = Agent(args.user, args.session)
    if args.cmd == "comp-review":
        return comp_review(agent)
    ok, payload = agent.call(args.tool, json.loads(args.arguments))
    show(f"{args.tool}({args.arguments})", ok, payload)
    if os.environ.get("AGENT_JSON"):
        print(json.dumps({"ok": ok, "payload": payload}))
    return 0 if ok else 3


if __name__ == "__main__":
    sys.exit(main())
