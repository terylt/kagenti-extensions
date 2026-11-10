#!/usr/bin/env python3
"""Show the recording's caption for the current scene.

    caption_bar.py 05-tamper            print one caption
    caption_bar.py --watch FILE         follow FILE, whose first line names the scene
    caption_bar.py --check              every scene script has a caption, in order

Captions come from demo/steps.md: `title` shows the Title line, a scene name
its row's caption numbered "n/7" with the act, and `summary` the Closing line.
"""

import argparse
import os
import re
import shutil
import sys
import textwrap
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"


def load():
    text = (HERE / "steps.md").read_text()
    rows = re.findall(r"^\| (\d+) \| ([^|]+) \| `([^`]+)` \| (.+?) \|$", text, re.M)
    steps = [(int(n), act.strip(), Path(script).stem, caption.strip()) for n, act, script, caption in rows]
    title = re.search(r"^Title: (.+)$", text, re.M).group(1)
    closing = re.search(r"^Closing: (.+)$", text, re.M).group(1)
    return steps, title, closing


def caption_for(scene):
    steps, title, closing = load()
    if scene == "title":
        return "", title
    if scene == "summary":
        return "", closing
    for n, act, name, caption in steps:
        if name == scene:
            return f"{n}/{len(steps)}  {act.upper()}", caption
    return "", ""


def render(scene):
    width = shutil.get_terminal_size((160, 4)).columns
    label, caption = caption_for(scene)
    lines = textwrap.wrap(caption, width - 6) or [""]
    out = ["\033[H\033[2J"]
    if label:
        out.append(DIM + label.center(width) + RESET + "\n")
    for line in lines:
        out.append(BOLD + line.center(width) + RESET + "\n")
    sys.stdout.write("".join(out))
    sys.stdout.flush()


def check():
    steps, _, _ = load()
    scripts = sorted(p.stem for p in (HERE.parent / "scenarios").glob("[0-9][0-9]-*.sh"))
    named = [name for _, _, name, _ in steps]
    if named != scripts:
        sys.exit(f"steps.md scenes {named} do not match the scenario scripts {scripts}")
    if [n for n, *_ in steps] != list(range(1, len(steps) + 1)):
        sys.exit("steps.md rows are not numbered 1..n")
    print(f"{len(steps)} scenes, each with a caption")


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("scene", nargs="?")
    p.add_argument("--watch")
    p.add_argument("--check", action="store_true")
    a = p.parse_args()
    if a.check:
        return check()
    if a.watch:
        sys.stdout.write("\033[?25l")
        last = None
        while True:
            try:
                scene = Path(a.watch).read_text().splitlines()[0].strip()
            except (OSError, IndexError):
                scene = "title"
            if scene != last:
                render(scene)
                last = scene
            time.sleep(0.1)
    render(a.scene or "title")


if __name__ == "__main__":
    main()
