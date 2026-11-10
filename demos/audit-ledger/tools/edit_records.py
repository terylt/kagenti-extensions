"""Edit the audit records file in place, as an insider with write access would.

    edit_records.py tamper RECORDS   flip the first recorded deny to an allow
    edit_records.py delete RECORDS   delete the last recorded deny

The file is rewritten in place, the same file truncated and written again,
so a follower sees an edit rather than a rotation. Only the bytes change:
nothing re-signs or re-chains, because an insider cannot.
"""

import sys

DENIED = b'"action":"Denied"'


def main():
    what, path = sys.argv[1], sys.argv[2]
    with open(path, "r+b") as f:
        lines = f.read().split(b"\n")
        denies = [i for i, line in enumerate(lines) if DENIED in line]
        if not denies:
            sys.exit("no recorded deny to edit; run ./run.sh scenarios first")
        if what == "tamper":
            i = denies[0]
            lines[i] = lines[i].replace(DENIED, b'"action":"Allowed"', 1)
            print(f"  ▸ flipped the deny in record {i + 1} to an allow")
        elif what == "delete":
            i = denies[-1]
            del lines[i]
            print(f"  ▸ deleted record {i + 1}, a deny")
        else:
            sys.exit(f"unknown edit {what!r}")
        f.seek(0)
        f.write(b"\n".join(lines))
        f.truncate()


if __name__ == "__main__":
    main()
