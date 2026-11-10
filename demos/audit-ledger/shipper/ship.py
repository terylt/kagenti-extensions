"""Follow the sink's records file and receipt each new record in the ledger.

    ship.py --file RECORDS --endpoint HOST:PORT --adapter LEDGER/adapters/cpex

The ledger's CPEX adapter does the mapping (entry type, idempotency key,
input_hash, signature) through its own process_line, so a receipt here is
exactly what the adapter would write. The adapter reads a file once or a
stream; this adds following the file by name, the way `tail -F` does.

Each record uid is shipped once. When the file is rewritten (a tamper
edit, a restart that re-reads it), records already receipted are not sent
again: the ledger keeps what it first received, which is the point.
"""

import argparse
import json
import os
import sys
import time


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--file", required=True)
    p.add_argument("--endpoint", required=True)
    p.add_argument("--adapter", required=True, help="the ledger checkout's adapters/cpex directory")
    args = p.parse_args()

    sys.path.insert(0, args.adapter)
    sys.path.insert(0, os.path.join(args.adapter, "..", "..", "sdks", "python"))
    from cpex_to_ledger import GapDetector, LedgerClient, process_line  # noqa: E402

    client = LedgerClient(args.endpoint)
    stats = {"written": 0, "parse_errors": 0, "write_errors": 0, "skipped": 0, "gaps_detected": 0}
    gaps = GapDetector()
    shipped = set()
    f, inode, offset, partial = None, None, 0, b""
    print(f"shipping {args.file} to {args.endpoint}", flush=True)

    while True:
        try:
            st = os.stat(args.file)
        except FileNotFoundError:
            time.sleep(0.2)
            continue
        if f is None or st.st_ino != inode:
            if f is not None:
                f.close()
            f, inode, offset, partial = open(args.file, "rb"), st.st_ino, 0, b""
        elif st.st_size < offset:
            offset, partial = 0, b""  # truncated in place
        f.seek(offset)
        chunk = f.read()
        offset += len(chunk)
        partial += chunk
        *lines, partial = partial.split(b"\n")
        for line in lines:
            if not line.strip():
                continue
            try:
                uid = json.loads(line).get("metadata", {}).get("uid", "")
            except ValueError:
                continue
            if uid and uid in shipped:
                continue
            process_line(client, line.decode(), stats, gaps)
            if uid:
                shipped.add(uid)
        time.sleep(0.2)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
