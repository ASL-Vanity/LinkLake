#!/usr/bin/env python3
"""只读检查 E2E 专用 SQLite 中的 DNS-01 恢复元数据。"""

import json
from pathlib import Path
import sqlite3
import sys


def main() -> None:
    database = Path(sys.argv[1]).resolve()
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=5) as connection:
        rows = connection.execute("SELECT state FROM dns01_intents ORDER BY id").fetchall()
    fields = ("id", "zone_id", "record_id", "cleanup_requested", "creation_observed", "creation_rejected")
    intents = [json.loads(row[0]) for row in rows]
    print(json.dumps([{key: intent[key] for key in fields} for intent in intents]))


if __name__ == "__main__":
    main()
