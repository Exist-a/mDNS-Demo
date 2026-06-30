#!/usr/bin/env python3
"""验证 mdnsscan --json 输出能被 json.load 解析。

用法: python scripts/validate_json.py <json_file>
"""
import json
import sys


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: validate_json.py <json_file>", file=sys.stderr)
        return 2
    with open(argv[1], "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"FAIL json parse: {e}")
            return 1

    if not isinstance(data, dict):
        print(f"FAIL top not dict")
        return 1
    if "services" not in data or "answers" not in data:
        print("FAIL missing services/answers")
        return 1
    print(f"OK json parses; services keys={list(data['services'].keys())}, ptrs={data['answers'].get('PTR')}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
