#!/usr/bin/env python3
"""验证 mdnsscan 的 YAML 输出能被 yaml.safe_load 解析。

用法: python scripts/validate_yaml.py <yaml_file>
"""
import sys
import yaml


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: validate_yaml.py <yaml_file>", file=sys.stderr)
        return 2
    with open(argv[1], "r", encoding="utf-8") as f:
        try:
            data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(f"FAIL yaml parse: {e}")
            return 1

    if not isinstance(data, dict):
        print(f"FAIL top-level not dict: {type(data)}")
        return 1

    if "services" not in data:
        print("FAIL missing 'services' top key")
        return 1
    if "answers" not in data:
        print("FAIL missing 'answers' top key")
        return 1

    svc = data["services"]
    if not isinstance(svc, dict) or len(svc) == 0:
        print(f"FAIL services empty or wrong type")
        return 1

    # banner 形态:demo-style 单元素 dict,或 list。兼容两种。
    def as_banner(v):
        if isinstance(v, dict):
            return v
        if isinstance(v, list) and v:
            return v[0]
        return None

    if "5000/tcp qdiscover" in svc:
        qd = as_banner(svc["5000/tcp qdiscover"])
        if qd is None:
            print("FAIL qdiscover empty")
            return 1
        required = {"Name", "IPv4", "IPv6", "Hostname", "TTL",
                    "accessType", "accessPort", "model", "displayModel",
                    "fwVer", "fwBuildNum"}
        got = set(qd.keys())
        missing = required - got
        if missing:
            print(f"FAIL qdiscover missing fields: {sorted(missing)}")
            return 1
        if not isinstance(qd["TTL"], int):
            print(f"FAIL TTL should be int, got {type(qd['TTL'])}")
            return 1
        if qd["accessType"] != "https":
            print(f"FAIL accessType: {qd['accessType']}")
            return 1
        print("OK qdiscover 11 fields present (Name/IPv4/IPv6/Hostname/TTL + 6 deep)")
    else:
        print("WARN no qdiscover in services (fixture-driven; skip deep check)")

    if "PTR" in data["answers"]:
        print(f"OK answers.PTR = {data['answers']['PTR']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
