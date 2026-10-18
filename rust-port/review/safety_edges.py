#!/usr/bin/env python3
"""Verify and disclose safe rejection differences around Java signed-long overflow."""
import argparse
import json
import subprocess
from pathlib import Path

from differential import REVIEW, execute_java, header


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust", type=Path, required=True)
    args = parser.parse_args()
    directory = REVIEW / "safety-cases"
    directory.mkdir(exist_ok=True)
    maximum = 0x7fffffffffffffff
    # (distance below signed MAX, section-entry size, Java acceptance, Rust acceptance)
    cases = [(64, 64, True, True), (63, 64, True, False), (56, 64, True, False),
             (55, 64, False, False), (4, 64, False, False), (0, 64, False, False),
             (32766, 32767, True, False), (0, 32768, True, True)]
    files = []
    for distance, entry_size, _, _ in cases:
        path = directory / f"signed-max-minus-{distance}-entry-{entry_size}.elf"
        path.write_bytes(header(shoff=maximum-distance, shentsize=entry_size))
        files.append(path)
    java = execute_java(files, prefix="safety-java")
    result = subprocess.run([str(args.rust.resolve()), "--compatible", *map(str, files)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode in (0, 1), result.stderr
    rust = json.loads(result.stdout)
    assert len(java) == len(rust) == len(cases)
    rows = []
    for case, want, have, path in zip(cases, java, rust, files):
        _, _, expected_java, expected_rust = case
        assert want["file"] == Path(have["file"]).name == path.name
        assert want["accepted"] == expected_java, want
        assert have["accepted"] == expected_rust, have
        if not expected_rust:
            assert have["error_type"] == "OffsetOverflow", have
        rows.append(dict(file=path.name, java_accepted=want["accepted"],
                         rust_accepted=have["accepted"],
                         intentional_safe_rejection=expected_java and not expected_rust,
                         java_error=want.get("error"), rust_error=have.get("error_type")))
    report = dict(cases=len(rows), intentional_safe_rejections=sum(r["intentional_safe_rejection"] for r in rows),
                  explanation="Rust rejects a signed-positive section-zero region addition that would overflow Java long; Java accepts some such gates before zero-filling at enormous offsets.",
                  results=rows)
    (REVIEW / "safety-comparison.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: {len(rows)} safety-edge expectations; {report['intentional_safe_rejections']} documented safe rejections differ from Java")


if __name__ == "__main__":
    main()
