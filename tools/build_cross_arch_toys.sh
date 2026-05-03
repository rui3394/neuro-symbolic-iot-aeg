#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOY_DIR="$ROOT_DIR/datasets/toy_cgi"
OUT_DIR="$TOY_DIR/build_cross"
MANIFEST="$ROOT_DIR/examples/cross_arch/toy_benchmark_manifest.json"
STATUS_FILE="$(mktemp)"

CFLAGS=${NS_AEG_CROSS_CFLAGS:-"-O0 -g -fno-pie -fno-builtin -Wall -Wextra"}
LDFLAGS=${NS_AEG_CROSS_LDFLAGS:-"-no-pie"}

mkdir -p "$OUT_DIR" "$(dirname "$MANIFEST")"

record_case() {
  local toy_id="$1"
  local arch="$2"
  local binary_path="$3"
  local target_yaml="$4"
  local build_status="$5"
  local compiler="$6"
  local notes="$7"
  local expected_behavior="$8"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$toy_id" "$arch" "$binary_path" "$target_yaml" "$build_status" "$compiler" "$notes" "$expected_behavior" \
    >> "$STATUS_FILE"
}

build_case() {
  local toy_id="$1"
  local source="$2"
  local target_yaml="$3"
  local expected_behavior="$4"
  local arch="$5"
  local compiler="$6"
  local arch_dir="$OUT_DIR/$arch"
  local binary="$arch_dir/$toy_id"
  local binary_rel="datasets/toy_cgi/build_cross/$arch/$toy_id"
  local log="$arch_dir/${toy_id}.build.log"

  mkdir -p "$arch_dir"
  if ! command -v "$compiler" >/dev/null 2>&1; then
    echo "skip $arch/$toy_id: compiler not found: $compiler"
    record_case "$toy_id" "$arch" "$binary_rel" "$target_yaml" "skipped_compiler_missing" "$compiler" "compiler not found" "$expected_behavior"
    return 0
  fi

  echo "build $arch/$toy_id with $compiler"
  if "$compiler" $CFLAGS "$TOY_DIR/$source" -o "$binary" $LDFLAGS >"$log" 2>&1; then
    record_case "$toy_id" "$arch" "$binary_rel" "$target_yaml" "built" "$compiler" "ok" "$expected_behavior"
  else
    echo "failed $arch/$toy_id: see $log"
    record_case "$toy_id" "$arch" "$binary_rel" "$target_yaml" "failed" "$compiler" "compile failed; see $log" "$expected_behavior"
  fi
}

for arch_compiler in \
  "x86_64:gcc" \
  "arm32:arm-linux-gnueabihf-gcc" \
  "aarch64:aarch64-linux-gnu-gcc" \
  "mipsel:mipsel-linux-gnu-gcc" \
  "mips:mips-linux-gnu-gcc"
do
  arch="${arch_compiler%%:*}"
  compiler="${arch_compiler#*:}"
  build_case "toy_01" "toy_01_basic_cmd.c" "configs/toy_01.yaml" "sat_expected" "$arch" "$compiler"
  build_case "toy_02" "toy_02_filter_chars.c" "configs/toy_02.yaml" "sat_expected" "$arch" "$compiler"
  build_case "toy_03" "toy_03_length_limit.c" "configs/toy_03.yaml" "planner_reject_expected" "$arch" "$compiler"
  build_case "toy_04" "toy_04_branch_check.c" "configs/toy_04.yaml" "unsat_expected" "$arch" "$compiler"
  build_case "toy_05" "toy_05_safe_case.c" "configs/toy_05.yaml" "unsat_expected" "$arch" "$compiler"
  build_case "toy_06" "toy_06_format_flow.c" "configs/toy_06.yaml" "sat_expected" "$arch" "$compiler"
  build_case "toy_07" "toy_07_format_safe_negative.c" "configs/toy_07.yaml" "unsat_expected" "$arch" "$compiler"
  build_case "toy_08" "toy_08_snprintf_truncation_negative.c" "configs/toy_08.yaml" "truncation_negative_expected" "$arch" "$compiler"
  build_case "toy_09" "toy_09_snprintf_truncation_positive.c" "configs/toy_09.yaml" "sat_expected" "$arch" "$compiler"
  build_case "toy_10" "toy_10_memcpy_flow_positive.c" "configs/toy_10.yaml" "sat_expected" "$arch" "$compiler"
  build_case "toy_11" "toy_11_memcpy_truncation_negative.c" "configs/toy_11.yaml" "truncation_negative_expected" "$arch" "$compiler"
done

python3 - "$STATUS_FILE" "$MANIFEST" <<'PY'
from __future__ import annotations

import json
from pathlib import Path
import sys
from datetime import datetime, timezone

status_path = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])
cases = []
for line in status_path.read_text(encoding="utf-8").splitlines():
    toy_id, arch, binary_path, target_yaml, build_status, compiler, notes, expected_behavior = line.split("\t", 7)
    cases.append(
        {
            "toy_id": toy_id,
            "arch": arch,
            "binary_path": binary_path,
            "target_yaml": target_yaml,
            "build_status": build_status,
            "compiler": compiler,
            "notes": notes,
            "expected_behavior": expected_behavior,
        }
    )

payload = {
    "schema_version": "cross_arch_toy_benchmark_manifest_v1",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "generated_by": "tools/build_cross_arch_toys.sh",
    "cases": cases,
}
manifest_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(f"wrote manifest: {manifest_path}")
PY

rm -f "$STATUS_FILE"

echo "cross-arch toy build complete"
