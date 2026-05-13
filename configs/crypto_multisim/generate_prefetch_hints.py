#!/usr/bin/env python3
"""
Generate chronological prefetch hints from SimpleMemTrace commit traces.

Examples:
  python3 configs/crypto_multisim/generate_prefetch_hints.py sha256
  python3 configs/crypto_multisim/generate_prefetch_hints.py sha256 \
      --lookback-min 5 --lookback-max 40 --lookback-seed 1
  python3 configs/crypto_multisim/generate_prefetch_hints.py \
      --trace /path/to/commit_rw_trace.csv --binary /path/to/binary
"""

import argparse
import ast
import csv
import random
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from inspect_commit_rw_trace import find_trace_file


SCRIPT_DIR = Path(__file__).resolve().parent
GEM5_ROOT = SCRIPT_DIR.parent.parent
SRC_ROOT = GEM5_ROOT.parent
BASE_CONFIG = SCRIPT_DIR / "multisim_se_x86_o3_crypto.py"

DEFAULT_TRACE_LOOKBACK = 20
DEFAULT_OBJDUMP = "objdump"

_OBJDUMP_INST_RE = re.compile(r"^\s*([0-9a-fA-F]+):")


@dataclass(frozen=True)
class HintGenerationStats:
    rows_read: int = 0
    hints_written: int = 0
    skipped_cache_hits: int = 0
    skipped_missing_pc: int = 0
    skipped_early_pc: int = 0
    malformed_rows: int = 0


def _format_hex(value: int) -> str:
    return f"0x{value:x}"


def _literal_assignment(module_path: Path, name: str):
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    return ast.literal_eval(node.value)
    raise KeyError(f"{name} not found in {module_path}")


def benchmark_path_candidates() -> dict[str, list[str]]:
    return _literal_assignment(BASE_CONFIG, "BENCHMARK_PATH_CANDIDATES")


def resolve_binary_path(benchmark_name: str) -> Path:
    candidates = benchmark_path_candidates()
    if benchmark_name not in candidates:
        known = ", ".join(sorted(candidates))
        raise KeyError(
            f"Unknown benchmark {benchmark_name!r}. Known benchmarks: {known}"
        )

    checked: list[Path] = []
    for candidate in candidates[benchmark_name]:
        path = Path(candidate)
        if not path.is_absolute():
            path = SRC_ROOT / path
        resolved = path.resolve()
        checked.append(resolved)
        if resolved.is_file() and resolved.stat().st_mode & 0o111:
            return resolved

    raise FileNotFoundError(
        "Could not find an executable benchmark binary. Checked:\n"
        + "\n".join(f"  - {path}" for path in checked)
    )


def parse_objdump_instruction_pcs_from_text(objdump_text: str) -> list[int]:
    pcs: list[int] = []
    for line in objdump_text.splitlines():
        match = _OBJDUMP_INST_RE.match(line)
        if match is not None:
            pcs.append(int(match.group(1), 16))
    return pcs


def disassemble_instruction_pcs(
    binary_path: Path,
    objdump: str = DEFAULT_OBJDUMP,
) -> list[int]:
    result = subprocess.run(
        [objdump, "-d", "--no-show-raw-insn", str(binary_path)],
        check=True,
        text=True,
        capture_output=True,
    )
    return parse_objdump_instruction_pcs_from_text(result.stdout)


def generate_hints_from_trace(
    trace_path: Path,
    instruction_pcs: Iterable[int],
    output_path: Path,
    lookback: int = DEFAULT_TRACE_LOOKBACK,
    lookback_min: int | None = None,
    lookback_max: int | None = None,
    lookback_seed: int = 1,
) -> HintGenerationStats:
    pcs_by_index = list(instruction_pcs)
    pc_to_index = {pc: index for index, pc in enumerate(pcs_by_index)}
    use_random_lookback = lookback_min is not None or lookback_max is not None

    if use_random_lookback:
        if lookback_min is None or lookback_max is None:
            raise ValueError(
                "Both lookback_min and lookback_max are required for "
                "random lookback"
            )
        if lookback_min < 0 or lookback_max < 0:
            raise ValueError("Random lookback bounds must be non-negative")
        if lookback_min > lookback_max:
            raise ValueError("lookback_min must be <= lookback_max")
        lookback_rng = random.Random(lookback_seed)
    else:
        if lookback < 0:
            raise ValueError("lookback must be non-negative")
        lookback_rng = None

    rows_read = 0
    hints_written = 0
    skipped_cache_hits = 0
    skipped_missing_pc = 0
    skipped_early_pc = 0
    malformed_rows = 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with trace_path.open("r", encoding="utf-8", newline="") as trace_file, (
        output_path.open("w", encoding="utf-8", newline="")
    ) as output_file:
        reader = csv.DictReader(trace_file)
        writer = csv.writer(output_file)
        writer.writerow(["pc", "address", "size"])

        for row in reader:
            rows_read += 1
            try:
                pc = int(row["instruction_pointer"], 0)
                address = int(row["memory_address"], 0)
                size = int(row["access_size"], 0)
                cache_hit = int(row["cache_hit"], 0)
            except (KeyError, TypeError, ValueError):
                malformed_rows += 1
                continue

            if cache_hit != 0:
                skipped_cache_hits += 1
                continue

            instruction_index = pc_to_index.get(pc)
            if instruction_index is None:
                skipped_missing_pc += 1
                continue

            row_lookback = (
                lookback_rng.randint(lookback_min, lookback_max)
                if lookback_rng is not None
                else lookback
            )
            if instruction_index < row_lookback:
                skipped_early_pc += 1
                continue

            hint_pc = pcs_by_index[instruction_index - row_lookback]
            writer.writerow([_format_hex(hint_pc), _format_hex(address), size])
            hints_written += 1

    return HintGenerationStats(
        rows_read=rows_read,
        hints_written=hints_written,
        skipped_cache_hits=skipped_cache_hits,
        skipped_missing_pc=skipped_missing_pc,
        skipped_early_pc=skipped_early_pc,
        malformed_rows=malformed_rows,
    )


def default_output_path(
    trace_path: Path,
    lookback: int,
    lookback_min: int | None = None,
    lookback_max: int | None = None,
    lookback_seed: int = 1,
) -> Path:
    if lookback_min is not None or lookback_max is not None:
        return (
            trace_path.parent
            / f"hints_pc{lookback_min}-{lookback_max}_seed{lookback_seed}.csv"
        )
    return trace_path.parent / f"hints_pc{lookback}.csv"


def _resolve_inputs(args: argparse.Namespace) -> tuple[Path, Path, Path]:
    if args.trace is not None:
        trace_path = args.trace.resolve()
    elif args.target is not None:
        trace_path = find_trace_file(args.target).resolve()
    else:
        raise ValueError("Provide a benchmark target or --trace.")

    if args.binary is not None:
        binary_path = args.binary.resolve()
    elif args.target is not None:
        binary_path = resolve_binary_path(args.target)
    else:
        raise ValueError("Provide --binary when using --trace without a benchmark.")

    output_path = (
        args.output.resolve()
        if args.output is not None
        else default_output_path(
            trace_path,
            args.lookback,
            args.lookback_min,
            args.lookback_max,
            args.lookback_seed,
        )
    )
    return trace_path, binary_path, output_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate chronological pc,address,size prefetch hints"
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="Benchmark name matching configs/crypto_multisim, e.g. sha256",
    )
    parser.add_argument("--trace", type=Path, help="Explicit trace CSV path")
    parser.add_argument("--binary", type=Path, help="Explicit benchmark binary")
    parser.add_argument("--output", type=Path, help="Output hint CSV path")
    parser.add_argument(
        "--lookback",
        type=int,
        default=DEFAULT_TRACE_LOOKBACK,
        help="Number of static objdump instructions to look back",
    )
    parser.add_argument(
        "--lookback-min",
        type=int,
        help="Minimum static objdump instructions to look back per row",
    )
    parser.add_argument(
        "--lookback-max",
        type=int,
        help="Maximum static objdump instructions to look back per row",
    )
    parser.add_argument(
        "--lookback-seed",
        type=int,
        default=1,
        help="Seed for random lookback selection",
    )
    parser.add_argument(
        "--objdump",
        default=DEFAULT_OBJDUMP,
        help="objdump executable to use",
    )
    args = parser.parse_args()

    random_lookback = (
        args.lookback_min is not None or args.lookback_max is not None
    )
    if random_lookback:
        if args.lookback_min is None or args.lookback_max is None:
            raise ValueError(
                "--lookback-min and --lookback-max must be provided together"
            )
        if args.lookback_min < 0 or args.lookback_max < 0:
            raise ValueError("--lookback-min/max must be non-negative")
        if args.lookback_min > args.lookback_max:
            raise ValueError("--lookback-min must be <= --lookback-max")
    elif args.lookback < 0:
        raise ValueError("--lookback must be non-negative")

    trace_path, binary_path, output_path = _resolve_inputs(args)
    instruction_pcs = disassemble_instruction_pcs(binary_path, args.objdump)
    stats = generate_hints_from_trace(
        trace_path=trace_path,
        instruction_pcs=instruction_pcs,
        output_path=output_path,
        lookback=args.lookback,
        lookback_min=args.lookback_min,
        lookback_max=args.lookback_max,
        lookback_seed=args.lookback_seed,
    )

    print(f"Trace: {trace_path}")
    print(f"Binary: {binary_path}")
    print(f"Output: {output_path}")
    if random_lookback:
        print(
            "Lookback: "
            f"random [{args.lookback_min}, {args.lookback_max}] "
            f"seed={args.lookback_seed}"
        )
    else:
        print(f"Lookback: fixed {args.lookback}")
    print(f"Rows read: {stats.rows_read}")
    print(f"Hints written: {stats.hints_written}")
    print(f"Skipped cache hits: {stats.skipped_cache_hits}")
    print(f"Skipped missing PCs: {stats.skipped_missing_pc}")
    print(f"Skipped early PCs: {stats.skipped_early_pc}")
    print(f"Malformed rows: {stats.malformed_rows}")


if __name__ == "__main__":
    main()
