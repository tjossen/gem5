#!/usr/bin/env python3
"""
Analyze gem5 ElasticTrace protobuf data and provide statistics.

Usage:
  python3 analyze_traces.py <benchmark> [--fetch|--dep]

Examples:
  python3 analyze_traces.py kyber768
  python3 analyze_traces.py sha256 --dep
"""

import argparse
import gzip
import sys
from collections import (
    Counter,
    defaultdict,
)
from pathlib import Path

# Add gem5 proto directory to path
GEM5_ROOT = Path(__file__).resolve().parent.parent.parent
SRC_PROTO = GEM5_ROOT / "src" / "proto"
sys.path.insert(0, str(SRC_PROTO))

import inst_dep_record_pb2
import packet_pb2
from google.protobuf.internal.decoder import _DecodeVarint

M5OUT_ROOT = GEM5_ROOT / "m5out"


def trace_output_dir(benchmark_name: str) -> Path:
    """Prefer the fullmem output directory, fall back to the legacy etrace dir."""
    fullmem_dir = M5OUT_ROOT / f"crypto_{benchmark_name}_etrace_fullmem"
    if fullmem_dir.exists():
        return fullmem_dir
    legacy_dir = M5OUT_ROOT / f"crypto_{benchmark_name}_etrace"
    return legacy_dir


# MemCmd::Command values from src/mem/packet.hh
READ_CMDS = {
    1,  # ReadReq
    11,  # SoftPFReq
    12,  # SoftPFExReq
    13,  # HardPFReq
    22,  # ReadExReq
    24,  # ReadCleanReq
    25,  # ReadSharedReq
    26,  # LoadLockedReq
    30,  # LockedRMWReadReq
}

WRITE_CMDS = {
    4,  # WriteReq
    16,  # WriteLineReq
    27,  # StoreCondReq
    32,  # LockedRMWWriteReq
    34,  # SwapReq
    42,  # CleanSharedReq
    44,  # CleanInvalidReq
    54,  # InvalidateReq
}


def read_varint(stream):
    """Read a varint-encoded length from stream."""
    buf = b""
    while True:
        byte = stream.read(1)
        if not byte:
            return None
        buf += byte
        if not (byte[0] & 0x80):
            break
    return _DecodeVarint(buf, 0)[0]


def read_message(stream, message_class):
    """Read a single protobuf message from stream."""
    length = read_varint(stream)
    if length is None:
        return None
    data = stream.read(length)
    if len(data) < length:
        return None
    msg = message_class()
    msg.ParseFromString(data)
    return msg


def skip_magic_number(stream):
    """Skip the gem5 magic number."""
    magic = stream.read(4)
    return magic == b"gem5"


def analyze_fetchtrace(benchmark_name):
    """Analyze fetchtrace statistics."""
    trace_dir = trace_output_dir(benchmark_name)
    trace_file_gz = (
        trace_dir
        / "board.processor.cores.core.traceListener.fetchtrace.proto.gz"
    )
    trace_file = (
        trace_dir / "board.processor.cores.core.traceListener.fetchtrace.proto"
    )

    if trace_file_gz.exists():
        f = gzip.open(trace_file_gz, "rb")
        is_gzipped = True
    elif trace_file.exists():
        f = open(trace_file, "rb")
        is_gzipped = False
    else:
        print(f"Fetchtrace file not found")
        return

    try:
        skip_magic_number(f)
        header = read_message(f, packet_pb2.PacketHeader)

        print(f"\n{'='*80}")
        print(f"FETCHTRACE ANALYSIS: {benchmark_name}")
        print(f"{'='*80}\n")

        # Collect statistics
        addrs = Counter()
        record_count = 0
        read_count = 0
        write_count = 0
        other_cmd_count = 0

        print("Analyzing records (this may take a moment)...")
        while True:
            pkt = read_message(f, packet_pb2.Packet)
            if pkt is None:
                break

            record_count += 1
            if record_count % 1000000 == 0:
                print(f"  ... processed {record_count} records")

            if pkt.HasField("addr"):
                addrs[pkt.addr] += 1

            if pkt.HasField("cmd"):
                if pkt.cmd in READ_CMDS:
                    read_count += 1
                elif pkt.cmd in WRITE_CMDS:
                    write_count += 1
                else:
                    other_cmd_count += 1

        print(f"\nStatistics:")
        print(f"  Total fetch packets: {record_count}")
        print(f"  Total reads: {read_count}")
        print(f"  Total writes: {write_count}")
        print(f"  Other/unknown cmd packets: {other_cmd_count}")
        print(f"  Unique addresses: {len(addrs)}")

        if addrs:
            top_addrs = addrs.most_common(10)
            print(f"\n  Top 10 most requested addresses:")
            for addr, count in top_addrs:
                pct = 100.0 * count / record_count
                print(f"    0x{addr:x}: {count} times ({pct:.2f}%)")

    finally:
        f.close()


def analyze_deptrace(benchmark_name):
    """Analyze dependency trace statistics."""
    trace_dir = trace_output_dir(benchmark_name)
    trace_file_gz = (
        trace_dir
        / "board.processor.cores.core.traceListener.deptrace.proto.gz"
    )
    trace_file = (
        trace_dir / "board.processor.cores.core.traceListener.deptrace.proto"
    )

    if trace_file_gz.exists():
        f = gzip.open(trace_file_gz, "rb")
        is_gzipped = True
    elif trace_file.exists():
        f = open(trace_file, "rb")
        is_gzipped = False
    else:
        print(f"Deptrace file not found")
        return

    try:
        skip_magic_number(f)
        header = read_message(f, inst_dep_record_pb2.InstDepRecordHeader)

        print(f"\n{'='*80}")
        print(f"DEPTRACE ANALYSIS: {benchmark_name}")
        print(f"{'='*80}\n")

        # Collect statistics
        record_types = defaultdict(int)
        pcs = Counter()
        record_count = 0
        rob_dep_counts = Counter()
        reg_dep_counts = Counter()
        total_rob_deps = 0
        total_reg_deps = 0
        comp_delays = []

        print("Analyzing records (this may take a moment)...")
        while True:
            rec = read_message(f, inst_dep_record_pb2.InstDepRecord)
            if rec is None:
                break

            record_count += 1
            if record_count % 100000 == 0:
                print(f"  ... processed {record_count} records")

            # Record type stats
            record_types[rec.type] += 1

            if rec.HasField("pc"):
                pcs[rec.pc] += 1

            # Dependency stats
            if rec.rob_dep:
                rob_dep_counts[len(rec.rob_dep)] += 1
                total_rob_deps += len(rec.rob_dep)

            if rec.reg_dep:
                reg_dep_counts[len(rec.reg_dep)] += 1
                total_reg_deps += len(rec.reg_dep)

            if rec.HasField("comp_delay"):
                comp_delays.append(rec.comp_delay)

        type_names = {0: "INVALID", 1: "LOAD", 2: "STORE", 3: "COMP"}
        print(f"\nStatistics:")
        print(f"  Total records: {record_count}")
        print(f"\n  Record types:")
        for rtype in sorted(record_types.keys()):
            count = record_types[rtype]
            pct = 100.0 * count / record_count
            print(
                f"    {type_names.get(rtype, f'UNKNOWN({rtype})')}: {count} ({pct:.2f}%)"
            )

        print(f"\n  Unique PCs: {len(pcs)}")
        if pcs:
            top_pcs = pcs.most_common(5)
            print(f"    Top 5:")
            for pc, count in top_pcs:
                pct = 100.0 * count / record_count
                print(f"      0x{pc:x}: {count} times ({pct:.2f}%)")

        print(f"\n  Register dependencies:")
        print(f"    Total: {total_reg_deps}")
        print(f"    Average per record: {total_reg_deps / record_count:.2f}")
        if reg_dep_counts:
            print(f"    Distribution: {dict(sorted(reg_dep_counts.items()))}")

        print(f"\n  ROB dependencies:")
        print(f"    Total: {total_rob_deps}")
        print(f"    Average per record: {total_rob_deps / record_count:.2f}")
        if rob_dep_counts:
            print(f"    Distribution: {dict(sorted(rob_dep_counts.items()))}")

        if comp_delays:
            print(f"\n  Computational delays:")
            print(f"    Min: {min(comp_delays)}")
            print(f"    Max: {max(comp_delays)}")
            print(f"    Avg: {sum(comp_delays) / len(comp_delays):.2f}")

    finally:
        f.close()


def main():
    parser = argparse.ArgumentParser(
        description="Analyze gem5 ElasticTrace data"
    )
    parser.add_argument("benchmark", help="Benchmark name (e.g., kyber768)")
    parser.add_argument(
        "--fetch", action="store_true", help="Analyze fetchtrace only"
    )
    parser.add_argument(
        "--dep", action="store_true", help="Analyze deptrace only"
    )

    args = parser.parse_args()

    # If neither is specified, show both
    show_both = not args.fetch and not args.dep

    if args.fetch or show_both:
        analyze_fetchtrace(args.benchmark)

    if args.dep or show_both:
        analyze_deptrace(args.benchmark)


if __name__ == "__main__":
    main()
