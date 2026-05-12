#!/usr/bin/env python3
"""
Parse and display ElasticTrace protobuf data from gem5 simulations.

Usage:
  python3 parse_traces.py <benchmark> [--fetch|--dep] [--records N]

Examples:
  python3 parse_traces.py kyber768                    # Show both traces, 10 records each
  python3 parse_traces.py kyber768 --fetch --records 5  # Show 5 fetch trace records
  python3 parse_traces.py sha256 --dep --records 20    # Show 20 dependency trace records
"""

import argparse
import gzip
import sys
from pathlib import Path

# Add gem5 proto directory to path
GEM5_ROOT = Path(__file__).resolve().parent.parent.parent
SRC_PROTO = GEM5_ROOT / "src" / "proto"
sys.path.insert(0, str(SRC_PROTO))

import io

import inst_dep_record_pb2
import inst_pb2
import packet_pb2
from google.protobuf.internal.decoder import _DecodeVarint
from google.protobuf.internal.encoder import _EncodeVarint

M5OUT_ROOT = GEM5_ROOT / "m5out"


def trace_output_dir(benchmark_name: str) -> Path:
    """Prefer the fullmem output directory, fall back to the legacy etrace dir."""
    fullmem_dir = M5OUT_ROOT / f"crypto_{benchmark_name}_etrace_fullmem"
    if fullmem_dir.exists():
        return fullmem_dir
    legacy_dir = M5OUT_ROOT / f"crypto_{benchmark_name}_etrace"
    return legacy_dir


# MemCmd::Command values from src/mem/packet.hh
MEM_CMD_NAMES = {
    0: "InvalidCmd",
    1: "ReadReq",
    2: "ReadResp",
    3: "ReadRespWithInvalidate",
    4: "WriteReq",
    5: "WriteResp",
    6: "WriteCompleteResp",
    7: "WritebackDirty",
    8: "WritebackClean",
    9: "WriteClean",
    10: "CleanEvict",
    11: "SoftPFReq",
    12: "SoftPFExReq",
    13: "HardPFReq",
    14: "SoftPFResp",
    15: "HardPFResp",
    16: "WriteLineReq",
    17: "UpgradeReq",
    18: "SCUpgradeReq",
    19: "UpgradeResp",
    20: "SCUpgradeFailReq",
    21: "UpgradeFailResp",
    22: "ReadExReq",
    23: "ReadExResp",
    24: "ReadCleanReq",
    25: "ReadSharedReq",
    26: "LoadLockedReq",
    27: "StoreCondReq",
    28: "StoreCondFailReq",
    29: "StoreCondResp",
    30: "LockedRMWReadReq",
    31: "LockedRMWReadResp",
    32: "LockedRMWWriteReq",
    33: "LockedRMWWriteResp",
    34: "SwapReq",
    35: "SwapResp",
    38: "MemFenceReq",
    39: "MemSyncReq",
    40: "MemSyncResp",
    41: "MemFenceResp",
    42: "CleanSharedReq",
    43: "CleanSharedResp",
    44: "CleanInvalidReq",
    45: "CleanInvalidResp",
    46: "InvalidDestError",
    47: "BadAddressError",
    48: "ReadError",
    49: "WriteError",
    50: "FunctionalReadError",
    51: "FunctionalWriteError",
    52: "PrintReq",
    53: "FlushReq",
    54: "InvalidateReq",
    55: "InvalidateResp",
    56: "HTMReq",
    57: "HTMReqResp",
    58: "HTMAbort",
    59: "TlbiExtSync",
}

# Request::Flags values from src/mem/request.hh
REQUEST_FLAG_NAMES = [
    (0x00000100, "INST_FETCH"),
    (0x00000200, "PHYSICAL"),
    (0x00000400, "UNCACHEABLE"),
    (0x00000800, "STRICT_ORDER"),
    (0x00008000, "PRIVILEGED"),
    (0x00010000, "CACHE_BLOCK_ZERO"),
    (0x00080000, "NO_ACCESS"),
    (0x00100000, "LOCKED_RMW"),
    (0x00200000, "LLSC"),
    (0x00400000, "MEM_SWAP"),
    (0x00800000, "MEM_SWAP_COND"),
    (0x01000000, "PREFETCH"),
    (0x02000000, "PF_EXCLUSIVE"),
    (0x04000000, "EVICT_NEXT"),
    (0x00020000, "ACQUIRE"),
    (0x00002000, "ACQUIRE_PC"),
    (0x00040000, "RELEASE"),
    (0x40000000, "ATOMIC_RETURN_OP"),
    (0x80000000, "ATOMIC_NO_RETURN_OP"),
    (0x00001000, "KERNEL"),
    (0x10000000, "SECURE"),
    (0x0020000000000000, "READ_MODIFY_WRITE"),
]


def cmd_name(cmd_value):
    return MEM_CMD_NAMES.get(cmd_value, f"Cmd({cmd_value})")


def cmd_rw(cmd_value):
    name = cmd_name(cmd_value)
    if "Read" in name or name in {
        "LoadLockedReq",
        "SoftPFReq",
        "SoftPFExReq",
        "HardPFReq",
    }:
        return "R"
    if "Write" in name or name in {
        "StoreCondReq",
        "SwapReq",
        "CleanInvalidReq",
        "CleanSharedReq",
    }:
        return "W"
    return "-"


def decode_request_flags(flag_value):
    active = [
        name for bit, name in REQUEST_FLAG_NAMES if (flag_value & bit) != 0
    ]
    return "|".join(active) if active else "-"


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
    """Skip the gem5 magic number (0x356d6567 = 'gem5' in little-endian)."""
    magic = stream.read(4)
    if magic != b"gem5":
        # Try reversed
        if magic == b"5meg":
            pass  # Already skipped
        else:
            print(f"Warning: Unexpected magic number: {magic.hex()}")
    return True


def parse_fetchtrace(benchmark_name, max_records=10):
    """Parse and display fetchtrace packet data."""
    trace_dir = trace_output_dir(benchmark_name)
    trace_file_gz = (
        trace_dir
        / "board.processor.cores.core.traceListener.fetchtrace.proto.gz"
    )
    trace_file = (
        trace_dir / "board.processor.cores.core.traceListener.fetchtrace.proto"
    )

    # Try gzipped first, then uncompressed
    if trace_file_gz.exists():
        trace_file = trace_file_gz
        is_gzipped = True
    elif trace_file.exists():
        is_gzipped = False
    else:
        print(f"Fetchtrace file not found: {trace_file} or {trace_file_gz}")
        return

    print(f"\n{'='*80}")
    print(
        f"FETCHTRACE: {benchmark_name} {'(gzipped)' if is_gzipped else '(uncompressed)'}"
    )
    print(f"{'='*80}")

    if is_gzipped:
        f = gzip.open(trace_file, "rb")
    else:
        f = open(trace_file, "rb")

    try:
        # Skip magic number
        skip_magic_number(f)

        # Read header
        header = read_message(f, packet_pb2.PacketHeader)
        if header:
            print(f"Header:")
            print(f"  obj_id:    {header.obj_id}")
            print(f"  tick_freq: {header.tick_freq}")
            print()

        # Read records
        record_count = 0
        print(f"First {max_records} fetch packet records:")
        print(
            f"{'#':<5} {'Tick':<15} {'Cmd':<5} {'CmdName':<20} {'R/W':<4} "
            f"{'Addr':<18} {'Size':<6} {'Flags':<10} {'PC':<18} {'FlagNames'}"
        )
        print("-" * 170)

        while record_count < max_records:
            pkt = read_message(f, packet_pb2.Packet)
            if pkt is None:
                break

            tick_str = str(pkt.tick) if pkt.HasField("tick") else "N/A"
            cmd_str = str(pkt.cmd) if pkt.HasField("cmd") else "N/A"
            cmd_name_str = cmd_name(pkt.cmd) if pkt.HasField("cmd") else "N/A"
            rw_str = cmd_rw(pkt.cmd) if pkt.HasField("cmd") else "N/A"
            addr_str = f"0x{pkt.addr:x}" if pkt.HasField("addr") else "N/A"
            size_str = str(pkt.size) if pkt.HasField("size") else "N/A"
            flags_str = f"0x{pkt.flags:x}" if pkt.HasField("flags") else "N/A"
            flag_names = (
                decode_request_flags(pkt.flags)
                if pkt.HasField("flags")
                else "N/A"
            )
            pc_str = f"0x{pkt.pc:x}" if pkt.HasField("pc") else "N/A"

            print(
                f"{record_count:<5} {tick_str:<15} {cmd_str:<5} {cmd_name_str:<20} "
                f"{rw_str:<4} {addr_str:<18} {size_str:<6} {flags_str:<10} "
                f"{pc_str:<18} {flag_names}"
            )
            record_count += 1

        print(f"\nTotal records read: {record_count}")
    finally:
        f.close()


def parse_deptrace(benchmark_name, max_records=10):
    """Parse and display data dependency trace."""
    trace_dir = trace_output_dir(benchmark_name)
    trace_file_gz = (
        trace_dir
        / "board.processor.cores.core.traceListener.deptrace.proto.gz"
    )
    trace_file = (
        trace_dir / "board.processor.cores.core.traceListener.deptrace.proto"
    )

    # Try gzipped first, then uncompressed
    if trace_file_gz.exists():
        trace_file = trace_file_gz
        is_gzipped = True
    elif trace_file.exists():
        is_gzipped = False
    else:
        print(f"Deptrace file not found: {trace_file} or {trace_file_gz}")
        return

    print(f"\n{'='*80}")
    print(
        f"DEPTRACE: {benchmark_name} {'(gzipped)' if is_gzipped else '(uncompressed)'}"
    )
    print(f"{'='*80}")

    if is_gzipped:
        f = gzip.open(trace_file, "rb")
    else:
        f = open(trace_file, "rb")

    try:
        # Skip magic number
        skip_magic_number(f)

        # Read header
        header = read_message(f, inst_dep_record_pb2.InstDepRecordHeader)
        if header:
            print(f"Header:")
            print(f"  obj_id:      {header.obj_id}")
            print(f"  tick_freq:   {header.tick_freq}")
            print(f"  window_size: {header.window_size}")
            print()

        # Read records
        record_count = 0
        record_types = {
            0: "INVALID",
            1: "LOAD",
            2: "STORE",
            3: "COMP",
        }

        print(f"First {max_records} dependency records:")
        print(
            f"{'#':<5} {'SeqNum':<12} {'Type':<8} {'PC':<18} {'PAddr':<18} "
            f"{'Size':<5} {'ROBDeps':<10} {'RegDeps':<10}"
        )
        print("-" * 100)

        while record_count < max_records:
            rec = read_message(f, inst_dep_record_pb2.InstDepRecord)
            if rec is None:
                break

            rec_type = record_types.get(rec.type, f"UNKNOWN({rec.type})")
            pc_str = f"0x{rec.pc:x}" if rec.HasField("pc") else "N/A"
            paddr_str = (
                f"0x{rec.p_addr:x}" if rec.HasField("p_addr") else "N/A"
            )
            size_str = str(rec.size) if rec.HasField("size") else "N/A"
            rob_deps = len(rec.rob_dep) if rec.rob_dep else 0
            reg_deps = len(rec.reg_dep) if rec.reg_dep else 0

            print(
                f"{record_count:<5} {rec.seq_num:<12} {rec_type:<8} {pc_str:<18} "
                f"{paddr_str:<18} {size_str:<5} {rob_deps:<10} {reg_deps:<10}"
            )

            # Show dependencies if any
            if rec.rob_dep or rec.reg_dep:
                if rec.rob_dep:
                    print(
                        f"    ROB dependencies: {', '.join(map(str, rec.rob_dep[:5]))}"
                    )
                    if len(rec.rob_dep) > 5:
                        print(
                            f"                     ... and {len(rec.rob_dep) - 5} more"
                        )
                if rec.reg_dep:
                    print(
                        f"    Reg dependencies: {', '.join(map(str, rec.reg_dep[:5]))}"
                    )
                    if len(rec.reg_dep) > 5:
                        print(
                            f"                     ... and {len(rec.reg_dep) - 5} more"
                        )

            record_count += 1

        print(f"\nTotal records read: {record_count}")
    finally:
        f.close()


def main():
    parser = argparse.ArgumentParser(
        description="Parse gem5 ElasticTrace protobuf files"
    )
    parser.add_argument(
        "benchmark", help="Benchmark name (e.g., kyber768, sha256)"
    )
    parser.add_argument(
        "--fetch", action="store_true", help="Parse fetchtrace only"
    )
    parser.add_argument(
        "--dep", action="store_true", help="Parse deptrace only"
    )
    parser.add_argument(
        "--records",
        type=int,
        default=10,
        help="Number of records to display (default: 10)",
    )

    args = parser.parse_args()

    # If neither is specified, show both
    show_both = not args.fetch and not args.dep

    if args.fetch or show_both:
        parse_fetchtrace(args.benchmark, args.records)

    if args.dep or show_both:
        parse_deptrace(args.benchmark, args.records)


if __name__ == "__main__":
    main()
