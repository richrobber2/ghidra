// SPDX-License-Identifier: Apache-2.0
//! Preloaded header + program-table parse and shared observable-field checksum.
#![forbid(unsafe_code)]

use ghidra_elf_segments::{ParsePolicy, parse_program_headers};
use std::{
    env, fs,
    hint::black_box,
    time::{Duration, Instant},
};

const BATCH_PASSES: u64 = 16;
const MIX_CONSTANT: u64 = 0x9e37_79b9_7f4a_7c15;

fn mix(state: u64, value: u64) -> u64 {
    state.rotate_left(9).wrapping_add(value) ^ MIX_CONSTANT
}

#[inline(never)]
fn parse_digest(input: &[u8]) -> u64 {
    let table = parse_program_headers(input, ParsePolicy::GhidraCompatible)
        .expect("validated benchmark corpus");
    assert!(table.missing().is_none(), "benchmark table warning");
    let h = table.header();
    assert!(
        h.diagnostics.iter().next().is_none(),
        "benchmark header warning"
    );
    let mut x = 0;
    for field in [
        u64::from(h.class_bits),
        u64::from(h.header_little_endian),
        u64::from(h.declared_little_endian),
        u64::from(h.ident[7]),
        u64::from(h.ident[8]),
        u64::from(h.elf_type),
        u64::from(h.machine),
        u64::from(h.version),
        h.entry,
        h.phoff,
        h.shoff,
        u64::from(h.flags),
        u64::from(h.ehsize),
        u64::from(h.phentsize),
        u64::from(h.phnum),
        u64::from(h.shentsize),
        u64::from(h.shnum),
        u64::from(h.shstrndx),
    ] {
        x = mix(x, field);
    }
    for entry in table.iter() {
        // raw_offset is validated by the separate oracle, not a post-parse Java observable.
        for field in [
            u64::from(entry.segment_type),
            u64::from(entry.flags),
            entry.offset,
            entry.virtual_address,
            entry.physical_address,
            entry.file_size,
            entry.memory_size,
            entry.align,
        ] {
            x = mix(x, field);
        }
    }
    x
}

fn pass(inputs: &[Vec<u8>]) -> u64 {
    inputs.iter().fold(0_u64, |sum, input| {
        sum.wrapping_add(parse_digest(black_box(input.as_slice())))
    })
}

fn measure(inputs: &[Vec<u8>], minimum: Duration) -> String {
    let mut checksum = 0_u64;
    let mut passes = 0_u64;
    let start = Instant::now();
    let elapsed;
    loop {
        for _ in 0..BATCH_PASSES {
            checksum = checksum.wrapping_add(pass(inputs));
        }
        passes += BATCH_PASSES;
        black_box(checksum);
        let current = start.elapsed();
        if current >= minimum {
            elapsed = current;
            break;
        }
    }
    format!(
        "{{\"elapsed_ns\":{},\"passes\":{},\"parses\":{},\"checksum\":\"{}\"}}",
        elapsed.as_nanos(),
        passes,
        passes * inputs.len() as u64,
        checksum
    )
}

fn vm_hwm_kib() -> u64 {
    fs::read_to_string("/proc/self/status")
        .expect("Linux process status")
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .expect("Linux VmHWM")
        .split_whitespace()
        .next()
        .expect("VmHWM value")
        .parse()
        .expect("VmHWM integer")
}

fn main() {
    let args: Vec<String> = env::args().collect();
    assert!(args.len() >= 5, "warmup_ms sample_ms samples files...");
    let warmup_ms: u64 = args[1].parse().expect("warmup milliseconds");
    let sample_ms: u64 = args[2].parse().expect("sample milliseconds");
    let samples: usize = args[3].parse().expect("sample count");
    let inputs: Vec<Vec<u8>> = args[4..]
        .iter()
        .map(|file| {
            let input = fs::read(file).expect("input file");
            assert!(input.len() <= 64 * 1024 * 1024, "benchmark input too large");
            input
        })
        .collect();
    let mut corpus_checksum = 0_u64;
    let digests: Vec<String> = inputs
        .iter()
        .map(|input| {
            let value = parse_digest(input);
            corpus_checksum = corpus_checksum.wrapping_add(value);
            format!("\"{value}\"")
        })
        .collect();
    if warmup_ms > 0 {
        black_box(measure(&inputs, Duration::from_millis(warmup_ms)));
    }
    let results: Vec<String> = (0..samples)
        .map(|_| measure(&inputs, Duration::from_millis(sample_ms)))
        .collect();
    println!(
        "{{\"process_vm_hwm_kib\":{},\"corpus_checksum\":\"{}\",\"digests\":[{}],\"samples\":[{}]}}",
        vm_hwm_kib(),
        corpus_checksum,
        digests.join(","),
        results.join(",")
    );
}
