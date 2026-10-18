//! Compatible header decoding plus observable normalized-field digest only.
use ghidra_elf::{ParsePolicy, ParsedHeader, parse_header};
use std::{
    env, fs,
    hint::black_box,
    time::{Duration, Instant},
};

const BATCH_PASSES: u64 = 256;

fn digest(h: &ParsedHeader) -> u64 {
    u64::from(h.class_bits)
        ^ u64::from(h.header_little_endian).rotate_left(1)
        ^ u64::from(h.declared_little_endian).rotate_left(2)
        ^ u64::from(h.elf_type).rotate_left(3)
        ^ u64::from(h.machine).rotate_left(7)
        ^ u64::from(h.version).rotate_left(11)
        ^ h.entry.rotate_left(13)
        ^ h.phoff.rotate_left(17)
        ^ h.shoff.rotate_left(19)
        ^ u64::from(h.flags).rotate_left(23)
        ^ u64::from(h.ehsize).rotate_left(29)
        ^ u64::from(h.phentsize).rotate_left(31)
        ^ u64::from(h.phnum).rotate_left(37)
        ^ u64::from(h.shentsize).rotate_left(41)
        ^ u64::from(h.shnum).rotate_left(43)
        ^ u64::from(h.shstrndx).rotate_left(47)
}

fn pass(inputs: &[Vec<u8>]) -> u64 {
    let mut checksum = 0_u64;
    for input in inputs {
        let header = parse_header(black_box(input.as_slice()), ParsePolicy::GhidraCompatible)
            .expect("validated benchmark corpus");
        checksum = checksum.wrapping_add(digest(black_box(&header)));
    }
    checksum
}

fn peak_rss_kib() -> u64 {
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

fn main() {
    let args: Vec<String> = env::args().collect();
    assert!(args.len() >= 5, "warmup_ms sample_ms samples files...");
    let warmup_ms: u64 = args[1].parse().expect("warmup milliseconds");
    let sample_ms: u64 = args[2].parse().expect("sample milliseconds");
    let samples: usize = args[3].parse().expect("sample count");
    let inputs: Vec<Vec<u8>> = args[4..]
        .iter()
        .map(|file| fs::read(file).expect("input file"))
        .collect();
    let mut corpus_checksum = 0_u64;
    let digests: Vec<String> = inputs
        .iter()
        .map(|input| {
            let header =
                parse_header(input, ParsePolicy::GhidraCompatible).expect("benchmark corpus");
            let digest = digest(&header);
            corpus_checksum = corpus_checksum.wrapping_add(digest);
            format!("\"{digest}\"")
        })
        .collect();
    if warmup_ms > 0 {
        black_box(measure(&inputs, Duration::from_millis(warmup_ms)));
    }
    let results: Vec<String> = (0..samples)
        .map(|_| measure(&inputs, Duration::from_millis(sample_ms)))
        .collect();
    let peak_rss_kib = peak_rss_kib();
    println!(
        "{{\"process_vm_hwm_kib\":{},\"corpus_checksum\":\"{}\",\"digests\":[{}],\"samples\":[{}]}}",
        peak_rss_kib,
        corpus_checksum,
        digests.join(","),
        results.join(",")
    );
}
