use std::env;
use std::fs;
use std::collections::HashSet;
use std::process;

use sha2::{Digest, Sha256};
use sha1::Sha1;
use md5::Md5;

use serde::Serialize;

// ----------------------------
// Data structures
// ----------------------------

#[derive(Serialize)]
struct Hashes {
    md5: String,
    sha1: String,
    sha256: String,
}

#[derive(Serialize)]
struct Matches {
    md5: bool,
    sha1: bool,
    sha256: bool,
}

#[derive(Serialize)]
struct ScanResult {
    file: String,
    size: usize,
    hashes: Hashes,
    matches: Matches,
    verdict: String,
}

// ----------------------------
// Helper functions
// ----------------------------

fn hash_file(bytes: &[u8]) -> (String, String, String) {
    let mut md5_hasher = Md5::new();
    md5_hasher.update(bytes);
    let md5_hex = hex::encode(md5_hasher.finalize());

    let mut sha1_hasher = Sha1::new();
    sha1_hasher.update(bytes);
    let sha1_hex = hex::encode(sha1_hasher.finalize());

    let mut sha256_hasher = Sha256::new();
    sha256_hasher.update(bytes);
    let sha256_hex = hex::encode(sha256_hasher.finalize());

    (md5_hex, sha1_hex, sha256_hex)
}

fn load_iocs(path: &str) -> (HashSet<String>, HashSet<String>, HashSet<String>) {
    let contents = match fs::read_to_string(path) {
        Ok(data) => data,
        Err(err) => {
            println!("Failed to load IOC file: {}", err);
            return (HashSet::new(), HashSet::new(), HashSet::new());
        }
    };

    let mut md5_iocs = HashSet::new();
    let mut sha1_iocs = HashSet::new();
    let mut sha256_iocs = HashSet::new();

    for line in contents.lines() {
        if let Some((hash_type, value)) = line.split_once(':') {
            match hash_type {
                "md5" => { md5_iocs.insert(value.to_string()); }
                "sha1" => { sha1_iocs.insert(value.to_string()); }
                "sha256" => { sha256_iocs.insert(value.to_string()); }
                _ => {}
            }
        }
    }

    (md5_iocs, sha1_iocs, sha256_iocs)
}

fn determine_verdict(md5: bool, sha1: bool, sha256: bool) -> String {
    let match_count = md5 as u8 + sha1 as u8 + sha256 as u8;

    match match_count {
        0 => "NO_MATCH".to_string(),
        1 => "PARTIAL_MATCH".to_string(),
        _ => "CONFIRMED_MATCH".to_string(),
    }
}

fn verdict_exit_code(verdict: &str) -> i32 {
    match verdict {
        "NO_MATCH" => 0,
        "PARTIAL_MATCH" => 1,
        "CONFIRMED_MATCH" => 2,
        _ => 3,
    }
}

fn scan_file(
    file_path: &str,
    bytes: &[u8],
    md5_iocs: &HashSet<String>,
    sha1_iocs: &HashSet<String>,
    sha256_iocs: &HashSet<String>,
) -> ScanResult {
    let (md5_hex, sha1_hex, sha256_hex) = hash_file(bytes);

    let md5_match = md5_iocs.contains(&md5_hex);
    let sha1_match = sha1_iocs.contains(&sha1_hex);
    let sha256_match = sha256_iocs.contains(&sha256_hex);

    let verdict = determine_verdict(md5_match, sha1_match, sha256_match);

    ScanResult {
        file: file_path.to_string(),
        size: bytes.len(),
        hashes: Hashes {
            md5: md5_hex,
            sha1: sha1_hex,
            sha256: sha256_hex,
        },
        matches: Matches {
            md5: md5_match,
            sha1: sha1_match,
            sha256: sha256_match,
        },
        verdict,
    }
}

// ----------------------------
// Main
// ----------------------------

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        println!("Usage: rust-secscan scan <file1> [file2 ...] [--json]");
        process::exit(3);
    }

    let mode = &args[1];
    if mode != "scan" {
        println!("Unsupported mode: {}", mode);
        process::exit(3);
    }

    let json_output = args.contains(&"--json".to_string());

    let file_paths: Vec<&String> = args[2..]
        .iter()
        .filter(|arg| !arg.starts_with("--"))
        .collect();

    if file_paths.is_empty() {
        println!("No files specified.");
        process::exit(3);
    }

    let (md5_iocs, sha1_iocs, sha256_iocs) = load_iocs("iocs.txt");

    let mut highest_exit = 0;

    for file_path in file_paths {
        match fs::read(file_path) {
            Ok(bytes) => {
                if bytes.is_empty() {
                    continue;
                }

                let result = scan_file(
                    file_path,
                    &bytes,
                    &md5_iocs,
                    &sha1_iocs,
                    &sha256_iocs,
                );

                let exit_code = verdict_exit_code(&result.verdict);
                highest_exit = highest_exit.max(exit_code);

                if json_output {
                    let json = serde_json::to_string_pretty(&result).unwrap();
                    println!("{}", json);
                } else {
                    println!("File: {}", result.file);
                    println!("Size: {} bytes", result.size);
                    println!("MD5: {}", result.hashes.md5);
                    println!("SHA1: {}", result.hashes.sha1);
                    println!("SHA256: {}", result.hashes.sha256);
                    println!("Verdict: {}", result.verdict);
                    println!();
                }
            }

            Err(err) => {
                println!("Failed to open {}: {}", file_path, err);
                highest_exit = highest_exit.max(3);
            }
        }
    }

    process::exit(highest_exit);
}

