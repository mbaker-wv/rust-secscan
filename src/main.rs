use std::env; // Command-line arguments
use std::fs;  // File system access
use std::collections::HashSet;

use sha2::{Digest, Sha256};
use sha1::Sha1;
use md5::Md5;

use serde::Serialize;

// ----------------------------
// Data structures for JSON output
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
    // MD5
    let mut md5_hasher = Md5::new();
    md5_hasher.update(bytes);
    let md5_hex = hex::encode(md5_hasher.finalize());

    // SHA1
    let mut sha1_hasher = Sha1::new();
    sha1_hasher.update(bytes);
    let sha1_hex = hex::encode(sha1_hasher.finalize());

    // SHA256
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

// ----------------------------
// Main
// ----------------------------

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        println!("Usage: rust_secscan scan <file_path>");
        return;
    }

    let mode = &args[1];
    let file_path = &args[2];

    if mode != "scan" {
        println!("Unsupported mode: {}", mode);
        return;
    }

    // Load IOC lists
    let (md5_iocs, sha1_iocs, sha256_iocs) = load_iocs("iocs.txt");

    // Read target file as raw bytes
    match fs::read(file_path) {
        Ok(bytes) => {
            if bytes.is_empty() {
                println!("File is empty - no hash computed");
                return;
            }

            let (md5_hex, sha1_hex, sha256_hex) = hash_file(&bytes);

            let md5_match = md5_iocs.contains(&md5_hex);
            let sha1_match = sha1_iocs.contains(&sha1_hex);
            let sha256_match = sha256_iocs.contains(&sha256_hex);

            let match_count =
                md5_match as u8 + sha1_match as u8 + sha256_match as u8;

            let verdict = match match_count {
                0 => "NO_MATCH",
                1 => "PARTIAL_MATCH",
                _ => "CONFIRMED_MATCH",
            }.to_string();

            let result = ScanResult {
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
            };

            let json = serde_json::to_string_pretty(&result).unwrap();
            println!("{}", json);
        }

        Err(error) => {
            println!("Failed to open file: {}", error);
        }
    }
}
