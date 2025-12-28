use std::env; // Access to command-line arguments and environment info
use std::fs;  // Access to filesystem functions (read files)
use std::collections::HashSet;
use sha2::{Digest,Sha256};
use sha1::Sha1;
use md5::Md5;

fn main() {
    // I collect all command-line arguments into a vector (list)
    let args: Vec<String> = env::args().collect();

    // args[0] -> program name
    // args[1] -> mode ("scan")
    // args[2] -> file path
    if args.len() < 3 {
        println!("Usage: rust_secscan scan <file_path>");
        return; // Stop the execution safely
    }

    // I borrow with (&) instead of copying — efficient and safe
    let mode = &args[1];

    // I borrow the file path argument
    let file_path = &args[2];

    // Anything else is rejected explicitly at this time
    if mode != "scan" {
        println!("Unsupported mode: {}", mode);
        return;
    }

    // Load IOC File
    let ioc_contents = match fs::read_to_string("iocs.txt") {
        Ok(data) => data,
        Err(err) => { 
            println!("Failed to load IOC file: {}", err);
            return
        }
    };

    // Store IOCs in sets for fast lookup
    let mut md5_iocs = HashSet::new();
    let mut sha1_iocs = HashSet::new();
    let mut sha256_iocs = HashSet::new();

    // Parse IOC lines
    for line in ioc_contents.lines() {
        if let Some((hash_type, value)) = line.split_once(':') {
            match hash_type {
                "md5" => { md5_iocs.insert(value.to_string()); }
                "sha1" => { sha1_iocs.insert(value.to_string()); }
                "sha256" => { sha256_iocs.insert(value.to_string());}
                _=> {} 
            }
        }
    }

    // I attempt to read the file as RAW BYTES
    // Ok(Vec<u8>)  -> file read successfully
    // Err(error)   -> something went wrong
    match fs::read(file_path) {
        Ok(bytes) => {
            // The bytes is a Vec<u8> — raw data from disk
            println!("File opened successfully");

            if bytes.len() == 0 {
                println!("File is empty - no hash computed");
                return;
            }

            println!("File size: {} bytes", bytes.len());

            // --- MD5 ---
            // I create a MD5 hasher
            let mut md5_hasher = Md5::new();
            
            // I then feed raw bytes into the hasher
            md5_hasher.update(&bytes);
            
            // I then finalize hash (Return fixed-size byte array)
            let md5_result = md5_hasher.finalize();
            
            // I then convert hash bytes to hex string
            let md5_hex = hex::encode(md5_result);

            // --- SHA1 ---
            let mut sha1_hasher = Sha1::new();
            sha1_hasher.update(&bytes);
            let sha1_result = sha1_hasher.finalize();
            let sha1_hex = hex::encode(sha1_result);
            
            // --- SHA256 ---
            let mut sha256_hasher = Sha256::new();
            sha256_hasher.update(&bytes);
            let sha256_result = sha256_hasher.finalize();
            let sha256_hex = hex::encode(sha256_result);
            
            // Prints the Hash values of the file
            println!("MD5:    {}",md5_hex);
            println!("SHA1:   {}",sha1_hex);
            println!("SHA256: {}", sha256_hex);

            // prints new line and then prompts for IOC compare check
            println!();
            println!("IOC Comparison");

            let mut matches = 0;

            if md5_iocs.contains(&md5_hex) {
                println!("MD5 MATCH");
                matches +=1;
            }

            if sha1_iocs.contains(&sha1_hex) {
                println!("SHA1 MATCH");
                matches +=1;
            }

            if sha256_iocs.contains(&sha256_hex) {
                println!("SHA256 MATCH");
                matches +=1;
            }

            match matches {
                0 => println!("VERDICT: NO MATCH"),
                1 => println!("VERDICT: PARTIAL MATCH"),
                _ => println!("VERDICT: CONFIRMED MATCH"),
            }
        }

        // if no file present or error, then prompts message
        Err(error) => {
            println!("Failed to open file: {}", error);
        }
    }
}
