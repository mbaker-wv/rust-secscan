use std::env; // Access to command-line arguments and environment info
use std::fs;  // Access to filesystem functions (read files, etc.)

use sha2::{Digest,Sha256};
use sha1::Sha1;
use md5::Md5;

fn main() {
    // Collect all command-line arguments into a vector (list)
    let args: Vec<String> = env::args().collect();

    // We expect:
    // args[0] -> program name
    // args[1] -> mode ("scan")
    // args[2] -> file path
    if args.len() < 3 {
        println!("Usage: rust_secscan scan <file_path>");
        return; // Stop the execution safely
    }

    // Borrow the mode argument ("scan")
    // We borrow (&) instead of copying — efficient and safe
    let mode = &args[1];

    // Borrow the file path argument ("test.txt")
    let file_path = &args[2];

    // Only "scan" mode is supported right now
    // Anything else is rejected explicitly
    if mode != "scan" {
        println!("Unsupported mode: {}", mode);
        return;
    }

    // Attempt to read the file as RAW BYTES
    // This returns:
    // Ok(Vec<u8>)  -> file read successfully
    // Err(error)   -> something went wrong
    match fs::read(file_path) {
        Ok(bytes) => {
            // bytes is a Vec<u8> — raw data from disk
            println!("File opened successfully");

            if bytes.len() == 0 {
                println!("File is empty - no hash computed");
                return;
            }

            println!("File size: {} bytes", bytes.len());

            // --- MD5 ---
            let mut md5_hasher = Md5::new();
            md5_hasher.update(&bytes);
            let md5_result = md5_hasher.finalize();
            let md5_hex = hex::encode(md5_result);

            // --- SHA1 ---
            let mut sha1_hasher = Sha1::new();
            sha1_hasher.update(&bytes);
            let sha1_result = sha1_hasher.finalize();
            let sha1_hex = hex::encode(sha1_result);

            // Create a SHA-256 hasher
            let mut hasher = Sha256::new();

            // Feed raw bytes into the hasher
            hasher.update(&bytes);

            // Finalize hash (Return fixed-size byte array)
            let digest = hasher.finalize();

            // Convert hash bytes to hex string
            let hash_hex = hex::encode(digest);
            
            println!("MD5:    {}",md5_hex);
            println!("SHA1:   {}",sha1_hex);
            println!("SHA256: {}", hash_hex);
        }
        Err(error) => {
            println!("Failed to open file: {}", error);
        }
    }
}
