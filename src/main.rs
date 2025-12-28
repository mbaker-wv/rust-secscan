use std::env; // Access to command-line arguments and environment info
use std::fs;  // Access to filesystem functions (read files)
use sha2::{Digest,Sha256};
use sha1::Sha1;
use md5::Md5;

const BAD_MD5: &str = "5d41402abc4b2a76b9719d911017c592";
const BAD_SHA1: &str = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";
const BAD_SHA256: &str = "3615f80c9d293ed7402687f94b22d58e529b8cc7916f8fac7fddf7fbd5af4cf0";

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
            // I create a SHA-256 hasher
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

            // sets the 'matched' var to false by default and marks it that it may change
            let mut matched = false;

            // start of the 'if' statements that check the known bad hashs to the hex of the file.
            if md5_hex == BAD_MD5 {
                println!("MD5 MATCH");
                matched = true;
            }

            if sha1_hex == BAD_SHA1 {
                println!("SHA1 MATCH");
                matched = true;
            }
            
            if sha256_hex == BAD_SHA256 {
                println!("SHA256 MATCH");
                matched = true;
            }

            if matched {
                println!("VERDICT: MATCHED (known bad file)");
            }   
            
            // if no hashes match then print no match
            else {
                println!("VERDICT: NO MATCH");
            }
        }

        // if no file present or error, then prompts message
        Err(error) => {
            println!("Failed to open file: {}", error);
        }
    }
}
