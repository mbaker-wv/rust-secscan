use std::env; // Access to command-line arguments and environment info
use std::fs;  // Access to filesystem functions (read files, etc.)

fn main() {
    // Collect all command-line arguments into a vector (list)
    let args: Vec<String> = env::args().collect();

    // We expect:
    // args[0] -> program name
    // args[1] -> mode ("scan")
    // args[2] -> file path
    if args.len() < 3 {
        println!("Usage: rust_secscan scan <file_path>");
        return; // Stop execution safely
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

            // bytes.len() = number of bytes in the file
            println!("File size: {} bytes", bytes.len());

            // Simple analysis using file size
            if bytes.len() == 0 {
                println!("File is empty");
            } else {
                println!("File contains data");
            }
        }

        Err(error) => {
            // Any error (missing file, permission issue, etc.)
            // is handled here instead of crashing
            println!("Failed to open file: {}", error);
        }
    }
}
