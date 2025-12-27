# rust-secscan

`rust-secscan` is a security-oriented file analysis utility written in Rust.  
This project is being developed incrementally as a way to learn Rust *by building a real tool*, not by doing disconnected examples.

The focus is correctness, safety, and understanding how low-level concepts like bytes, hashing, and error handling apply to real-world security workflows.

## Overview

At its core, `rust-secscan` reads files safely as raw bytes and computes cryptographic hashes commonly used in incident response and malware triage.

This project emphasizes:
- Explicit error handling
- A clear separation between text and bytes
- Predictable, deterministic behavior
- Clean, readable output suitable for security analysis

## Current Features

- Safe file reading using raw bytes (`Vec<u8>`)
- Explicit error handling using `Result`
- File hashing with:
  - **MD5** (legacy identifier)
  - **SHA-1** (legacy identifier)
  - **SHA-256** (primary integrity hash)
- Detection and handling of empty files
- Simple, readable console output

## Planned Features

Future development will expand the tool to include:

- Hash comparison against known IOCs
- Allow / deny verdicts
- Structured output (JSON / CSV)
- Modularization and refactoring
- Additional file analysis helpers

The goal is to evolve this into a small but realistic security utility.

## Why Rust?

Rust was chosen because it enforces many of the same principles required in security tooling:

- Memory safety without garbage collection
- Explicit handling of failure cases
- Strong type system that prevents unsafe assumptions
- Clear distinction between raw data (bytes) and interpreted data (text)

This project intentionally avoids shortcuts and emphasizes understanding *why* each step is necessary.

### Scan a file
```
cargo run -- scan <file_path>
```

### Security Notes
- MD5 and SHA-1 are included strictly for legacy identification and compatibility with existing IOC sources.
- SHA-256 is treated as the primary integrity hash.
- This tool does not attempt to make trust decisions yet — it provides accurate identifiers that can be used by other workflows.

### Disclaimer

This project is intended for educational and experimental use.
It is not a replacement for enterprise-grade malware analysis or antivirus software.
