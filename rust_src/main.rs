//! chainproof CLI — SLSA supply chain attestation verifier.
//!
//! Usage:
//!   chainproof --version
//!   chainproof verify --artifact <PATH> --statement <JSON_FILE>
//!
//! Exit codes:
//!   0  — verification succeeded (digest match, SLSA level reported)
//!   1  — verification failed (digest mismatch or attestation error)
//!   2  — bad arguments / usage error

use chainproof_lib::{verify_artifact, VerificationResult};
use std::{env, fs, process};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const NAME:    &str = env!("CARGO_PKG_NAME");

fn usage() -> ! {
    eprintln!(
        "Usage:\n  {NAME} --version\n  {NAME} verify --artifact <PATH> --statement <JSON_FILE>"
    );
    process::exit(2);
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        usage();
    }

    match args[1].as_str() {
        "--version" | "-V" => {
            println!("{NAME} {VERSION}");
            process::exit(0);
        }
        "verify" => run_verify(&args[2..]),
        _ => usage(),
    }
}

fn run_verify(args: &[String]) {
    let mut artifact_path: Option<&str> = None;
    let mut statement_file: Option<&str> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--artifact" => {
                i += 1;
                artifact_path = args.get(i).map(String::as_str);
            }
            "--statement" => {
                i += 1;
                statement_file = args.get(i).map(String::as_str);
            }
            other => {
                eprintln!("Unknown flag: {other}");
                usage();
            }
        }
        i += 1;
    }

    let artifact_path = artifact_path.unwrap_or_else(|| {
        eprintln!("Missing --artifact");
        usage();
    });

    let statement_file = statement_file.unwrap_or_else(|| {
        eprintln!("Missing --statement");
        usage();
    });

    // Read the statement JSON file.
    let statement_json = fs::read_to_string(statement_file).unwrap_or_else(|e| {
        eprintln!("Cannot read statement file '{statement_file}': {e}");
        process::exit(2);
    });

    let result: VerificationResult = verify_artifact(artifact_path, &statement_json);

    // Pretty-print result as JSON to stdout.
    let output = serde_json::to_string_pretty(&result).unwrap_or_else(|e| {
        eprintln!("Serialization error: {e}");
        process::exit(2);
    });
    println!("{output}");

    if result.digest_match {
        process::exit(0);
    } else {
        process::exit(1);
    }
}
