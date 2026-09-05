//! chainproof CLI — SLSA attestation verifier
use std::process;
use chainproof_lib::verify_artifact;

fn usage() {
    eprintln!("chainproof v0.1.0 — SLSA Supply Chain Attestation Verifier");
    eprintln!("");
    eprintln!("USAGE:");
    eprintln!("  chainproof verify --artifact <path> --statement <json_file>");
    eprintln!("  chainproof --version");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 { usage(); process::exit(2); }

    match args[1].as_str() {
        "--version" => {
            println!("chainproof 0.1.0 (rust)");
            process::exit(0);
        }
        "verify" => {
            let artifact = args.iter().position(|a| a == "--artifact")
                .and_then(|i| args.get(i + 1))
                .unwrap_or_else(|| { usage(); process::exit(2); });
            let stmt_path = args.iter().position(|a| a == "--statement")
                .and_then(|i| args.get(i + 1))
                .unwrap_or_else(|| { usage(); process::exit(2); });

            let json = std::fs::read_to_string(stmt_path)
                .unwrap_or_else(|e| { eprintln!("Error reading statement: {}", e); process::exit(2); });

            match verify_artifact(artifact, &json) {
                Ok(result) => {
                    println!("{}", serde_json::to_string_pretty(&result).unwrap());
                    process::exit(if result.digest_match { 0 } else { 1 });
                }
                Err(e) => {
                    eprintln!("Verification error: {}", e);
                    process::exit(1);
                }
            }
        }
        _ => { usage(); process::exit(2); }
    }
}
