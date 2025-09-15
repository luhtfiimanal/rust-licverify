use clap::{Arg, Command};
use licverify::{LicenseError, Verifier};
use std::process;

fn main() {
    let matches = Command::new("licverify")
        .version("0.1.0")
        .about("Rust client for go-license verification system")
        .arg(
            Arg::new("public-key")
                .long("public-key")
                .short('k')
                .value_name("FILE")
                .help("Path to public key PEM file")
                .required(true),
        )
        .arg(
            Arg::new("license")
                .long("license")
                .short('l')
                .value_name("FILE")
                .help("Path to license file")
                .required(true),
        )
        .get_matches();

    let public_key_path = matches.get_one::<String>("public-key").unwrap();
    let license_path = matches.get_one::<String>("license").unwrap();

    if let Err(e) = run_verification(public_key_path, license_path) {
        eprintln!("License verification failed: {}", e);
        process::exit(1);
    }

    println!("License is valid!");
}

fn run_verification(public_key_path: &str, license_path: &str) -> Result<(), LicenseError> {
    // Read public key
    let public_key_pem = std::fs::read_to_string(public_key_path).map_err(LicenseError::Io)?;

    // Create verifier
    let verifier = Verifier::new(&public_key_pem)?;

    // Load license
    let license = verifier.load_license(license_path)?;

    // Perform verification
    verifier.verify(&license)?;

    // Print license information
    println!("License ID: {}", license.id);
    println!("Customer: {}", license.customer_id);
    println!("Product: {}", license.product_id);
    println!("Serial: {}", license.serial_number);
    println!(
        "Issue Date: {}",
        license.issue_date.format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!(
        "Expiry Date: {}",
        license.expiry_date.format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!("Features: {}", license.features.join(", "));

    let days_remaining = license.days_until_expiry();
    if days_remaining > 0 {
        println!("Days remaining: {}", days_remaining);
    } else if days_remaining == 0 {
        println!("License expires today!");
    }

    Ok(())
}
