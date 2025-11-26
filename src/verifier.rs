use crate::error::{LicenseError, LicenseResult};
use crate::hardware::HardwareInfo;
use crate::license::License;
use rsa::RsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use sha2::Sha256;

/// License verifier that handles signature and hardware binding verification
pub struct Verifier {
    public_key: RsaPublicKey,
}

impl Verifier {
    /// Create a new verifier with the given PEM-encoded public key
    ///
    /// # Arguments
    ///
    /// * `public_key_pem` - RSA public key in PEM format
    ///
    /// # Returns
    ///
    /// Returns a `Verifier` instance or `LicenseError` if the key is invalid
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use licverify::Verifier;
    ///
    /// let public_key_pem = std::fs::read_to_string("public.pem")?;
    /// let verifier = Verifier::new(&public_key_pem)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn new(public_key_pem: &str) -> LicenseResult<Self> {
        if public_key_pem.is_empty() {
            return Err(LicenseError::InvalidPublicKey(
                "Public key cannot be empty".to_string(),
            ));
        }

        let public_key = RsaPublicKey::from_public_key_pem(public_key_pem).map_err(|e| {
            LicenseError::InvalidPublicKey(format!("Failed to parse public key: {}", e))
        })?;

        Ok(Verifier { public_key })
    }

    /// Load a license from file
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the license file (.lic)
    ///
    /// # Returns
    ///
    /// Returns a `License` struct or `LicenseError` if loading fails
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use licverify::Verifier;
    /// # let public_key_pem = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----";
    /// # let verifier = Verifier::new(public_key_pem)?;
    /// let license = verifier.load_license("license.lic")?;
    /// println!("License loaded: {}", license.id);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn load_license<P: AsRef<std::path::Path>>(&self, path: P) -> LicenseResult<License> {
        License::load(path)
    }

    /// Verify the license signature using RSA-PKCS1v15-SHA256
    ///
    /// Performs cryptographic verification of the license signature against
    /// the license payload using the verifier's RSA public key.
    ///
    /// # Arguments
    ///
    /// * `license` - The license to verify
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if signature is valid, `LicenseError::InvalidSignature` otherwise
    pub fn verify_signature(&self, license: &License) -> LicenseResult<()> {
        use rsa::pkcs1v15::{Signature, VerifyingKey};
        use rsa::signature::Verifier;

        let payload = license.payload_bytes();

        // Check signature length (should be 256 bytes for RSA-2048)
        if license.signature.len() != 256 {
            return Err(LicenseError::InvalidSignature);
        }

        // Create verifying key from our RSA public key with SHA-256 (PKCS#1 v1.5 standard)
        let verifying_key: VerifyingKey<Sha256> = VerifyingKey::new(self.public_key.clone());

        // Create signature object from the license signature bytes
        let signature = Signature::try_from(license.signature.as_slice())
            .map_err(|_| LicenseError::InvalidSignature)?;

        // Verify signature - pass payload directly, verify() handles hashing internally
        verifying_key
            .verify(payload, &signature)
            .map_err(|_| LicenseError::InvalidSignature)?;

        Ok(())
    }

    /// Verify hardware binding
    ///
    /// Checks if the current system's hardware matches the license's hardware binding requirements.
    /// Compares MAC addresses, disk IDs, and hostnames as specified in the license.
    ///
    /// # Arguments
    ///
    /// * `license` - The license containing hardware binding requirements
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if hardware matches, `LicenseError::HardwareBinding` otherwise
    pub fn verify_hardware_binding(&self, license: &License) -> LicenseResult<()> {
        let hardware_info = HardwareInfo::get()?;
        hardware_info.matches_binding(&license.hardware_ids)
    }

    /// Verify license expiry
    ///
    /// Checks if the license has expired by comparing the expiry date with the current time.
    ///
    /// # Arguments
    ///
    /// * `license` - The license to check for expiry
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if license is still valid, `LicenseError::Expired` if expired
    pub fn verify_expiry(&self, license: &License) -> LicenseResult<()> {
        if license.is_expired() {
            return Err(LicenseError::Expired {
                date: license
                    .expiry_date
                    .format("%Y-%m-%d %H:%M:%S UTC")
                    .to_string(),
            });
        }
        Ok(())
    }

    /// Perform complete license verification
    ///
    /// Performs all verification checks: signature validation, hardware binding,
    /// and expiry verification in sequence.
    ///
    /// # Arguments
    ///
    /// * `license` - The license to verify completely
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all checks pass, or the first `LicenseError` encountered
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use licverify::Verifier;
    /// # let public_key_pem = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----";
    /// # let verifier = Verifier::new(public_key_pem)?;
    /// # let license = verifier.load_license("license.lic")?;
    /// match verifier.verify(&license) {
    ///     Ok(()) => println!("License is valid!"),
    ///     Err(e) => println!("License verification failed: {}", e),
    /// }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn verify(&self, license: &License) -> LicenseResult<()> {
        self.verify_signature(license)?;
        self.verify_hardware_binding(license)?;
        self.verify_expiry(license)?;
        Ok(())
    }
}
