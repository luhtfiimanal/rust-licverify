use crate::error::{LicenseError, LicenseResult};
use crate::hardware::HardwareBinding;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Cursor;
use std::path::Path;

/// RSA-2048 signature size in bytes
const SIGNATURE_SIZE: usize = 256;

/// License structure compatible with go-license format
///
/// Represents a license file that can be in either binary (v2.0+) or JSON (v1.x) format.
/// Contains all license information including customer details, expiry dates, features,
/// and hardware binding requirements.
///
/// # Example
///
/// ```rust
/// use licverify::License;
///
/// let license = License::load("license.lic")?;
/// println!("Customer: {}", license.customer_id);
/// println!("Expires: {}", license.expiry_date);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct License {
    pub id: String,
    pub customer_id: String,
    pub product_id: String,
    pub serial_number: String,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub issue_date: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub expiry_date: DateTime<Utc>,
    pub features: Vec<String>,
    pub hardware_ids: HardwareBinding,

    #[serde(skip)]
    pub signature: Vec<u8>,
    #[serde(skip)]
    raw_payload: Vec<u8>,
}

impl License {
    /// Load a license from file path
    ///
    /// Automatically detects and parses both binary (v2.0+) and JSON (v1.x) license formats.
    /// The signature is extracted and stored separately for verification.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the license file
    ///
    /// # Returns
    ///
    /// Returns a `License` instance or `LicenseError` if parsing fails
    ///
    /// # Example
    ///
    /// ```rust
    /// use licverify::License;
    ///
    /// let license = License::load("license.lic")?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn load<P: AsRef<Path>>(path: P) -> LicenseResult<Self> {
        let data = fs::read(path)?;

        if data.len() <= SIGNATURE_SIZE {
            return Err(LicenseError::FileTooSmall);
        }

        let payload_len = data.len() - SIGNATURE_SIZE;
        let payload = data[..payload_len].to_vec();
        let signature = data[payload_len..].to_vec();

        // Try binary format first (go-license v2.0+)
        if let Ok(mut license) = Self::decode_binary_format(&payload) {
            license.signature = signature;
            license.raw_payload = payload;
            return Ok(license);
        }

        // Fallback to JSON format (legacy v1.x)
        let mut license: License = serde_json::from_slice(&payload).map_err(|e| {
            LicenseError::ParseError(format!("Failed to parse JSON license: {}", e))
        })?;

        license.signature = signature;
        license.raw_payload = payload;

        Ok(license)
    }

    /// Get the payload bytes used for signature verification
    ///
    /// Returns the raw license data (without signature) that was used to generate
    /// the cryptographic signature. This is used internally for signature verification.
    ///
    /// # Returns
    ///
    /// Returns the payload bytes as a slice
    pub fn payload_bytes(&self) -> &[u8] {
        if !self.raw_payload.is_empty() {
            &self.raw_payload
        } else {
            // This shouldn't happen in normal usage, but provide fallback
            &[]
        }
    }

    /// Decode binary license format (go-license v2.0+)
    fn decode_binary_format(payload: &[u8]) -> LicenseResult<Self> {
        use std::io::{Cursor, Read};

        if payload.len() < 5 {
            return Err(LicenseError::ParseError(
                "Data too small to be a valid license".to_string(),
            ));
        }

        let mut cursor = Cursor::new(payload);

        // Read header (version: u8, length: u32)
        let mut header = [0u8; 5];
        cursor
            .read_exact(&mut header)
            .map_err(|e| LicenseError::ParseError(format!("Failed to read header: {}", e)))?;

        let version = header[0];
        let _length = u32::from_le_bytes([header[1], header[2], header[3], header[4]]);

        if version != 1 {
            return Err(LicenseError::ParseError(format!(
                "Unsupported license format version: {}",
                version
            )));
        }

        // Read license fields
        let id = Self::read_string(&mut cursor)?;
        let customer_id = Self::read_string(&mut cursor)?;
        let product_id = Self::read_string(&mut cursor)?;
        let serial_number = Self::read_string(&mut cursor)?;

        // Read timestamps
        let mut timestamp_buf = [0u8; 8];
        cursor
            .read_exact(&mut timestamp_buf)
            .map_err(|e| LicenseError::ParseError(format!("Failed to read issue date: {}", e)))?;
        let issue_unix = i64::from_le_bytes(timestamp_buf);

        cursor
            .read_exact(&mut timestamp_buf)
            .map_err(|e| LicenseError::ParseError(format!("Failed to read expiry date: {}", e)))?;
        let expiry_unix = i64::from_le_bytes(timestamp_buf);

        let issue_date = DateTime::from_timestamp(issue_unix, 0)
            .ok_or_else(|| LicenseError::ParseError("Invalid issue date timestamp".to_string()))?;
        let expiry_date = DateTime::from_timestamp(expiry_unix, 0)
            .ok_or_else(|| LicenseError::ParseError("Invalid expiry date timestamp".to_string()))?;

        // Read features
        let features = Self::read_string_slice(&mut cursor)?;

        // Read hardware binding
        let mac_addresses = Self::read_string_slice(&mut cursor)?;
        let disk_ids = Self::read_string_slice(&mut cursor)?;
        let host_names = Self::read_string_slice(&mut cursor)?;
        let custom_ids = Self::read_string_slice(&mut cursor)?;

        Ok(License {
            id,
            customer_id,
            product_id,
            serial_number,
            issue_date,
            expiry_date,
            features,
            hardware_ids: HardwareBinding {
                mac_addresses,
                disk_ids,
                host_names,
                custom_ids,
            },
            signature: vec![],
            raw_payload: payload.to_vec(),
        })
    }

    /// Read a length-prefixed string from the cursor
    fn read_string(cursor: &mut Cursor<&[u8]>) -> LicenseResult<String> {
        use std::io::Read;

        let mut len_buf = [0u8; 2];
        cursor.read_exact(&mut len_buf).map_err(|e| {
            LicenseError::ParseError(format!("Failed to read string length: {}", e))
        })?;
        let length = u16::from_le_bytes(len_buf) as usize;

        let mut string_buf = vec![0u8; length];
        cursor
            .read_exact(&mut string_buf)
            .map_err(|e| LicenseError::ParseError(format!("Failed to read string data: {}", e)))?;

        String::from_utf8(string_buf)
            .map_err(|e| LicenseError::ParseError(format!("Invalid UTF-8 string: {}", e)))
    }

    /// Read a length-prefixed string slice from the cursor
    fn read_string_slice(cursor: &mut Cursor<&[u8]>) -> LicenseResult<Vec<String>> {
        use std::io::Read;

        let mut len_buf = [0u8; 2];
        cursor
            .read_exact(&mut len_buf)
            .map_err(|e| LicenseError::ParseError(format!("Failed to read slice length: {}", e)))?;
        let length = u16::from_le_bytes(len_buf) as usize;

        let mut result = Vec::with_capacity(length);
        for _ in 0..length {
            result.push(Self::read_string(cursor)?);
        }

        Ok(result)
    }

    /// Check if the license has expired
    ///
    /// Compares the license expiry date with the current UTC time.
    ///
    /// # Returns
    ///
    /// Returns `true` if the license has expired, `false` otherwise
    ///
    /// # Example
    ///
    /// ```rust
    /// # use licverify::License;
    /// # let license = License::load("license.lic").unwrap_or_else(|_| panic!());
    /// if license.is_expired() {
    ///     println!("⚠️  License has expired!");
    /// }
    /// ```
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expiry_date
    }

    /// Get days until expiration (negative if expired)
    ///
    /// Calculates the number of days remaining until the license expires.
    /// Returns a negative number if the license has already expired.
    ///
    /// # Returns
    ///
    /// Returns the number of days until expiry (negative if expired)
    ///
    /// # Example
    ///
    /// ```rust
    /// # use licverify::License;
    /// # let license = License::load("license.lic").unwrap_or_else(|_| panic!());
    /// let days = license.days_until_expiry();
    /// if days > 0 {
    ///     println!("License expires in {} days", days);
    /// } else {
    ///     println!("License expired {} days ago", -days);
    /// }
    /// ```
    pub fn days_until_expiry(&self) -> i64 {
        let now = Utc::now();
        (self.expiry_date - now).num_days()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_license_expiry() {
        let mut license = License {
            id: "test".to_string(),
            customer_id: "customer".to_string(),
            product_id: "product".to_string(),
            serial_number: "serial".to_string(),
            issue_date: Utc.with_ymd_and_hms(2023, 1, 1, 0, 0, 0).unwrap(),
            expiry_date: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            features: vec!["basic".to_string()],
            hardware_ids: HardwareBinding::default(),
            signature: vec![],
            raw_payload: vec![],
        };

        // Test future expiry
        assert!(!license.is_expired());

        // Test past expiry
        license.expiry_date = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap();
        assert!(license.is_expired());
    }
}
