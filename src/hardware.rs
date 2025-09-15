use crate::error::{LicenseError, LicenseResult};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Hardware binding information for license verification
///
/// Specifies which hardware identifiers a license is bound to. Empty vectors
/// mean no binding is required for that hardware type.
///
/// # Example
///
/// ```rust
/// use licverify::HardwareBinding;
///
/// let binding = HardwareBinding {
///     mac_addresses: vec!["aa:bb:cc:dd:ee:ff".to_string()],
///     disk_ids: vec!["DISK123".to_string()],
///     host_names: vec!["workstation-01".to_string()],
///     custom_ids: vec![],
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HardwareBinding {
    #[serde(default)]
    pub mac_addresses: Vec<String>,
    #[serde(default)]
    pub disk_ids: Vec<String>,
    #[serde(default)]
    pub host_names: Vec<String>,
    #[serde(default)]
    pub custom_ids: Vec<String>,
}

/// Current hardware information
///
/// Contains the actual hardware identifiers detected on the current system.
/// Used for comparing against license hardware binding requirements.
///
/// # Example
///
/// ```rust
/// use licverify::HardwareInfo;
///
/// let hw_info = HardwareInfo::get()?;
/// println!("MAC Addresses: {:?}", hw_info.mac_addresses);
/// println!("Disk IDs: {:?}", hw_info.disk_ids);
/// println!("Hostname: {}", hw_info.hostname);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct HardwareInfo {
    pub mac_addresses: Vec<String>,
    pub disk_ids: Vec<String>,
    pub hostname: String,
}

impl HardwareInfo {
    /// Get hardware information for the current system
    ///
    /// Automatically detects MAC addresses, disk IDs, and hostname for the current platform.
    /// Uses platform-specific methods for accurate hardware detection.
    ///
    /// # Returns
    ///
    /// Returns `HardwareInfo` with detected hardware identifiers
    ///
    /// # Example
    ///
    /// ```rust
    /// use licverify::HardwareInfo;
    ///
    /// let hw_info = HardwareInfo::get()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn get() -> LicenseResult<Self> {
        let mac_addresses = get_mac_addresses()?;
        let disk_ids = get_disk_ids()?;
        let hostname = get_hostname()?;

        Ok(HardwareInfo {
            mac_addresses,
            disk_ids,
            hostname,
        })
    }

    /// Check if this hardware matches the given binding requirements
    ///
    /// Verifies that the current hardware satisfies the license's hardware binding.
    /// At least one identifier must match for each non-empty binding category.
    ///
    /// # Arguments
    ///
    /// * `binding` - The hardware binding requirements from the license
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if hardware matches, `LicenseError::HardwareBinding` if not
    ///
    /// # Example
    ///
    /// ```rust
    /// use licverify::{HardwareInfo, HardwareBinding};
    ///
    /// let hw_info = HardwareInfo::get()?;
    /// let binding = HardwareBinding::default(); // No binding requirements
    /// hw_info.matches_binding(&binding)?; // Should always pass
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn matches_binding(&self, binding: &HardwareBinding) -> LicenseResult<()> {
        // Check MAC addresses
        if !binding.mac_addresses.is_empty()
            && !contains_any(&self.mac_addresses, &binding.mac_addresses)
        {
            return Err(LicenseError::HardwareBinding {
                reason: "MAC address mismatch".to_string(),
            });
        }

        // Check disk IDs
        if !binding.disk_ids.is_empty() && !contains_any(&self.disk_ids, &binding.disk_ids) {
            return Err(LicenseError::HardwareBinding {
                reason: "Disk ID mismatch".to_string(),
            });
        }

        // Check hostnames
        if !binding.host_names.is_empty() && !binding.host_names.contains(&self.hostname) {
            return Err(LicenseError::HardwareBinding {
                reason: "Hostname mismatch".to_string(),
            });
        }

        Ok(())
    }
}

/// Check if any item from list1 is contained in list2
fn contains_any(list1: &[String], list2: &[String]) -> bool {
    let set2: HashSet<&String> = list2.iter().collect();
    list1.iter().any(|item| set2.contains(item))
}

/// Get MAC addresses for all network interfaces
fn get_mac_addresses() -> LicenseResult<Vec<String>> {
    #[cfg(target_os = "linux")]
    {
        get_linux_mac_addresses()
    }
    #[cfg(target_os = "windows")]
    {
        get_windows_mac_addresses()
    }
    #[cfg(target_os = "macos")]
    {
        get_macos_mac_addresses()
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        Ok(vec!["unknown-mac".to_string()])
    }
}

/// Get disk IDs/serial numbers
fn get_disk_ids() -> LicenseResult<Vec<String>> {
    #[cfg(target_os = "linux")]
    {
        get_linux_disk_ids()
    }
    #[cfg(target_os = "windows")]
    {
        get_windows_disk_ids()
    }
    #[cfg(target_os = "macos")]
    {
        get_macos_disk_ids()
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        Ok(vec!["unknown-disk".to_string()])
    }
}

/// Get system hostname
fn get_hostname() -> LicenseResult<String> {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .or_else(|_| {
            std::process::Command::new("hostname")
                .output()
                .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
                .map_err(|e| LicenseError::Hardware(format!("Failed to get hostname: {}", e)))
        })
        .map_err(|e| LicenseError::Hardware(format!("Failed to get hostname: {}", e)))
}

#[cfg(target_os = "linux")]
fn get_linux_mac_addresses() -> LicenseResult<Vec<String>> {
    use std::fs;

    let mut mac_addresses = Vec::new();

    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let interface_name = entry.file_name();
            let interface_str = interface_name.to_string_lossy();

            // Skip loopback interface
            if interface_str == "lo" {
                continue;
            }

            let address_path = format!("/sys/class/net/{}/address", interface_str);
            if let Ok(address) = fs::read_to_string(&address_path) {
                let mac = address.trim().to_string();
                if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                    mac_addresses.push(mac);
                }
            }
        }
    }

    if mac_addresses.is_empty() {
        mac_addresses.push("linux-mac-fallback".to_string());
    }

    Ok(mac_addresses)
}

#[cfg(target_os = "linux")]
fn get_linux_disk_ids() -> LicenseResult<Vec<String>> {
    use std::process::Command;

    // Try lsblk first
    if let Ok(output) = Command::new("lsblk")
        .args(["-ndo", "SERIAL", "-d"])
        .output()
    {
        let serials: Vec<String> = String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty())
            .collect();

        if !serials.is_empty() {
            return Ok(serials);
        }
    }

    // Fallback to /dev/disk/by-id
    if let Ok(entries) = std::fs::read_dir("/dev/disk/by-id") {
        let disk_ids: Vec<String> = entries
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .collect();

        if !disk_ids.is_empty() {
            return Ok(disk_ids);
        }
    }

    Ok(vec!["linux-disk-fallback".to_string()])
}

#[cfg(target_os = "windows")]
fn get_windows_mac_addresses() -> LicenseResult<Vec<String>> {
    use std::process::Command;

    if let Ok(output) = Command::new("wmic")
        .args([
            "path",
            "Win32_NetworkAdapter",
            "where",
            "NetConnectionStatus=2",
            "get",
            "MACAddress",
        ])
        .output()
    {
        let mac_addresses: Vec<String> = String::from_utf8_lossy(&output.stdout)
            .lines()
            .skip(1) // Skip header
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty())
            .collect();

        if !mac_addresses.is_empty() {
            return Ok(mac_addresses);
        }
    }

    Ok(vec!["windows-mac-fallback".to_string()])
}

#[cfg(target_os = "windows")]
fn get_windows_disk_ids() -> LicenseResult<Vec<String>> {
    use std::process::Command;

    if let Ok(output) = Command::new("wmic")
        .args(["diskdrive", "get", "SerialNumber"])
        .output()
    {
        let disk_ids: Vec<String> = String::from_utf8_lossy(&output.stdout)
            .lines()
            .skip(1) // Skip header
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty())
            .collect();

        if !disk_ids.is_empty() {
            return Ok(disk_ids);
        }
    }

    Ok(vec!["windows-disk-fallback".to_string()])
}

#[cfg(target_os = "macos")]
fn get_macos_mac_addresses() -> LicenseResult<Vec<String>> {
    use std::process::Command;

    if let Ok(output) = Command::new("ifconfig").output() {
        let mut mac_addresses = Vec::new();
        let output_str = String::from_utf8_lossy(&output.stdout);

        for line in output_str.lines() {
            if line.contains("ether ") {
                if let Some(mac_start) = line.find("ether ") {
                    let mac_part = &line[mac_start + 6..];
                    if let Some(mac_end) = mac_part.find(' ') {
                        let mac = mac_part[..mac_end].trim().to_string();
                        if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                            mac_addresses.push(mac);
                        }
                    }
                }
            }
        }

        if !mac_addresses.is_empty() {
            return Ok(mac_addresses);
        }
    }

    Ok(vec!["macos-mac-fallback".to_string()])
}

#[cfg(target_os = "macos")]
fn get_macos_disk_ids() -> LicenseResult<Vec<String>> {
    use std::process::Command;

    if let Ok(output) = Command::new("diskutil")
        .args(["info", "/dev/disk0"])
        .output()
    {
        let output_str = String::from_utf8_lossy(&output.stdout);

        for line in output_str.lines() {
            if line.contains("Serial Number") {
                if let Some(colon_pos) = line.find(':') {
                    let serial = line[colon_pos + 1..].trim().to_string();
                    if !serial.is_empty() {
                        return Ok(vec![serial]);
                    }
                }
            }
        }
    }

    Ok(vec!["macos-disk-fallback".to_string()])
}
