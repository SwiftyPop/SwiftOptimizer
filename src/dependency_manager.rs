// dependency_manager.rs
// External Dependency Management System for OneClick Optimizer

use reqwest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const TOOLS_DIR: &str = "C:\\OneClick Tools";

/// Represents a downloadable dependency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    pub url: String,
    pub dest_path: String,
    pub is_archive: bool,
    pub archive_format: Option<ArchiveFormat>,
    pub required_for: Vec<String>,
    pub checksum: Option<String>,
    pub description: String,
}

/// Supported archive formats
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ArchiveFormat {
    Zip,
    SevenZ,
    Tar,
}

/// Main dependency manager
pub struct DependencyManager {
    dependencies: HashMap<String, Dependency>,
    cache_dir: PathBuf,
}

impl DependencyManager {
    /// Create a new dependency manager instance
    pub fn new() -> Self {
        Self {
            dependencies: Self::define_dependencies(),
            cache_dir: PathBuf::from(TOOLS_DIR),
        }
    }

    /// Define all external dependencies
    fn define_dependencies() -> HashMap<String, Dependency> {
        let mut deps = HashMap::new();

        // ========== CORE TOOLS ==========

        // OneclickTools.zip - Main tool bundle
        deps.insert(
            "oneclick_tools".to_string(),
            Dependency {
                url: "https://github.com/QuakedK/Oneclick/raw/refs/heads/main/Downloads/OneclickTools.zip".to_string(),
                dest_path: TOOLS_DIR.to_string(),
                is_archive: true,
                archive_format: Some(ArchiveFormat::Zip),
                required_for: vec!["core".to_string()],
                checksum: None,
                description: "Core tools bundle (NSudo, Timer Resolution, DPC Checker, OOShutUp10, Dcontrol, Power Plans)".to_string(),
            },
        );

        // Visual C++ Redistributable
        deps.insert(
            "vc_redist".to_string(),
            Dependency {
                url: "https://aka.ms/vs/17/release/vc_redist.x64.exe".to_string(),
                dest_path: format!("{}\\VC Redist\\VC_redist.x64.exe", TOOLS_DIR),
                is_archive: false,
                archive_format: None,
                required_for: vec!["core".to_string()],
                checksum: None,
                description: "Visual C++ 2015-2022 Redistributable (x64)".to_string(),
            },
        );

        // ========== NVIDIA GPU TOOLS ==========

        // NVIDIA Profile Inspector
        deps.insert(
            "nvidia_inspector".to_string(),
            Dependency {
                url: "https://github.com/Orbmu2k/nvidiaProfileInspector/releases/download/2.4.0.29/nvidiaProfileInspector.zip".to_string(),
                dest_path: format!("{}\\Nvidia\\nvidiaProfileInspector", TOOLS_DIR),
                is_archive: true,
                archive_format: Some(ArchiveFormat::Zip),
                required_for: vec!["nvidia_tweaks".to_string()],
                checksum: None,
                description: "NVIDIA Profile Inspector for advanced GPU settings".to_string(),
            },
        );

        // NVIDIA Profile Configuration
        deps.insert(
            "nvidia_profile".to_string(),
            Dependency {
                url: "https://raw.githubusercontent.com/QuakedK/Oneclick/refs/heads/main/Downloads/QuakedOptimizedNVProflie.nip".to_string(),
                dest_path: format!("{}\\Nvidia\\Quaked Optimized NV Proflie.nip", TOOLS_DIR),
                is_archive: false,
                archive_format: None,
                required_for: vec!["nvidia_tweaks".to_string()],
                checksum: None,
                description: "Optimized NVIDIA profile settings".to_string(),
            },
        );

        // ========== SEARCH REPLACEMENT ==========

        // Open Shell Menu
        deps.insert(
            "open_shell".to_string(),
            Dependency {
                url: "https://github.com/Open-Shell/Open-Shell-Menu/releases/download/v4.4.191/OpenShellSetup_4_4_191.exe".to_string(),
                dest_path: format!("{}\\Open Shell\\OpenShellSetup_4_4_191.exe", TOOLS_DIR),
                is_archive: false,
                archive_format: None,
                required_for: vec!["search_replacement".to_string()],
                checksum: None,
                description: "Open Shell Menu - Windows Start Menu replacement".to_string(),
            },
        );

        // Open Shell Theme
        deps.insert(
            "open_shell_theme".to_string(),
            Dependency {
                url: "https://github.com/QuakedK/Oneclick/raw/refs/heads/main/Downloads/OpenShellTheme.xml".to_string(),
                dest_path: format!("{}\\Open Shell\\OpenShellTheme.xml", TOOLS_DIR),
                is_archive: false,
                archive_format: None,
                required_for: vec!["search_replacement".to_string()],
                checksum: None,
                description: "Custom theme for Open Shell Menu".to_string(),
            },
        );

        // ========== NETWORK TOOLS ==========

        // DNS Jumper
        deps.insert(
            "dns_jumper".to_string(),
            Dependency {
                url: "https://www.sordum.org/files/downloads.php?dns-jumper".to_string(),
                dest_path: format!("{}\\DnsJumper", TOOLS_DIR),
                is_archive: true,
                archive_format: Some(ArchiveFormat::Zip),
                required_for: vec!["network_tweaks".to_string()],
                checksum: None,
                description: "DNS Jumper - DNS optimization and testing tool".to_string(),
            },
        );

        // ========== EXTRAS ==========



        // ========== APP INSTALLER RESOURCES ==========


        deps
    }

    /// Initialize the dependency manager
    pub async fn initialize(&self) -> Result<(), Box<dyn std::error::Error>> {
        fs::create_dir_all(&self.cache_dir)?;
        println!(
            "📦 Dependency manager initialized at: {}",
            self.cache_dir.display()
        );
        Ok(())
    }

    /// Check if a dependency is already available
    pub fn is_dependency_available(&self, dep: &Dependency) -> bool {
        let path = Path::new(&dep.dest_path);

        if dep.is_archive {
            // For archives, check if extracted folder exists and has content
            path.exists()
                && path
                    .read_dir()
                    .map(|mut d| d.next().is_some())
                    .unwrap_or(false)
        } else {
            // For single files, just check existence
            path.exists()
        }
    }

    /// Download a single dependency
    pub async fn download_dependency(
        &self,
        name: &str,
        dep: &Dependency,
    ) -> Result<(), Box<dyn std::error::Error>> {
        println!("⬇️  Downloading: {} ({})", name, dep.description);

        // Download file
        let response = reqwest::get(&dep.url).await?;

        if !response.status().is_success() {
            return Err(format!("Failed to download {}: HTTP {}", name, response.status()).into());
        }

        let bytes = response.bytes().await?;

        // Verify checksum if provided
        if let Some(expected_checksum) = &dep.checksum {
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let actual_checksum = format!("{:x}", hasher.finalize());

            if &actual_checksum != expected_checksum {
                return Err(format!(
                    "Checksum mismatch for {}: expected {}, got {}",
                    name, expected_checksum, actual_checksum
                )
                .into());
            }
            println!("  ✓ Checksum verified");
        }

        // Create parent directory
        let dest_path = Path::new(&dep.dest_path);
        if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Save to temporary location if archive
        let temp_path = if dep.is_archive {
            format!("{}.tmp", dep.dest_path)
        } else {
            dep.dest_path.clone()
        };

        fs::write(&temp_path, bytes)?;

        // Extract if it's an archive
        if dep.is_archive {
            println!("  📦 Extracting...");
            self.extract_archive(&temp_path, &dep.dest_path, &dep.archive_format)?;
            fs::remove_file(&temp_path)?;
        }

        println!("  ✅ Completed: {}", name);
        Ok(())
    }

    /// Extract an archive based on its format
    fn extract_archive(
        &self,
        archive_path: &str,
        dest_path: &str,
        format: &Option<ArchiveFormat>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        fs::create_dir_all(dest_path)?;

        match format {
            Some(ArchiveFormat::Zip) => {
                Command::new("tar")
                    .args(&["-xf", archive_path, "-C", dest_path])
                    .status()?;
            }
            Some(ArchiveFormat::SevenZ) => {
                // Use PowerShell for 7z files
                let ps_script = format!(
                    "Expand-Archive -Path '{}' -DestinationPath '{}' -Force",
                    archive_path, dest_path
                );
                Command::new("powershell")
                    .args(&["-Command", &ps_script])
                    .status()?;
            }
            Some(ArchiveFormat::Tar) => {
                Command::new("tar")
                    .args(&["-xf", archive_path, "-C", dest_path])
                    .status()?;
            }
            None => {
                return Err("No archive format specified for archive file".into());
            }
        }

        Ok(())
    }

    /// Download all dependencies required for specific features
    pub async fn download_required(
        &self,
        required_features: &[String],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut to_download = Vec::new();

        // Find dependencies that need to be downloaded
        for (name, dep) in &self.dependencies {
            let is_required = required_features.is_empty()
                || dep
                    .required_for
                    .iter()
                    .any(|f| required_features.contains(f));

            if is_required && !self.is_dependency_available(dep) {
                to_download.push((name.clone(), dep.clone()));
            }
        }

        if to_download.is_empty() {
            println!("✅ All required dependencies are already available.");
            return Ok(());
        }

        println!("\n📦 Need to download {} dependencies:", to_download.len());
        for (name, dep) in &to_download {
            println!("  • {} - {}", name, dep.description);
        }
        println!();

        // Download each dependency
        let mut failed = Vec::new();
        for (name, dep) in to_download {
            match self.download_dependency(&name, &dep).await {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("⚠️  Warning: Failed to download {}: {}", name, e);
                    failed.push((name, e.to_string()));
                }
            }
        }

        if !failed.is_empty() {
            println!("\n⚠️  Some downloads failed:");
            for (name, error) in failed {
                println!("  • {}: {}", name, error);
            }
            println!("\nThe program may not function correctly without these dependencies.");
        }

        Ok(())
    }

    /// Download dependencies on-demand for a specific feature
    pub async fn download_on_demand(
        &self,
        feature: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let deps_for_feature: Vec<_> = self
            .dependencies
            .iter()
            .filter(|(_, dep)| dep.required_for.contains(&feature.to_string()))
            .collect();

        if deps_for_feature.is_empty() {
            return Ok(());
        }

        println!("📦 Downloading dependencies for: {}", feature);

        for (name, dep) in deps_for_feature {
            if !self.is_dependency_available(dep) {
                self.download_dependency(name, dep).await?;
            }
        }

        Ok(())
    }

    /// Verify all required dependencies are present
    #[allow(dead_code)] // Suppress unused warning
    pub fn verify_dependencies(
        &self,
        required_features: &[String],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut missing = Vec::new();

        for (name, dep) in &self.dependencies {
            let is_required = required_features.is_empty()
                || dep
                    .required_for
                    .iter()
                    .any(|f| required_features.contains(f));

            if is_required && !self.is_dependency_available(dep) {
                missing.push(name.clone());
            }
        }

        if !missing.is_empty() {
            return Err(format!("Missing required dependencies: {}", missing.join(", ")).into());
        }

        println!("✅ All dependencies verified.");
        Ok(())
    }

    /// Get the path to a specific dependency
    pub fn get_dependency_path(&self, name: &str) -> Option<PathBuf> {
        self.dependencies
            .get(name)
            .map(|dep| PathBuf::from(&dep.dest_path))
    }



    /// List all available dependencies
    #[allow(dead_code)] // Suppress unused warning
    pub fn list_dependencies(&self) {
        println!("\n📦 Available Dependencies:");
        println!("═══════════════════════════════════════");

        let mut deps: Vec<_> = self.dependencies.iter().collect();
        deps.sort_by_key(|(name, _)| name.as_str());

        for (name, dep) in deps {
            let status = if self.is_dependency_available(dep) {
                "✅"
            } else {
                "❌"
            };
            println!(
                "{} {} - {} ({})",
                status,
                name,
                dep.description,
                dep.required_for.join(", ")
            );
        }
        println!();
    }

    /// Clean up downloaded dependencies
    #[allow(dead_code)] // Suppress unused warning
    pub fn cleanup(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("🧹 Cleaning up temporary files...");

        // Remove specific temporary directories
                let temp_dirs: Vec<String> = vec![];

        for dir in temp_dirs {
            if Path::new(&dir).exists() {
                let _ = fs::remove_dir_all(&dir);
            }
        }

        println!("✅ Cleanup complete.");
        Ok(())
    }

    /// Get statistics about dependencies
    #[allow(dead_code)] // Suppress unused warning
    pub fn get_stats(&self) -> DependencyStats {
        let total = self.dependencies.len();
        let downloaded = self
            .dependencies
            .values()
            .filter(|dep| self.is_dependency_available(dep))
            .count();

        DependencyStats {
            total,
            downloaded,
            missing: total - downloaded,
        }
    }
}

/// Statistics about dependency status
#[allow(dead_code)] // Suppress unused warning
pub struct DependencyStats {
    pub total: usize,
    pub downloaded: usize,
    pub missing: usize,
}

impl std::fmt::Display for DependencyStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Dependencies: {}/{} downloaded, {} missing",
            self.downloaded, self.total, self.missing
        )
    }
}

/// Helper function to download a file directly
#[allow(dead_code)] // Suppress unused warning
pub async fn download_file(url: &str, dest: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("⬇️  Downloading from: {}", url);

    let response = reqwest::get(url).await?;

    if !response.status().is_success() {
        return Err(format!("HTTP error: {}", response.status()).into());
    }

    let bytes = response.bytes().await?;

    // Create parent directory if needed
    if let Some(parent) = Path::new(dest).parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(dest, bytes)?;
    println!("✅ Downloaded to: {}", dest);

    Ok(())
}

/// Execute an external tool safely
#[allow(dead_code)] // Suppress unused warning
pub fn execute_external_tool(
    exe_path: &Path,
    args: &[&str],
    description: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if !exe_path.exists() {
        return Err(format!(
            "External tool not found: {}\nPath: {}",
            description,
            exe_path.display()
        )
        .into());
    }

    println!("🔧 Running: {}", description);

    let status = Command::new(exe_path).args(args).status()?;

    if !status.success() {
        return Err(format!(
            "External tool failed: {} (exit code: {:?})",
            description,
            status.code()
        )
        .into());
    }

    println!("  ✅ Completed successfully");
    Ok(())
}

/// Execute an external tool and wait for user confirmation
#[allow(dead_code)] // Suppress unused warning
pub fn execute_external_tool_interactive(
    exe_path: &Path,
    args: &[&str],
    description: &str,
    instructions: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if !exe_path.exists() {
        return Err(format!(
            "External tool not found: {}\nPath: {}",
            description,
            exe_path.display()
        )
        .into());
    }

    println!("🔧 Launching: {}", description);
    println!("📋 Instructions: {}", instructions);

    Command::new(exe_path).args(args).spawn()?;

    println!("\nPress Enter when complete...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dependency_manager_creation() {
        let manager = DependencyManager::new();
        assert!(!manager.dependencies.is_empty());
    }

    #[test]
    fn test_dependency_paths() {
        let manager = DependencyManager::new();
        let path = manager.get_dependency_path("oneclick_tools");
        assert!(path.is_some());
    }

    #[test]
    fn test_stats() {
        let manager = DependencyManager::new();
        let stats = manager.get_stats();
        assert_eq!(stats.total, stats.downloaded + stats.missing);
    }
}
