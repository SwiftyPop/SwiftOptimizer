// main.rs
// OneClick Optimizer - Main Application

// Import the dependency manager module
mod dependency_manager;

use std::fs;
use std::io::{self, Write};
use std::process::{Command, Stdio};
use tokio;
use winreg::RegKey;
use winreg::enums::*;

// Use the DependencyManager only (cleaned up unused imports)
use dependency_manager::DependencyManager;

const VERSION: &str = "8.0";

// NOTE: We do NOT redefine HKEY constants here.
// Instead, we use their string representations ("HKCU", "HKLM")
// in the function calls, as required by the external `reg.exe` tool.

#[derive(Debug)]
struct SystemInfo {
    is_admin: bool,
    // Fields are kept for future use, suppressing the unused warning
    #[allow(dead_code)]
    is_win11: bool,
    #[allow(dead_code)]
    build_number: u32,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize Logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // 2. Initial Checks
    let info = check_system_requirements();

    if !info.is_admin {
        eprintln!("❌ ERROR: Please run this application as Administrator.");
        prompt_continue("Press Enter to exit...");
        return Ok(());
    }

    // 3. Application Loop
    let manager = DependencyManager::new();
    manager.initialize().await?;

    if let Err(e) = run_menu(&manager).await {
        eprintln!("\nFATAL ERROR: {}", e);
        prompt_continue("Press Enter to exit...");
        return Err(e);
    }

    Ok(())
}

/// The main application menu loop
async fn run_menu(manager: &DependencyManager) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        println!("\n╔═════════════════════════════════════╗");
        println!("║      OneClick Optimizer v{}      ║", VERSION);
        println!("║─────────────────────────────────────║");
        println!("║ [1]  Install/Update Dependencies    ║");
        println!("║ [2]  Apply Basic Tweaks (Registry)  ║");
        println!("║ [3]  Apply Latency Tweaks (BCD/Reg) ║");
        println!("║ [4]  Apply Game Tweaks              ║");
        println!("║ [5]  Clean System (Temp Files)      ║");
        println!("║ [0]  Exit                           ║");
        println!("╚═════════════════════════════════════╝");

        match prompt_choice("Select an option (0-5):") {
            Ok(choice) => match choice.as_str() {
                "1" => install_dependencies(manager).await?,
                "2" => apply_basic_tweaks()?,
                "3" => apply_latency_tweaks()?,
                "4" => apply_game_tweaks()?,
                "5" => clean_system()?,
                "0" => {
                    println!("Goodbye!");
                    break;
                }
                _ => println!("Invalid option. Please try again."),
            },
            Err(_) => println!("Invalid input. Please enter a number."),
        }
    }
    Ok(())
}

// =========================================================================
//  UTILITY FUNCTIONS (Error Fixes Applied)
// =========================================================================

/// Helper function for registry addition/modification
// FIX: Changed hkey from HKEY to &str (e.g., "HKLM" or "HKCU") to pass to reg.exe
fn reg_add(
    hkey: &str, // Accepts string literal
    key_path: &str,
    value_name: &str,
    value_type: &str,
    value_data: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "  -> Modifying Registry: {}({}) = {}",
        key_path, value_name, value_data
    );

    // Use `hkey` directly in the format string
    Command::new("reg")
        .args(&[
            "add",
            &format!("{}\\{}", hkey, key_path),
            "/v",
            value_name,
            "/t",
            value_type,
            "/d",
            value_data,
            "/f",
        ])
        .stdout(Stdio::null())
        .status()?;

    Ok(())
}

/// Helper function for deleting a registry key
// FIX: Changed hkey from HKEY to &str
fn del_reg_key(hkey: &str, key_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("  -> Deleting Registry Key: {}", key_path);

    // Use `hkey` directly in the format string
    Command::new("reg")
        .args(&["delete", &format!("{}\\{}", hkey, key_path), "/f"])
        .stdout(Stdio::null())
        .status()?;

    Ok(())
}

/// Helper function for BCD (Boot Configuration Data) modifications
fn bcdedit(command: &str, argument: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("  -> Running BCDEDIT: {} {} {}", command, argument, value);

    Command::new("bcdedit")
        .args(&[command, argument, value])
        .stdout(Stdio::null())
        .status()?;

    Ok(())
}

/// Helper function for Service Control (sc) modifications
fn sc_config(service_name: &str, start_type: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "  -> Configuring Service '{}' to start={}",
        service_name, start_type
    );

    Command::new("sc")
        .args(&["config", service_name, "start=", start_type])
        .stdout(Stdio::null())
        .status()?;

    Ok(())
}

/// Helper function to run a PowerShell command
fn powershell(script: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("  -> Running PowerShell Command: {}", script);

    Command::new("powershell")
        .args(&["-Command", script])
        .stdout(Stdio::null())
        .status()?;

    Ok(())
}

/// Prompts the user for a Yes/No answer (Y/N)
fn prompt_yes_no(message: &str) -> Result<bool, Box<dyn std::error::Error>> {
    loop {
        print!("{} (y/n): ", message);
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let trimmed = input.trim().to_lowercase();

        match trimmed.as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("Invalid input. Please enter 'y' or 'n'."),
        }
    }
}

/// Prompts the user for any string input
fn prompt_choice(message: &str) -> Result<String, Box<dyn std::error::Error>> {
    print!("{}: ", message);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

/// Simple prompt to pause execution
fn prompt_continue(message: &str) {
    print!("{}", message);
    let _ = io::stdout().flush();
    let mut input = String::new();
    let _ = io::stdin().read_line(&mut input);
}

// =========================================================================
//  SYSTEM INFORMATION AND TWEAKING FUNCTIONS
// =========================================================================

/// Checks if the user is running as admin and gathers OS info
fn check_system_requirements() -> SystemInfo {
    println!("Checking system requirements...");

    // Check for admin rights (by attempting to run a command that requires it)
    let is_admin = Command::new("net")
        .args(&["session"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if is_admin {
        println!("✅ Administrator rights detected.");
    } else {
        println!("⚠️  NOT running as Administrator.");
    }

    // Attempt to get OS build info (simplified for demonstration)
    let is_win11 = false;
    let build_number = 0;

    SystemInfo {
        is_admin,
        is_win11,
        build_number,
    }
}

/// Apply general performance tweaks via the Registry
fn apply_basic_tweaks() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n⚙️  Applying basic system tweaks...");

    // Disable Nagle's Algorithm (improves network latency)
    // NOTE: HKEY_LOCAL_MACHINE is passed as "HKLM"
    reg_add(
        "HKLM",
        "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\<Your-Network-Adapter-GUID>",
        "TcpNoDelay",
        "REG_DWORD",
        "1",
    )?;
    reg_add(
        "HKLM",
        "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\<Your-Network-Adapter-GUID>",
        "TcpAckFrequency",
        "REG_DWORD",
        "1",
    )?;
    println!(
        "⚠️ NOTE: TcpNoDelay/TcpAckFrequency should be applied to your specific network adapter GUID."
    );

    // Disable HPET (High Precision Event Timer) via services
    sc_config("hpet", "disabled")?;

    // Disable Windows Error Reporting
    sc_config("WerSvc", "disabled")?;

    // Disable Telemetry and Data Collection services
    sc_config("DiagTrack", "disabled")?;
    sc_config("dmwappushservice", "disabled")?;

    println!("✅ Basic tweaks applied. System service changes require reboot.");
    Ok(())
}

/// Apply low-level latency tweaks, including BCD modifications
fn apply_latency_tweaks() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n⚡ Applying latency tweaks...");

    // Disable dynamic tick (important for stability/latency)
    bcdedit("/set", "disabledynamictick", "yes")?;
    bcdedit("/set", "useplatformtick", "no")?;

    // Set minimal Timer Resolution (often handled by external tools like TimerResolution.exe)
    // NOTE: HKEY_LOCAL_MACHINE is passed as "HKLM"
    reg_add(
        "HKLM",
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile",
        "SystemResponsiveness",
        "REG_DWORD",
        "0",
    )?;

    // Set priority for the active process
    reg_add(
        "HKLM",
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games",
        "Scheduling Category",
        "REG_SZ",
        "High",
    )?;
    reg_add(
        "HKLM",
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games",
        "Priority",
        "REG_DWORD",
        "6",
    )?;

    println!("✅ Latency tweaks applied.");
    Ok(())
}

/// Apply tweaks specific to gaming performance
fn apply_game_tweaks() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🎮 Applying game-specific tweaks...");

    // Disable Fullscreen Optimizations (FSO)
    // NOTE: HKEY_CURRENT_USER is passed as "HKCU"
    reg_add(
        "HKCU",
        "System\\GameConfigStore",
        "GameDVR_FSEBehaviorMode",
        "REG_DWORD",
        "2",
    )?;

    // Disable Game Bar and Game DVR
    reg_add(
        "HKCU",
        "Software\\Microsoft\\Windows\\CurrentVersion\\GameDVR",
        "Enabled",
        "REG_DWORD",
        "0",
    )?;

    // Disable Visual Effects that impact gaming performance
    powershell(
        "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced' -Name 'ListviewAlphaSelect' -Value 0",
    )?;
    powershell(
        "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced' -Name 'TaskbarAnimations' -Value 0",
    )?;

    println!("✅ Game tweaks applied.");
    Ok(())
}

/// Cleans temporary files, cache, and prefetch data
fn clean_system() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🧹 Cleaning system files...");

    let user_profile = env!("USERPROFILE");

    // Clear Temporary Files
    powershell(&format!(
        "Remove-Item -Path '{}\\AppData\\Local\\Temp\\*' -Recurse -Force -ErrorAction SilentlyContinue",
        user_profile
    ))?;
    powershell(
        "Remove-Item -Path 'C:\\Windows\\Temp\\*' -Recurse -Force -ErrorAction SilentlyContinue",
    )?;

    // Clear Prefetch
    powershell(
        "Remove-Item -Path 'C:\\Windows\\Prefetch\\*' -Recurse -Force -ErrorAction SilentlyContinue",
    )?;

    // Clear DNS Cache
    powershell("ipconfig /flushdns")?;

    // Clean Windows Update cache (BITS)
    powershell(
        "net stop bits ; net stop wuauserv ; Remove-Item -Path 'C:\\Windows\\SoftwareDistribution\\Download\\*' -Recurse -Force -ErrorAction SilentlyContinue ; net start bits ; net start wuauserv",
    )?;

    println!("✅ System cleaned. Temporary and cache files removed.");
    Ok(())
}

/// Downloads and updates all external dependencies
async fn install_dependencies(
    manager: &DependencyManager,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n📦 Starting dependency installation...");

    // Download all dependencies needed for the "core" features initially
    let required = vec!["core".to_string()];
    manager.download_required(&required).await?;

    // If the user wants to download ALL dependencies, uncomment the line below:
    // manager.download_required(&[]).await?;

    println!("✅ Dependencies status updated.");
    Ok(())
}
