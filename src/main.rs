// main.rs
// OneClick Optimizer - Main Application

// Import the dependency manager module
mod dependency_manager;


use std::io::{self, Write};
use std::process::{Command, Stdio};
use tokio;
use colored::*;


use ipconfig;
use sysinfo::{System, SystemExt};

// Use the DependencyManager only (cleaned up unused imports)
use dependency_manager::DependencyManager;

const VERSION: &str = "0.1.0";

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

    // Apply Win11 specific tweaks
    if info.is_win11 {
        println!("  -> Windows 11 detected. Applying specific tweaks...");
        if info.build_number >= 22000 {
            reg_add("HKLM", "SYSTEM\\ControlSet001\\Control\\Session Manager\\kernel", "GlobalTimerResolutionRequests", "REG_DWORD", "1")?;
        }
        if info.build_number >= 26100 {
            println!("⚠️  Windows 11 24H2 or later detected. This version may have compatibility issues.");
        }
    }

    // 3. Create Restore Point
    if let Err(e) = create_restore_point() {
        eprintln!("\n⚠️  Could not create restore point: {}. It is recommended to exit and resolve the issue.", e);
        if !prompt_yes_no("Do you want to continue without a restore point?")? {
            return Ok(());
        }
    }

    // 4. Application Loop
    let manager = DependencyManager::new();
    manager.initialize().await?;
    install_dependencies(&manager).await?;

    if let Err(e) = run_menu(&manager).await {
        eprintln!("\nFATAL ERROR: {}", e);
        prompt_continue("Press Enter to exit...");
        return Err(e);
    }

    Ok(())
}

/// Helper function to print a colored header
fn print_header(text: &str, color: Color) {
    println!("{}", text.color(color).bold());
}

/// Helper function to print a colored option
fn print_option(number: &str, description: &str, number_color: Color, text_color: Color) {
    println!("  {}. {}", number.color(number_color).bold(), description.color(text_color));
}

/// Helper function to print a colored group heading
fn print_group_heading(text: &str, color: Color) {
    println!("\n{}", text.color(color).bold().underline());
}

/// Helper function to print a colored separator
fn print_separator(character: char, length: usize, color: Color) {
    println!("{}", std::iter::repeat(character).take(length).collect::<String>().color(color));
}

/// The main application menu loop
/// The main application menu loop
async fn run_menu(manager: &DependencyManager) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        // Clear screen for a cleaner look
        Command::new("cmd").args(&["/C", "cls"]).status().ok();

        print_separator('═', 50, Color::BrightBlue);
        print_header(&format!("SwiftOptimizer v{}", VERSION), Color::BrightGreen);
        print_separator('═', 50, Color::BrightBlue);

        print_group_heading("Core Actions:", Color::Cyan);
        print_option("1", "Create Restore Point", Color::Yellow, Color::White);

        print_group_heading("System Tweaks:", Color::Cyan);
        print_option("2", "Apply Basic Tweaks (Registry)", Color::Yellow, Color::White);
        print_option("3", "Apply Latency Tweaks (BCD/Reg)", Color::Yellow, Color::White);
        print_option("4", "Apply System & Privacy Tweaks", Color::Yellow, Color::White);
        print_option("5", "Apply Advanced System Tweaks", Color::Yellow, Color::White);
        print_option("6", "Disable Unnecessary Services", Color::Yellow, Color::White);
        print_option("7", "Apply Additional Service Tweaks", Color::Yellow, Color::White);
        print_option("8", "Disable Scheduled Tasks", Color::Yellow, Color::White);
        print_option("9", "Set Win32PrioritySeparation", Color::Yellow, Color::White);
        print_option("10", "Disable Unnecessary Devices", Color::Yellow, Color::White);
        print_option("11", "Apply GPU & Interrupt Tweaks", Color::Yellow, Color::White);
        print_option("12", "Set Windows Process Priorities", Color::Yellow, Color::White);

        print_group_heading("Specific Optimizations:", Color::Cyan);
        print_option("13", "Apply Game Tweaks", Color::Yellow, Color::White);
        print_option("14", "Apply Game/App Optimizations", Color::Yellow, Color::White);
        print_option("15", "Manage Windows Defender", Color::Yellow, Color::White);
        print_option("16", "Replace Windows Search", Color::Yellow, Color::White);
        print_option("17", "Apply O&O ShutUp10 Tweaks", Color::Yellow, Color::White);

        print_group_heading("Tools & Utilities:", Color::Cyan);
        print_option("18", "Clean System (Temp Files)", Color::Yellow, Color::White);
        print_option("19", "Remove Bloatware", Color::Yellow, Color::White);
        print_option("20", "Disable Startup Apps", Color::Yellow, Color::White);
        print_option("21", "Extras", Color::Yellow, Color::White);

        print_separator('─', 50, Color::BrightBlue);
        print_option("0", "Exit", Color::Red, Color::White);
        print_separator('─', 50, Color::BrightBlue);

        match prompt_choice(&format!("{}> Enter selection: ", "".color(Color::BrightGreen)))?.as_str() {
            "1" => create_restore_point()?,
            "2" => apply_basic_tweaks()?,
            "3" => apply_latency_tweaks()?,
            "4" => apply_system_tweaks()?,
            "5" => apply_advanced_tweaks(manager)?,
            "6" => disable_unnecessary_services()?,
            "7" => apply_additional_service_tweaks()?,
            "8" => disable_scheduled_tasks()?,
            "9" => set_win32_priority_separation()?,
            "10" => disable_unnecessary_devices()?,
            "11" => apply_gpu_tweaks(manager).await?,
            "12" => set_windows_process_priorities()?,
            "13" => apply_game_tweaks()?,
            "14" => apply_game_app_optimizations()?,
            "15" => manage_windows_defender(manager)?,
            "16" => replace_windows_search(manager).await?,
            "17" => apply_ooshutup10_tweaks(manager)?,
            "18" => clean_system()?,
            "19" => remove_bloatware()?,
            "20" => disable_startup_apps()?,
            "21" => run_extras_menu(manager).await?,
            "0" => {
                println!("Goodbye!");
                break;
            }
            _ => {
                println!("{}", "Invalid option. Please try again.".red());
                prompt_continue("Press Enter to continue...");
            }
        }
    }
    Ok(())
}

// =========================================================================
//  EXTRAS MENU
// =========================================================================

/// Sets CPU priorities for core Windows processes
fn set_windows_process_priorities() -> Result<(), Box<dyn std::error::Error>> {
    println!("\nSetting Windows process priorities...");

    let processes = vec![
        ("ApplicationFrameHost.exe", "1", "", ""),
        ("csrss.exe", "4", "3", ""),
        ("dllhost.exe", "1", "", ""),
        ("dwm.exe", "", "3", ""),
        ("fontdrvhost.exe", "1", "", ""),
        ("lsass.exe", "1", "0", "1"),
        ("SearchIndexer.exe", "1", "0", ""),
        ("services.exe", "1", "", ""),
        ("sihost.exe", "1", "", ""),
        ("smss.exe", "1", "", ""),
        ("StartMenu.exe", "1", "", ""),
        ("svchost.exe", "1", "0", ""),
        ("TrustedInstaller.exe", "1", "0", ""),
        ("wininit.exe", "1", "", ""),
        ("winlogon.exe", "1", "", ""),
        ("WMIADAP.exe", "1", "", ""),
        ("WmiPrvSE.exe", "1", "", ""),
        ("wuauclt.exe", "1", "0", ""),
    ];

    for (process_name, cpu_priority, io_priority, page_priority) in processes {
        let key_path = format!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{}\PerfOptions", process_name);
        if !cpu_priority.is_empty() {
            reg_add("HKLM", &key_path, "CpuPriorityClass", "REG_DWORD", cpu_priority)?;
        }
        if !io_priority.is_empty() {
            reg_add("HKLM", &key_path, "IoPriority", "REG_DWORD", io_priority)?;
        }
        if !page_priority.is_empty() {
            reg_add("HKLM", &key_path, "PagePriority", "REG_DWORD", page_priority)?;
        }
    }
    reg_add("HKLM", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\svchost.exe", "MinimumStackCommitInBytes", "REG_DWORD", "32768")?;

    println!("✅ Windows process priorities set.");
    Ok(())
}


/// Shows the extras menu
async fn run_extras_menu(manager: &DependencyManager) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        println!("\nExtras Menu:");
        println!("  [1] Wifi Fixer");
        println!("  [2] Network Tweaks");
        println!("  [3] Restart and Clean");
        println!("  [0] Return to Main Menu");

        match prompt_choice("Select an option (0-3):")?.as_str() {
            "1" => fix_wifi()?,
            "2" => apply_network_tweaks(manager).await?,
            "3" => restart_and_clean()?,
            "0" => break,
            _ => println!("Invalid option."),
        }
    }
    Ok(())
}

/// Restarts the computer after cleaning the system
fn restart_and_clean() -> Result<(), Box<dyn std::error::Error>> {
    println!("\nRestarting and cleaning...");
    if prompt_yes_no("This will clean system files and restart your computer. Are you sure?")? {
        clean_system()?;
        println!("  -> Restarting computer...");
        powershell("shutdown /r /t 0")?;
    }
    Ok(())
}





/// Applies network tweaks and launches DNS Jumper
async fn apply_network_tweaks(manager: &DependencyManager) -> Result<(), Box<dyn std::error::Error>> {
    println!("\nApplying network tweaks...");

    // NDIS Tweaks
    println!("  -> Applying NDIS tweaks...");
    if let Some(guid) = get_active_network_adapter_guid() {
        let key_path = format!("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{}", guid);
        reg_add("HKLM", &key_path, "TcpAckFrequency", "REG_DWORD", "1")?;
        reg_add("HKLM", &key_path, "TCPNoDelay", "REG_DWORD", "1")?;
        reg_add("HKLM", &key_path, "MaxUserPort", "REG_DWORD", "65534")?;
        reg_add("HKLM", &key_path, "TcpTimedWaitDelay", "REG_DWORD", "30")?;
    } else {
        println!("⚠️  Could not find active network adapter. Skipping NDIS tweaks.");
    }

    // DNS Jumper
    println!("  -> Launching DNS Jumper...");
    manager.download_on_demand("network_tweaks").await?;
    if let Some(path) = manager.get_dependency_path("dns_jumper") {
        let exe_path = path.join("DnsJumper.exe");
        if exe_path.exists() {
            Command::new(exe_path).status()?;
        } else {
            println!("⚠️  DNS Jumper not found.");
        }
    } else {
        println!("⚠️  DNS Jumper dependency not defined.");
    }

    Ok(())
}




/// Re-enables essential network services
fn fix_wifi() -> Result<(), Box<dyn std::error::Error>> {
    println!("\nRe-enabling network services...");
    let services_to_enable = vec![
        ("Dhcp", "auto"),
        ("Dnscache", "auto"),
        ("NlaSvc", "auto"),
        ("LanmanWorkstation", "auto"),
        ("WinHttpAutoProxySvc", "demand"),
        ("WlanSvc", "auto"),
    ];

    for (service, start_type) in services_to_enable {
        sc_config(service, start_type)?;
    }

    println!("✅ Network services re-enabled.");
    Ok(())
}




// =========================================================================
//  TWEAKING FUNCTIONS
// =========================================================================

/// Shows a submenu for applying GPU tweaks
async fn apply_gpu_tweaks(manager: &DependencyManager) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        println!("\nGPU Tweaks Menu:");
        println!("  [1] Apply Nvidia Registry Tweaks");
        println!("  [2] Set MSI Mode for Devices");
        println!("  [3] Import Nvidia Profile");
        println!("  [0] Return to Main Menu");

        match prompt_choice("Select an option (0-3):")?.as_str() {
            "1" => apply_nvidia_tweaks()?,
            "2" => set_msi_mode()?,
            "3" => import_nvidia_profile(manager).await?,
            "0" => break,
            _ => println!("Invalid option."),
        }
    }
    Ok(())
}

/// Sets MSI mode for devices
fn set_msi_mode() -> Result<(), Box<dyn std::error::Error>> {
    println!("\nSetting MSI mode for devices...");
    // This is a complex operation that typically involves modifying registry keys
    // for specific devices. It often requires identifying the device's hardware ID
    // and then setting the MsixMode and MessageSignaledInterruptProperties keys.
    // For a simplified implementation, we'll just print a message.
    println!("  -> MSI mode setting is a complex operation and requires specific device identification.");
    println!("  -> This feature is not fully implemented in this version.");
    println!("✅ MSI mode setting skipped.");
    Ok(())
}

/// Imports the Nvidia profile using Nvidia Profile Inspector
async fn import_nvidia_profile(manager: &DependencyManager) -> Result<(), Box<dyn std::error::Error>> {
    println!("\nImporting Nvidia Profile...");
    manager.download_on_demand("nvidia_tweaks").await?;

    if let Some(inspector_path) = manager.get_dependency_path("nvidia_inspector") {
        let exe_path = inspector_path.join("nvidiaProfileInspector.exe");
        if let Some(profile_path) = manager.get_dependency_path("nvidia_profile") {
            if exe_path.exists() && profile_path.exists() {
                println!("  -> Running Nvidia Profile Inspector to import profile silently...");
                let command = format!("& \"{}\" -silentImport \"{}\"", exe_path.display(), profile_path.display());
                powershell(&command)?;
                println!("✅ Nvidia profile imported successfully.");
            } else {
                println!("⚠️  Nvidia Profile Inspector or profile file not found.");
                println!("    Expected Inspector path: {}", exe_path.display());
                println!("    Expected Profile path: {}", profile_path.display());
            }
        } else {
            println!("⚠️  Nvidia profile dependency not defined.");
        }
    } else {
        println!("⚠️  Nvidia Inspector dependency not defined.");
    }
    Ok(())
}


/// Applies Nvidia specific tweaks
fn apply_nvidia_tweaks() -> Result<(), Box<dyn std::error::Error>> {
    println!("\nApplying Nvidia tweaks...");

    // Disable Nvidia Telemetry Services
    println!("  -> Disabling Nvidia Telemetry...");
    sc_config("NvTelemetryContainer", "disabled")?;

    // Power Settings
    println!("  -> Applying power settings...");
    reg_add("HKLM", "SYSTEM\\CurrentControlSet\\Services\\nvlddmkm\\Power", "PowerMizerEnable", "REG_DWORD", "0")?;
    reg_add("HKLM", "SYSTEM\\CurrentControlSet\\Services\\nvlddmkm\\Power", "PowerMizerLevel", "REG_DWORD", "1")?;
    reg_add("HKLM", "SYSTEM\\CurrentControlSet\\Services\\nvlddmkm\\Power", "PerfLevelSrc", "REG_DWORD", "2222")?;

    // MPO and HDCP
    println!("  -> Disabling MPO and HDCP...");
    reg_add("HKLM", "SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers", "OverlayTestMode", "REG_DWORD", "5")?;
    reg_add("HKLM", "SYSTEM\\CurrentControlSet\\Services\\nvlddmkm", "RMHdcpKeyGlobZero", "REG_DWORD", "1")?;

    // Telemetry Registry Keys
    println!("  -> Disabling additional telemetry...");
    reg_add("HKLM", "SOFTWARE\\NVIDIA Corporation\\Global\\NvTweak", "NvCplDisableRefreshRatePage", "REG_DWORD", "1")?;
    reg_add("HKLM", "SOFTWARE\\NVIDIA Corporation\\Global\\NvTweak", "NvCplEnableAdditionalInfoPage", "REG_DWORD", "0")?;
    reg_add("HKLM", "SOFTWARE\\NVIDIA Corporation\\Global\\NvTweak", "NvCplEnableClientSettingsPage", "REG_DWORD", "1")?;
    reg_add("HKLM", "SOFTWARE\\NVIDIA Corporation\\Global\\NvTweak", "NoPages", "REG_DWORD", "1")?;
    reg_add("HKLM", "SOFTWARE\\NVIDIA Corporation\\Global\\NvTweak", "NoSubPages", "REG_DWORD", "1")?;

    // Uninstall Telemetry Client
    println!("  -> Uninstalling Telemetry Client...");
    let command = "rundll32.exe C:\\Program Files\\NVIDIA Corporation\\Installer2\\InstallerCore\\NVI2.DLL,UninstallPackage NvTelemetry";
    powershell(command)?;

    println!("✅ Nvidia tweaks applied.");
    Ok(())
}


/// Disables a list of unnecessary PnP devices
fn disable_unnecessary_devices() -> Result<(), Box<dyn std::error::Error>> {
    println!("\nDisabling unnecessary devices...");

    if !prompt_yes_no("This will disable many non-essential PnP devices. Are you sure?")? {
        println!("Skipping device disabling.");
        return Ok(());
    }

    let devices_to_disable = vec![
        "Microsoft GS Wavetable Synth",
        "Microsoft Streaming Quality Manager Proxy",
        "Microsoft Streaming Service Proxy",
        "WAN Miniport (SSTP)",
        "WAN Miniport (IKEv2)",
        "WAN Miniport (L2TP)",
        "WAN Miniport (PPTP)",
        "WAN Miniport (PPPOE)",
        "WAN Miniport (IP)",
        "WAN Miniport (IPv6)",
        "WAN Miniport (Network Monitor)",
        "Composite Bus Enumerator",
        "Remote Desktop Device Redirector Bus",
        "Microsoft Wi-Fi Direct Virtual Adapter",
        "Microsoft Basic Display Adapter",
        "Microsoft Basic Render Adapter",
    ];

    for device in devices_to_disable {
        println!("  -> Disabling {}", device);
        let command = format!("Get-PnpDevice -FriendlyName \"{}\" | Disable-PnpDevice -Confirm:$false", device);
        powershell(&command)?;
    }

    println!("✅ Unnecessary devices disabled.");
    Ok(())
}


/// Sets the Win32PrioritySeparation value based on an expanded set of options
fn set_win32_priority_separation() -> Result<(), Box<dyn std::error::Error>> {
    println!("\nSetting Win32PrioritySeparation...");
    println!("  This setting controls how the CPU allocates time between foreground and background processes.");
    println!("\n  Select an optimization profile:");
    println!("  [1] Windows Default (2) - The standard Windows setting.");
    println!("  [2] Gaming - Max Responsiveness (40) - Short, fixed quanta. May improve input response at the cost of smoothness.");
    println!("  [3] Gaming - Smooth Gameplay (22) - Long, variable quanta with high foreground boost. Recommended for smooth FPS.");
    println!("  [4] Gaming - Balanced (38) - Short, variable quanta with high foreground boost. A mix of responsiveness and smoothness.");
    println!("  [5] Gaming - Balanced (37) - Short, variable quanta with medium foreground boost.");
    println!("  [6] Background Services Optimized (24) - Long, fixed quanta with no foreground boost.");
    println!("  [7] Custom - Enter your own decimal value.");
    println!("  [0] Cancel");

    match prompt_choice("Select an option (0-7):")?.as_str() {
        "1" => reg_add("HKLM", r"SYSTEM\CurrentControlSet\Control\PriorityControl", "Win32PrioritySeparation", "REG_DWORD", "2")?,
        "2" => reg_add("HKLM", r"SYSTEM\CurrentControlSet\Control\PriorityControl", "Win32PrioritySeparation", "REG_DWORD", "40")?,
        "3" => reg_add("HKLM", r"SYSTEM\CurrentControlSet\Control\PriorityControl", "Win32PrioritySeparation", "REG_DWORD", "22")?,
        "4" => reg_add("HKLM", r"SYSTEM\CurrentControlSet\Control\PriorityControl", "Win32PrioritySeparation", "REG_DWORD", "38")?,
        "5" => reg_add("HKLM", r"SYSTEM\CurrentControlSet\Control\PriorityControl", "Win32PrioritySeparation", "REG_DWORD", "37")?,
        "6" => reg_add("HKLM", r"SYSTEM\CurrentControlSet\Control\PriorityControl", "Win32PrioritySeparation", "REG_DWORD", "24")?,
        "7" => {
            let custom_value = prompt_choice("Enter custom decimal value:")?;
            reg_add("HKLM", r"SYSTEM\CurrentControlSet\Control\PriorityControl", "Win32PrioritySeparation", "REG_DWORD", &custom_value)?;
        }
        "0" => return Ok(()),
        _ => println!("Invalid option."),
    }

    println!("✅ Win32PrioritySeparation set. A reboot is not required, but you can test different values with your game open.");
    Ok(())
}


/// Disables a long list of unnecessary scheduled tasks
fn disable_scheduled_tasks() -> Result<(), Box<dyn std::error::Error>> {
    println!("\nDisabling scheduled tasks...");

    if !prompt_yes_no("This will disable many scheduled tasks. Are you sure?")? {
        println!("Skipping scheduled task disabling.");
        return Ok(());
    }

    let tasks_to_disable = vec![
        // CTT Telemetry
        "Microsoft\u{5c}Windows\u{5c}Application Experience\u{5c}Microsoft Compatibility Appraiser",
        "Microsoft\u{5c}Windows\u{5c}Application Experience\u{5c}ProgramDataUpdater",
        "Microsoft\u{5c}Windows\u{5c}Autochk\u{5c}Proxy",
        "Microsoft\u{5c}Windows\u{5c}Customer Experience Improvement Program\u{5c}Consolidator",
        "Microsoft\u{5c}Windows\u{5c}Customer Experience Improvement Program\u{5c}UsbCeip",
        "Microsoft\u{5c}Windows\u{5c}DiskDiagnostic\u{5c}Microsoft-Windows-DiskDiagnosticDataCollector",
        "Microsoft\u{5c}Windows\u{5c}Feedback\u{5c}Siuf\u{5c}DmClient",
        "Microsoft\u{5c}Windows\u{5c}Feedback\u{5c}Siuf\u{5c}DmClientOnScenarioDownload",
        "Microsoft\u{5c}Windows\u{5c}Windows Error Reporting\u{5c}QueueReporting",
        "Microsoft\u{5c}Windows\u{5c}Application Experience\u{5c}MareBackup",
        "Microsoft\u{5c}Windows\u{5c}Application Experience\u{5c}StartupAppTask",
        "Microsoft\u{5c}Windows\u{5c}Application Experience\u{5c}PcaPatchDbTask",
        "Microsoft\u{5c}Windows\u{5c}Maps\u{5c}MapsUpdateTask",
        // PiF Tasks
        "Microsoft\u{5c}Windows\u{5c}Defrag\u{5c}ScheduledDefrag",
        "Microsoft\u{5c}Windows\u{5c}Device Information\u{5c}Device",
        "Microsoft\u{5c}Windows\u{5c}Diagnosis\u{5c}RecommendedTroubleshootingScanner",
        "Microsoft\u{5c}Windows\u{5c}DiskCleanup\u{5c}SilentCleanup",
        "Microsoft\u{5c}Windows\u{5c}FileHistory\u{5c}File History (maintenance mode)",
        "Microsoft\u{5c}Windows\u{5c}Maintenance\u{5c}WinSAT",
        "Microsoft\u{5c}Windows\u{5c}PI\u{5c}Sqm-Tasks",
        "Microsoft\u{5c}Windows\u{5c}Power Efficiency Diagnostics\u{5c}AnalyzeSystem",
        "Microsoft\u{5c}Windows\u{5c}PushToInstall\u{5c}Registration",
        "Microsoft\u{5c}Windows\u{5c}Servicing\u{5c}StartComponentCleanup",
        "Microsoft\u{5c}Windows\u{5c}Shell\u{5c}FamilySafetyMonitor",
        "Microsoft\u{5c}Windows\u{5c}Speech\u{5c}SpeechModelDownloadTask",
        "Microsoft\u{5c}Windows\u{5c}WindowsUpdate\u{5c}Scheduled Start",
        // Quaked Tasks
        "GoogleUpdateTaskMachineCore{9C99738B-B026-4A33-A16D-7CCD7650D527}",
        "GoogleUpdateTaskMachineUA{2E0C9FAD-7C87-42A8-8EFF-986A5662B894}",
        "Opera GX scheduled Autoupdate 1711926802",
        "BraveSoftwareUpdateTaskMachineCore{A8A54493-B843-4D11-BA1F-30C26E9F10BE}",
        "BraveSoftwareUpdateTaskMachineUA{FF1E0511-D7AF-4DB6-8A41-DC39EA60EC93}",
        "CCleaner Update"
    ];

    for task in tasks_to_disable {
        println!("  -> Disabling {}", task);
        Command::new("schtasks").arg("/Change").arg("/TN").arg(task).arg("/Disable").stdout(Stdio::null()).status()?;
    }

    println!("✅ Scheduled tasks disabled.");
    Ok(())
}


/// Apply system and privacy tweaks
fn apply_system_tweaks() -> Result<(), Box<dyn std::error::Error>> {
    println!("\nApplying system and privacy tweaks...");

    // Disable Activity History
    println!("  -> Disabling Activity History...");
    reg_add("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableActivityFeed", "REG_DWORD", "0")?;
    reg_add("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\System", "PublishUserActivities", "REG_DWORD", "0")?;
    reg_add("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\System", "UploadUserActivities", "REG_DWORD", "0")?;

    // Disable Location
    println!("  -> Disabling Location...");
    reg_add("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location", "Value", "REG_SZ", "Deny")?;
    reg_add("HKLM", r"SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration", "Status", "REG_DWORD", "0")?;

    // Disable Notifications
    println!("  -> Disabling Notifications...");
    reg_add("HKCU", r"Software\Policies\Microsoft\Windows\Explorer", "DisableNotificationCenter", "REG_DWORD", "1")?;
    reg_add("HKCU", r"Software\Microsoft\Windows\CurrentVersion\PushNotifications", "ToastEnabled", "REG_DWORD", "0")?;

    // Disable Storage Sense
    println!("  -> Disabling Storage Sense...");
    powershell(r"Remove-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Recurse -ErrorAction SilentlyContinue")?;

    // Disable StickyKeys
    println!("  -> Disabling StickyKeys...");
    reg_add("HKCU", r"Control Panel\Accessibility\StickyKeys", "Flags", "REG_SZ", "506")?;

    // Enable Numlock on startup
    println!("  -> Enabling Numlock on startup...");
    reg_add(r"HKU\.DEFAULT", r"Control Panel\Keyboard", "InitialKeyboardIndicators", "REG_DWORD", "80000002")?;

    // Enable Windows 10 Right-Click Menu
    println!("  -> Enabling Windows 10 Right-Click Menu...");
    powershell(r"New-Item -Path 'HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}' -Name 'InprocServer32' -Force -Value ''")?;

    // Show File Extensions and Hidden Files
    println!("  -> Showing file extensions and hidden files...");
    reg_add("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "HideFileExt", "REG_DWORD", "0")?;
    reg_add("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "Hidden", "REG_DWORD", "1")?;

    // Enable Hardware Accelerated GPU Scheduling (HAGS)
    println!("  -> Enabling Hardware Accelerated GPU Scheduling...");
    reg_add("HKLM", r"SYSTEM\CurrentControlSet\Control\GraphicsDrivers", "HwSchMode", "REG_DWORD", "2")?;

    // Disable Mouse Acceleration
    println!("  -> Disabling Mouse Acceleration...");
    reg_add("HKCU", r"Control Panel\Mouse", "MouseSpeed", "REG_SZ", "0")?;
    reg_add("HKCU", r"Control Panel\Mouse", "MouseThreshold1", "REG_SZ", "0")?;
    reg_add("HKCU", r"Control Panel\Mouse", "MouseThreshold2", "REG_SZ", "0")?;

    // Disable Hibernation
    println!("  -> Disabling Hibernation...");
    reg_add("HKLM", r"System\CurrentControlSet\Control\Session Manager\Power", "HibernateEnabled", "REG_DWORD", "0")?;
    powershell(r"powercfg.exe /hibernate off")?;

    // Disable UAC
    println!("  -> Disabling UAC (User Account Control)...");
    reg_add("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", "REG_DWORD", "0")?;

    // Disabling Taskbar Widgets
    println!("  -> Disabling Taskbar Widgets...");
    reg_add("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "TaskbarDa", "REG_DWORD", "0")?;

    // Setting Display For Performance
    println!("  -> Setting Display For Performance...");
    reg_add("HKCU", r"Control Panel\Desktop", "DragFullWindows", "REG_SZ", "0")?;
    reg_add("HKCU", r"Control Panel\Desktop", "MenuShowDelay", "REG_SZ", "200")?;
    reg_add("HKCU", r"Control Panel\Desktop\WindowMetrics", "MinAnimate", "REG_SZ", "0")?;
    reg_add("HKCU", r"Control Panel\Keyboard", "KeyboardDelay", "REG_DWORD", "0")?;
    reg_add("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "ListviewAlphaSelect", "REG_DWORD", "0")?;
    reg_add("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "ListviewShadow", "REG_DWORD", "0")?;
    reg_add("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "TaskbarAnimations", "REG_DWORD", "0")?;
    reg_add("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects", "VisualFXSetting", "REG_DWORD", "3")?;
    reg_add("HKCU", r"Software\Microsoft\Windows\DWM", "EnableAeroPeek", "REG_DWORD", "0")?;
    reg_add("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "TaskbarMn", "REG_DWORD", "0")?;
    reg_add("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "TaskbarDa", "REG_DWORD", "0")?;
    reg_add("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "ShowTaskViewButton", "REG_DWORD", "0")?;
    reg_add("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Search", "SearchboxTaskbarMode", "REG_DWORD", "0")?;
    powershell(r"Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'UserPreferencesMask' -Type Binary -Value ([byte[]](144,18,3,128,16,0,0,0))")?;

    // Disabling Game Mode
    println!("  -> Disabling Game Mode...");
    reg_add("HKCU", r"Software\Microsoft\GameBar", "AllowAutoGameMode", "REG_DWORD", "0")?;
    reg_add("HKCU", r"Software\Microsoft\GameBar", "AutoGameModeEnabled", "REG_DWORD", "0")?;

    // Disabling Transparency Effects
    println!("  -> Disabling Transparency Effects...");
    reg_add("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", "EnableTransparency", "REG_DWORD", "0")?;

    // Disabling HomeGroup
    println!("  -> Disabling HomeGroup...");
    sc_config("HomeGroupListener", "demand")?;
    sc_config("HomeGroupProvider", "demand")?;

    // Disabling Unnecessary WiFi Settings
    println!("  -> Disabling Unnecessary WiFi Settings...");
    reg_add("HKLM", r"Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting", "Value", "REG_DWORD", "0")?;
    reg_add("HKLM", r"Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots", "Value", "REG_DWORD", "0")?;

    // Disabling Teredo and IPv6
    println!("  -> Disabling Teredo and IPv6...");
    reg_add("HKLM", r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters", "DisabledComponents", "REG_DWORD", "1")?;
    reg_add("HKLM", r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters", "DisabledComponents", "REG_DWORD", "255")?;
    powershell(r"Disable-NetAdapterBinding -Name '*' -ComponentID ms_tcpip6")?;

    println!("✅ System and privacy tweaks applied.");
    Ok(())
}


/// Shows a submenu for applying more specific service tweaks
fn apply_additional_service_tweaks() -> Result<(), Box<dyn std::error::Error>> {
    loop {
        println!("\nAdditional Service Tweaks Menu:");
        println!("  [1] Apply PiF (Privacy is Freedom) Tweaks");
        println!("  [2] Apply Quaked's Service Tweaks");
        println!("  [0] Return to Main Menu");

        match prompt_choice("Select an option (0-2):")?.as_str() {
            "1" => apply_pif_service_tweaks()?,
            "2" => apply_quaked_service_tweaks()?,
            "0" => break,
            _ => println!("Invalid option."),
        }
    }
    Ok(())
}

/// Applies service tweaks from the PiF list
fn apply_pif_service_tweaks() -> Result<(), Box<dyn std::error::Error>> {
    println!("\nApplying PiF service tweaks...");
    let services = vec![
        ("wlidsvc", "disabled"),
        ("DisplayEnhancementService", "disabled"),
        ("TabletInputService", "disabled"),
        ("RetailDemo", "disabled"),
        ("Fax", "disabled"),
        ("SharedAccess", "disabled"),
        ("lfsvc", "disabled"),
        ("WpcMonSvc", "disabled"),
        ("SessionEnv", "disabled"),
        ("MicrosoftEdgeElevationService", "disabled"),
        ("edgeupdate", "disabled"),
        ("edgeupdatem", "disabled"),
        ("autotimesvc", "disabled"),
        ("CscService", "disabled"),
        ("TermService", "disabled"),
        ("SensorDataService", "disabled"),
        ("SensorService", "disabled"),
        ("SensrSvc", "disabled"),
        ("shpamsvc", "disabled"),
        ("diagnosticshub.standardcollector.service", "disabled"),
        ("PhoneSvc", "disabled"),
        ("TapiSrv", "disabled"),
        ("UevAgentService", "disabled"),
        ("WalletService", "disabled"),
        ("TokenBroker", "disabled"),
        ("WebClient", "disabled"),
        ("MixedRealityOpenXRSvc", "disabled"),
        ("stisvc", "disabled"),
        ("WbioSrvc", "disabled"),
        ("icssvc", "disabled"),
        ("Wecsvc", "disabled"),
        ("XboxGipSvc", "disabled"),
        ("XblAuthManager", "disabled"),
        ("XboxNetApiSvc", "disabled"),
        ("XblGameSave", "disabled"),
        ("SEMgrSvc", "disabled"),
        ("iphlpsvc", "disabled"),
        ("BthAvctpSvc", "disabled"),
        ("BDESVC", "disabled"),
        ("cbdhsvc", "disabled"),
        ("CDPSvc", "disabled"),
        ("CDPUserSvc", "disabled"),
        ("DevQueryBroker", "disabled"),
        ("DevicesFlowUserSvc", "disabled"),
        ("dmwappushservice", "disabled"),
        ("DispBrokerDesktopSvc", "disabled"),
        ("TrkWks", "disabled"),
        ("EFS", "disabled"),
        ("fdPHost", "disabled"),
        ("FDResPub", "disabled"),
        ("IKEEXT", "disabled"),
        ("NPSMSvc", "disabled"),
        ("WPDBusEnum", "disabled"),
        ("PcaSvc", "disabled"),
        ("RasMan", "disabled"),
        ("SstpSvc", "disabled"),
        ("ShellHWDetection", "disabled"),
        ("SSDPSRV", "disabled"),
        ("SysMain", "disabled"),
        ("OneSyncSvc", "disabled"),
        ("lmhosts", "disabled"),
        ("UserDataSvc", "disabled"),
        ("UnistoreSvc", "disabled"),
        ("Wcmsvc", "disabled"),
        ("FontCache", "disabled"),
        ("W32Time", "disabled"),
        ("tzautoupdate", "disabled"),
        ("DsSvc", "disabled"),
        ("diagsvc", "disabled"),
        ("DialogBlockingService", "disabled"),
        ("NetTcpPortSharing", "disabled"),
        ("ssh-agent", "disabled"),
        ("wercplsupport", "disabled"),
        ("WMPNetworkSvc", "disabled"),
        ("WerSvc", "disabled"),
        ("WinHttpAutoProxySvc", "disabled"),
    ];
    for (service, start_type) in services {
        sc_config(service, start_type)?;
    }
    println!("✅ PiF service tweaks applied.");
    Ok(())
}

/// Applies service tweaks from Quaked's list
fn apply_quaked_service_tweaks() -> Result<(), Box<dyn std::error::Error>> {
    println!("\nApplying Quaked's service tweaks...");
    let services = vec![
        ("ALG", "disabled"),
        ("AJRouter", "disabled"),
        ("XblAuthManager", "disabled"),
        ("XblGameSave", "disabled"),
        ("XboxNetApiSvc", "disabled"),
        ("WSearch", "disabled"),
        ("lfsvc", "disabled"),
        ("RemoteRegistry", "disabled"),
        ("WpcMonSvc", "disabled"),
        ("SEMgrSvc", "disabled"),
        ("SCardSvr", "disabled"),
        ("Netlogon", "disabled"),
        ("CscService", "disabled"),
        ("icssvc", "disabled"),
        ("wisvc", "disabled"),
        ("RetailDemo", "disabled"),
        ("WalletService", "disabled"),
        ("Fax", "disabled"),
        ("WbioSrvc", "disabled"),
        ("iphlpsvc", "disabled"),
        ("wcncsvc", "disabled"),
        ("fhsvc", "disabled"),
        ("PhoneSvc", "disabled"),
        ("seclogon", "disabled"),
        ("FrameServer", "disabled"),
        ("StiSvc", "disabled"),
        ("PcaSvc", "disabled"),
        ("DPS", "disabled"),
        ("MapsBroker", "disabled"),
        ("bthserv", "disabled"),
        ("BDESVC", "disabled"),
        ("BthAvctpSvc", "disabled"),
        ("DiagTrack", "disabled"),
        ("CertPropSvc", "disabled"),
        ("WdiServiceHost", "disabled"),
        ("lmhosts", "disabled"),
        ("WdiSystemHost", "disabled"),
        ("TrkWks", "disabled"),
        ("WerSvc", "disabled"),
        ("TabletInputService", "disabled"),
        ("EntAppSvc", "disabled"),
        ("Spooler", "disabled"),
        ("BcastDVRUserService", "disabled"),
        ("WMPNetworkSvc", "disabled"),
        ("diagnosticshub.standardcollector.service", "disabled"),
        ("DmEnrollmentSvc", "disabled"),
        ("PNRPAutoReg", "disabled"),
        ("wlidsvc", "disabled"),
        ("AXInstSV", "disabled"),
        ("NcbService", "disabled"),
        ("DeviceAssociationService", "disabled"),
        ("StorSvc", "disabled"),
        ("TieringEngineService", "disabled"),
        ("Themes", "disabled"),
        ("AppReadiness", "disabled"),
        // Hyper-V
        ("HvHost", "disabled"),
        ("vmickvpexchange", "disabled"),
        ("vmicguestinterface", "disabled"),
        ("vmicshutdown", "disabled"),
        ("vmicheartbeat", "disabled"),
        ("vmicvmsession", "disabled"),
        ("vmicrdv", "disabled"),
        ("vmictimesync", "disabled"),
        ("vmicvss", "disabled"),
        // Browsers
        ("edgeupdate", "disabled"),
        ("edgeupdatem", "disabled"),
        ("GoogleChromeElevationService", "disabled"),
        ("gupdate", "disabled"),
        ("gupdatem", "disabled"),
        ("BraveElevationService", "disabled"),
        ("brave", "disabled"),
        ("bravem", "disabled"),
        // Manufacturer Bloat
        ("HPAppHelperCap", "disabled"),
        ("HPDiagsCap", "disabled"),
        ("HpTouchpointAnalyticsService", "disabled"),
        ("HPNetworkCap", "disabled"),
        ("HPOmenCap", "disabled"),
        ("HPSysInfoCap", "disabled"),
        ("logi_lamparray_service", "disabled"),
    ];
    for (service, start_type) in services {
        sc_config(service, start_type)?;
    }
    println!("✅ Quaked's service tweaks applied.");
    Ok(())
}


/// Disables a long list of unnecessary system services
fn disable_unnecessary_services() -> Result<(), Box<dyn std::error::Error>> {
    println!("\nDisabling unnecessary services...");

    if !prompt_yes_no("This will disable a large number of system services. Are you sure?")? {
        println!("Skipping service disabling.");
        return Ok(());
    }

    let services_to_configure = vec![
        ("AJRouter", "disabled"),
        ("ALG", "demand"),
        ("AppIDSvc", "demand"),
        ("AppMgmt", "demand"),
        ("AppReadiness", "demand"),
        ("AppVClient", "disabled"),
        ("AppXSvc", "demand"),
        ("Appinfo", "demand"),
        ("AssignedAccessManagerSvc", "disabled"),
        ("AxInstSV", "demand"),
        ("BDESVC", "demand"),
        ("BITS", "delayed-auto"),
        ("BTAGService", "demand"),
        ("Browser", "demand"),
        ("CDPSvc", "demand"),
        ("COMSysApp", "demand"),
        ("CertPropSvc", "demand"),
        ("ClipSVC", "demand"),
        ("CscService", "demand"),
        ("DcpSvc", "demand"),
        ("DevQueryBroker", "demand"),
        ("DeviceAssociationService", "demand"),
        ("DeviceInstall", "demand"),
        ("DiagTrack", "disabled"),
        ("DialogBlockingService", "disabled"),
        ("DisplayEnhancementService", "demand"),
        ("DmEnrollmentSvc", "demand"),
        ("DoSvc", "delayed-auto"),
        ("DsSvc", "demand"),
        ("DsmSvc", "demand"),
        ("DusmSvc", "auto"),
        ("EFS", "demand"),
        ("EapHost", "demand"),
        ("EntAppSvc", "demand"),
        ("FDResPub", "demand"),
        ("Fax", "demand"),
        ("FrameServer", "demand"),
        ("FrameServerMonitor", "demand"),
        ("GraphicsPerfSvc", "demand"),
        ("HomeGroupListener", "demand"),
        ("HomeGroupProvider", "demand"),
        ("HvHost", "demand"),
        ("IEEtwCollectorService", "demand"),
        ("IKEEXT", "demand"),
        ("InstallService", "demand"),
        ("InventorySvc", "demand"),
        ("IpxlatCfgSvc", "demand"),
        ("KtmRm", "demand"),
        ("LanmanServer", "auto"),
        ("LanmanWorkstation", "auto"),
        ("LicenseManager", "demand"),
        ("LxpSvc", "demand"),
        ("MSDTC", "disabled"),
        ("MSiSCSI", "demand"),
        ("MapsBroker", "delayed-auto"),
        ("McpManagementService", "demand"),
        ("MicrosoftEdgeElevationService", "demand"),
        ("MixedRealityOpenXRSvc", "demand"),
        ("MsKeyboardFilter", "demand"),
        ("NaturalAuthentication", "demand"),
        ("NcaSvc", "demand"),
        ("NcbService", "demand"),
        ("NcdAutoSetup", "demand"),
        ("NetSetupSvc", "demand"),
        ("NetTcpPortSharing", "disabled"),
        ("Netlogon", "demand"),
        ("Netman", "demand"),
        ("NgcCtnrSvc", "demand"),
        ("NgcSvc", "demand"),
        ("NlaSvc", "demand"),
        ("PNRPAutoReg", "demand"),
        ("PNRPsvc", "demand"),
        ("PcaSvc", "demand"),
        ("PeerDistSvc", "demand"),
        ("PerfHost", "demand"),
        ("PhoneSvc", "demand"),
        ("PlugPlay", "demand"),
        ("PolicyAgent", "demand"),
        ("PrintNotify", "demand"),
        ("PushToInstall", "demand"),
        ("QWAVE", "demand"),
        ("RasAuto", "demand"),
        ("RasMan", "demand"),
        ("RemoteAccess", "disabled"),
        ("RemoteRegistry", "disabled"),
        ("RetailDemo", "demand"),
        ("RmSvc", "demand"),
        ("RpcLocator", "demand"),
        ("SCPolicySvc", "demand"),
        ("SCardSvr", "demand"),
        ("SDRSVC", "demand"),
        ("SEMgrSvc", "demand"),
        ("SNMPTRAP", "demand"),
        ("SSDPSRV", "demand"),
        ("ScDeviceEnum", "demand"),
        ("SecurityHealthService", "demand"),
        ("Sense", "demand"),
        ("SensorDataService", "demand"),
        ("SensorService", "demand"),
        ("SensrSvc", "demand"),
        ("SessionEnv", "demand"),
        ("SharedAccess", "demand"),
        ("SharedRealitySvc", "demand"),
        ("ShellHWDetection", "auto"),
        ("SmsRouter", "demand"),
        ("Spooler", "auto"),
        ("SstpSvc", "demand"),
        ("StateRepository", "demand"),
        ("StiSvc", "demand"),
        ("StorSvc", "demand"),
        ("SysMain", "auto"),
        ("TabletInputService", "demand"),
        ("TapiSrv", "demand"),
        ("TermService", "auto"),
        ("TextInputManagementService", "demand"),
        ("Themes", "auto"),
        ("TieringEngineService", "demand"),
        ("TimeBroker", "demand"),
        ("TimeBrokerSvc", "demand"),
        ("TokenBroker", "demand"),
        ("TrkWks", "auto"),
        ("TroubleshootingSvc", "demand"),
        ("TrustedInstaller", "demand"),
        ("UI0Detect", "demand"),
        ("UevAgentService", "disabled"),
        ("UmRdpService", "demand"),
        ("UsoSvc", "demand"),
        ("VSS", "demand"),
        ("VacSvc", "demand"),
        ("VaultSvc", "auto"),
        ("W32Time", "demand"),
        ("WEPHOSTSVC", "demand"),
        ("WFDSConMgrSvc", "demand"),
        ("WMPNetworkSvc", "demand"),
        ("WManSvc", "demand"),
        ("WPDBusEnum", "demand"),
        ("WSService", "demand"),
        ("WSearch", "delayed-auto"),
        ("WaaSMedicSvc", "demand"),
        ("WalletService", "demand"),
        ("WarpJITSvc", "demand"),
        ("WbioSrvc", "demand"),
        ("Wcmsvc", "auto"),
        ("WcsPlugInService", "demand"),
        ("WdNisSvc", "demand"),
        ("WdiServiceHost", "demand"),
        ("WdiSystemHost", "demand"),
        ("WebClient", "demand"),
        ("Wecsvc", "demand"),
        ("WerSvc", "demand"),
        ("WiaRpc", "demand"),
        ("WinDefend", "auto"),
        ("WinHttpAutoProxySvc", "demand"),
        ("WinRM", "demand"),
        ("Winmgmt", "auto"),
        ("WlanSvc", "auto"),
        ("WpcMonSvc", "demand"),
        ("WpnService", "demand"),
        ("WwanSvc", "demand"),
        ("XblAuthManager", "demand"),
        ("XblGameSave", "demand"),
        ("XboxGipSvc", "demand"),
        ("XboxNetApiSvc", "demand"),
        ("autotimesvc", "demand"),
        ("bthserv", "demand"),
        ("camsvc", "demand"),
        ("dcsvc", "demand"),
        ("defragsvc", "demand"),
        ("diagnosticshub.standardcollector.service", "demand"),
        ("diagsvc", "demand"),
        ("dmwappushservice", "demand"),
        ("dot3svc", "demand"),
        ("edgeupdate", "demand"),
        ("edgeupdatem", "demand"),
        ("embeddedmode", "demand"),
        ("fdPHost", "demand"),
        ("fhsvc", "demand"),
        ("gpsvc", "auto"),
        ("hidserv", "demand"),
        ("icssvc", "demand"),
        ("iphlpsvc", "auto"),
        ("lfsvc", "demand"),
        ("lltdsvc", "demand"),
        ("lmhosts", "demand"),
        ("mpssvc", "auto"),
        ("msiserver", "demand"),
        ("netprofm", "demand"),
        ("nsi", "auto"),
        ("p2pimsvc", "demand"),
        ("p2psvc", "demand"),
        ("perceptionsimulation", "demand"),
        ("pla", "demand"),
        ("seclogon", "demand"),
        ("shpamsvc", "disabled"),
        ("smphost", "disabled"),
        ("spectrum", "demand"),
        ("sppsvc", "delayed-auto"),
        ("ssh-agent", "disabled"),
        ("svsvc", "demand"),
        ("swprv", "demand"),
        ("tiledatamodelsvc", "auto"),
        ("tzautoupdate", "disabled"),
        ("uhssvc", "disabled"),
        ("upnphost", "demand"),
        ("vds", "demand"),
        ("vm3dservice", "demand"),
        ("vmicguestinterface", "demand"),
        ("vmicheartbeat", "demand"),
        ("vmickvpexchange", "demand"),
        ("vmicrdv", "demand
        "),
        ("vmicshutdown", "demand"),
        ("vmictimesync", "demand"),
        ("vmicvmsession", "demand"),
        ("vmicvss", "demand"),
        ("vmvss", "demand"),
        ("wbengine", "demand"),
        ("wcncsvc", "demand"),
        ("webthreatdefsvc", "demand"),
        ("wercplsupport", "demand"),
        ("wisvc", "demand"),
        ("wlidsvc", "demand"),
        ("wlpasvc", "demand"),
        ("wmiApSrv", "demand"),
        ("workfolderssvc", "demand"),
        ("wscsvc", "delayed-auto"),
        ("wuauserv", "demand"),
        ("wudfsvc", "demand"),
    ];

    for (service, start_type) in services_to_configure {
        sc_config(service, start_type)?;
    }

    println!("✅ Unnecessary services disabled.");
    Ok(())
}


/// Applies advanced system tweaks using NSudo and other methods
fn apply_advanced_tweaks(manager: &DependencyManager) -> Result<(), Box<dyn std::error::Error>> {
    println!("\nApplying advanced system tweaks...");

    // Set boot menu policy to Legacy
    println!("  -> Setting boot menu policy to Legacy...");
    bcdedit("/set", "{current}", "bootmenupolicy Legacy")?;

    // Group svchost.exe processes based on RAM
    println!("  -> Grouping svchost.exe processes...");
    let mut sys = System::new_all();
    sys.refresh_all();
    let ram_kb = sys.total_memory() / 1024;
    reg_add("HKLM", r"SYSTEM\CurrentControlSet\Control", "SvcHostSplitThresholdInKB", "REG_DWORD", &ram_kb.to_string())?;

    // Disable Core Isolation/Memory Integrity
    println!("  -> Disabling Core Isolation/Memory Integrity...");
    reg_add("HKLM", r"System\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled", "REG_DWORD", "0")?;

    // Task Manager startup tweak
    println!("  -> Applying Task Manager startup tweak...");
    reg_add("HKCU", r"Software\Microsoft\Windows\CurrentVersion\TaskManager", "Preferences", "REG_BINARY", "0000000000000000000000000000000000000000000000000000000000000000")?;

    // Remove Edge "Managed by" policy
    println!("  -> Removing Edge 'Managed by' policy...");
    del_reg_key("HKLM", r"SOFTWARE\Policies\Microsoft\Edge")?;

    // Delete AutoLogger-Diagtrack-Listener.etl
    println!("  -> Deleting AutoLogger-Diagtrack-Listener.etl...");
    let program_data = std::env::var("PROGRAMDATA").unwrap_or_default();
    let autologger_path = format!(r"{}\\Microsoft\\Diagnosis\\ETLLogs\\AutoLogger\\AutoLogger-Diagtrack-Listener.etl", program_data);
    if std::path::Path::new(&autologger_path).exists() {
        std::fs::remove_file(&autologger_path)?;
        let autologger_dir = format!(r"{}\\Microsoft\\Diagnosis\\ETLLogs\\AutoLogger", program_data);
        Command::new("icacls").arg(&autologger_dir).arg("/deny").arg("SYSTEM:(OI)(CI)F").status()?;
    }


    if let Some(tools_path) = manager.get_dependency_path("oneclick_tools") {
        let nsudo_path = tools_path.join("NSudo").join("NSudoLG.exe");
        if !nsudo_path.exists() {
            println!("⚠️  NSudoLG.exe not found. Please install dependencies first.");
            return Ok(());
        }

        let scripts_to_run = vec!["Amd\\AMD.bat", "Sound\\Sound.bat", "Orca\\Orca.bat"];

        for script in scripts_to_run {
            let script_path = tools_path.join(script);
            if script_path.exists() {
                println!("  -> Running {} with TrustedInstaller privileges...", script);
                Command::new(&nsudo_path)
                    .arg("-U:T")
                    .arg("-P:E")
                    .arg("-ShowWindowMode:Hide")
                    .arg(script_path)
                    .status()?;
            } else {
                println!("    -> Script {} not found, skipping.", script);
            }
        }

        println!("✅ Advanced system tweaks applied.");

    } else {
        println!("⚠️  OneClick Tools not found. Please install dependencies first.");
    }

    Ok(())
}


/// Disables all startup applications
fn disable_startup_apps() -> Result<(), Box<dyn std::error::Error>> {
    println!("\nDisabling startup applications...");

    if !prompt_yes_no("This will disable all startup applications. Are you sure?")? {
        println!("Skipping startup application disabling.");
        return Ok(());
    }

    let output = Command::new("wmic").arg("startup").arg("get").arg("caption").arg("/format:list").output()?;
    let output_str = String::from_utf8_lossy(&output.stdout);

    for line in output_str.lines() {
        if line.starts_with("Caption=") {
            let app_name = &line[8..];
            if !app_name.is_empty() {
                println!("  -> Disabling {}", app_name);
                reg_add("HKCU", "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run", app_name, "REG_BINARY", "0300000000000000")?;
                reg_add("HKLM", "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run", app_name, "REG_BINARY", "0300000000000000")?;
            }
        }
    }

    println!("✅ Startup applications disabled.");
    Ok(())
}


/// Replaces Windows Search with Open Shell
async fn replace_windows_search(manager: &DependencyManager) -> Result<(), Box<dyn std::error::Error>> {
    println!("\nReplacing Windows Search with Open Shell...");

    println!("⚠️  WARNING: This is a destructive operation that removes core Windows Search files.");
    println!("  This can only be undone by a system restore. It is not recommended unless you are sure.");

    if !prompt_yes_no("Are you sure you want to continue?")? {
        println!("Skipping search replacement.");
        return Ok(());
    }

    // Files to remove
    let files_to_remove = vec![
        "C:\\Windows\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\SearchHost.exe",
        "C:\\Windows\\SystemApps\\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\\StartMenuExperienceHost.exe",
        "C:\\Windows\\SystemApps\\ShellExperienceHost_cw5n1h2txyewy\\ShellExperienceHost.exe",
        "C:\\Windows\\System32\\taskhostw.exe",
    ];

    println!("  -> Removing search-related executables...");
    for file_path in files_to_remove {
        let p = std::path::Path::new(file_path);
        if p.exists() {
            // Taking ownership and changing permissions is complex from Rust.
            // For now, we will shell out to `takeown` and `icacls`.
            println!("    -> Taking ownership of {}", file_path);
            Command::new("takeown").arg("/F").arg(file_path).status()?;
            println!("    -> Granting admin permissions on {}", file_path);
            Command::new("icacls").arg(file_path).arg("/grant").arg("administrators:F").status()?;
            println!("    -> Deleting {}", file_path);
            std::fs::remove_file(p)?;
        } else {
            println!("    -> {} not found, skipping.", file_path);
        }
    }

    println!("  -> Installing Open Shell...");
    manager.download_on_demand("search_replacement").await?;

    if let Some(open_shell_path) = manager.get_dependency_path("open_shell") {
        if open_shell_path.exists() {
            println!("  -> Launching Open Shell installer...");
            println!("  Please follow the on-screen instructions to install Open Shell.");
            println!("  It is recommended to uncheck 'Classic Explorer' and 'Open-Shell Update'.");
            Command::new(open_shell_path).status()?;

            // Automate theme application
            if let Some(theme_path) = manager.get_dependency_path("open_shell_theme") {
                let start_menu_exe = "C:\\Program Files\\Open-Shell\\StartMenu.exe";
                if std::path::Path::new(start_menu_exe).exists() {
                    println!("  -> Applying Open Shell theme silently...");
                    let command = format!("& \"{}\" -xml \"{}\"", start_menu_exe, theme_path.display());
                    powershell(&command)?;
                    println!("✅ Open Shell theme applied successfully.");
                } else {
                    println!("⚠️  Open Shell StartMenu.exe not found. Cannot apply theme automatically.");
                }
            } else {
                println!("⚠️  Open Shell theme dependency not defined.");
            }

            prompt_continue("Press Enter after you have completed the Open Shell setup...");
        } else {
            println!("⚠️  Open Shell installer not found. Please install dependencies first.");
        }
    } else {
        println!("⚠️  Open Shell not found. Please install dependencies first.");
    }

    Ok(())
}


/// Manages Windows Defender status
fn manage_windows_defender(manager: &DependencyManager) -> Result<(), Box<dyn std::error::Error>> {
    println!("\nManaging Windows Defender...");

    let output = Command::new("sc").arg("query").arg("WinDefend").output()?;
    let output_str = String::from_utf8_lossy(&output.stdout);

    if output_str.contains("RUNNING") {
        println!("  -> Windows Defender is currently running.");
        if prompt_yes_no("Do you want to disable it?")? {
            println!("  Please follow these steps:");
            println!("  1. Open Windows Security (ms-settings:windowsdefender).");
            println!("  2. Go to 'Virus & threat protection' > 'Manage settings'.");
            println!("  3. Turn off 'Real-time protection' and 'Tamper Protection'.");
            powershell("start ms-settings:windowsdefender")?;
            prompt_continue("Press Enter after you have completed the steps...");

            if let Some(tools_path) = manager.get_dependency_path("oneclick_tools") {
                let dcontrol_path = tools_path.join("Dcontrol").join("dControl.exe");
                if dcontrol_path.exists() {
                    println!("  -> Launching dControl.exe...");
                    println!("  In dControl, click 'Disable Windows Defender' and then use the menu to add it to the exclusion list.");
                    Command::new(dcontrol_path).status()?;
                } else {
                    println!("⚠️  dControl.exe not found. Please install dependencies first.");
                }
            } else {
                println!("⚠️  OneClick Tools not found. Please install dependencies first.");
            }
        }
    } else {
        println!("  -> Windows Defender is not running.");
    }

    Ok(())
}


/// Applies game and application specific optimizations
fn apply_game_app_optimizations() -> Result<(), Box<dyn std::error::Error>> {
    println!("\nApplying Game/App Optimizations...");

    let user_profile = std::env::var("USERPROFILE").unwrap_or_default();

    let games = vec![
        "C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\FortniteClient-Win64-Shipping.exe".to_string(),
        format!("{}\\AppData\\Local\\Roblox\\Versions\\RobloxPlayerBeta.exe", user_profile),
        "C:\\Riot Games\\VALORANT\\live\\VALORANT.exe".to_string(),
        "C:\\Program Files (x86)\\Steam\\steamapps\\common\\Counter-Strike 2\\cs2.exe".to_string(),
    ];

    let apps = vec![
        format!("{}\\AppData\\Local\\Discord\\Discord.exe", user_profile),
        format!("{}\\AppData\\Roaming\\Spotify\\Spotify.exe", user_profile),
        "C:\\Program Files (x86)\\Steam\\Steam.exe".to_string(),
    ];

    println!("  -> Setting Games to High Performance and High Priority...");
    for game_path_str in games {
        let game_path = std::path::Path::new(&game_path_str);
        if game_path.exists() {
            let exe_name = game_path.file_name().unwrap().to_str().unwrap();
            println!("    -> Optimizing {}", exe_name);

            // Set GPU preference to High Performance
            reg_add("HKCU", &format!("SOFTWARE\\Microsoft\\DirectX\\UserGpuPreferences"), &game_path.to_str().unwrap(), "REG_SZ", "GpuPreference=2")?;

            // Set CPU priority to High
            reg_add("HKLM", &format!("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\{}/PerfOptions", exe_name), "CpuPriorityClass", "REG_DWORD", "3")?;

            // Disable fullscreen optimizations
            reg_add("HKLM", &format!("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers"), &game_path.to_str().unwrap(), "REG_SZ", "~ DISABLEDXMAXIMIZEDWINDOWEDMODE HIGHDPIAWARE")?;
        }
    }

    println!("  -> Setting Apps to Power Saving and Low Priority...");
    for app_path_str in apps {
        let app_path = std::path::Path::new(&app_path_str);
        if app_path.exists() {
            let exe_name = app_path.file_name().unwrap().to_str().unwrap();
            println!("    -> Optimizing {}", exe_name);

            // Set GPU preference to Power Saving
            reg_add("HKCU", &format!("SOFTWARE\\Microsoft\\DirectX\\UserGpuPreferences"), &app_path.to_str().unwrap(), "REG_SZ", "GpuPreference=1")?;

            // Set CPU priority to Low
            reg_add("HKLM", &format!("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\{}/PerfOptions", exe_name), "CpuPriorityClass", "REG_DWORD", "1")?;
        }
    }

    println!("✅ Game/App optimizations applied.");
    Ok(())
}


/// Applies O&O ShutUp10 tweaks using a config file
fn apply_ooshutup10_tweaks(manager: &DependencyManager) -> Result<(), Box<dyn std::error::Error>> {
    println!("\nApplying O&O ShutUp10 tweaks...");

    if let Some(tools_path) = manager.get_dependency_path("oneclick_tools") {
        let exe_path = tools_path.join("OOshutup10").join("OOSU10.exe");
        let cfg_path = tools_path.join("OOshutup10").join("QuakedOOshutup10.cfg");

        if exe_path.exists() && cfg_path.exists() {
            println!("  -> Running O&O ShutUp10 with custom configuration...");
            Command::new(exe_path)
                .arg(cfg_path)
                .arg("/quiet")
                .stdout(Stdio::null())
                .status()?;
            println!("✅ O&O ShutUp10 tweaks applied successfully.");
        } else {
            println!("⚠️  O&O ShutUp10 or its configuration file not found. Please install dependencies first.");
        }
    } else {
        println!("⚠️  OneClick Tools not found. Please install dependencies first.");
    }

    Ok(())
}






/// Removes common bloatware applications
fn remove_bloatware() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🗑️  Removing bloatware...");

    if !prompt_yes_no("This will attempt to remove over 50 pre-installed and bloatware apps, as well as core Windows components like Edge and OneDrive. Are you sure?")? {
        println!("Skipping bloatware removal.");
        return Ok(());
    }

    let apps_to_remove = vec![
        "*3DBuilder*",
        "*Cortana*",
        "*Getstarted*",
        "*WindowsAlarms*",
        "*WindowsCamera*",
        "*bing*",
        "*MicrosoftOfficeHub*",
        "*OneNote*",
        "*WindowsPhone*",
        "*photos*",
        "*SkypeApp*",
        "*solit*",
        "*WindowsSoundRecorder*",
        "*windowscommunicationsapps*",
        "*zune*",
        "*WindowsCalculator*",
        "*WindowsMaps*",
        "*Sway*",
        "*CommsPhone*",
        "*ConnectivityStore*",
        "*Microsoft.Messaging*",
        "*Microsoft.WindowsStore*",
        "*Microsoft.BingWeather*",
        "*Microsoft.BingSports*",
        "*Microsoft.BingNews*",
        "*Microsoft.BingFinance*",
        "*Microsoft.HEIFImageExtension*",
        "*Microsoft.VP9VideoExtensions*",
        "*Microsoft.WebMediaExtensions*",
        "*Microsoft.WebpImageExtension*",
        "*Microsoft.Office.OneNote*",
        "*Microsoft.Office.Sway*",
        "*Microsoft.StorePurchaseApp*",
        "*Microsoft.XboxApp*",
        "*Microsoft.Xbox.TCUI*",
        "*Microsoft.XboxGamingOverlay*",
        "*Microsoft.XboxGameOverlay*",
        "*Microsoft.XboxIdentityProvider*",
        "*Microsoft.XboxSpeechToTextOverlay*",
        "*Microsoft.Windows.Phone*",
        "*Microsoft.CommsPhone*",
        "*Microsoft.YourPhone*",
        "*Microsoft.Appconnector*",
        "*Microsoft.GetHelp*",
        "*Microsoft.MixedReality.Portal*",
        "*Microsoft.WindowsFeedbackHub*",
        "*Microsoft.MinecraftUWP*",
        "*Microsoft.Wallet*",
        "*Microsoft.OneConnect*",
        "*Microsoft.MicrosoftSolitaireCollection*",
        "*Microsoft.MicrosoftStickyNotes*",
        "*Microsoft.ZuneMusic*",
        "*Microsoft.ZuneVideo*",
        "*Microsoft.GroupMe10*",
        "*king.com.CandyCrushSaga*",
        "*king.com.CandyCrushSodaSaga*",
        "*ShazamEntertainmentLtd.Shazam*",
        "*Flipboard.Flipboard*",
        "*9E2F88E3.Twitter*",
        "*ClearChannelRadioDigital.iHeartRadio*",
        "*D5EA27B7.Duolingo-LearnLanguagesforFree*",
        "*AdobeSystemsIncorporated.AdobePhotoshopExpress*",
        "*PandoraMediaInc.29680B314EFC2*",
        "*46928bounde.EclipseManager*",
        "*ActiproSoftwareLLC.562882FEEB491*",
        "*SpotifyAB.SpotifyMusic*",
        "*Microsoft.Advertising.Xaml*",
        "*Microsoft.RemoteDesktop*",
        "*Microsoft.NetworkSpeedTest*",
        "*Microsoft.Todos*",
        "*Microsoft.Windows.Search*",
        "*Microsoft.Print3D*",
        "*Microsoft.Microsoft3DViewer*",
        "*Microsoft.Windows.Cortana*",
        "*windowsterminal*",
        "*Microsoft.ScreenSketch*",
        "*Microsoft.PowerAutomateDesktop*",
        "*Microsoft.People*",
        "*Microsoft.MSPaint*",
        "*Microsoft.Office.Outlook*",
        "*Microsoft.WindowsNotepad*",
        "*Microsoft.OneDrive*",
        "*Microsoft.ParentalControls*",
        "*Microsoft.549981C3F5F10*", // Cortana
        "*Clipchamp*",
        "*RealtekSemiconductorCorp.RealtekAudioControl*",
        "*HPAudioControl*",
        "*MicrosoftTeams*",
    ];

    for app in apps_to_remove {
        println!("  -> Removing {}", app);
        let command = format!("Get-AppxPackage {} | Remove-AppxPackage -AllUsers", app);
        powershell(&command)?;
    }

    // Microsoft Gaming Services
    println!("  -> Removing Microsoft Gaming Services...");
    powershell("get-appxpackage Microsoft.GamingServices | remove-AppxPackage -AllUsers")?;

    // OneDrive
    println!("  -> Removing OneDrive...");
    powershell("winget uninstall --silent --accept-source-agreements Microsoft.OneDrive")?;
    // Additional OneDrive cleanup from batch script
    reg_add("HKCR", r"CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}", "System.IsPinnedToNameSpaceTree", "REG_DWORD", "0")?;
    reg_add("HKCR", r"Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}", "System.IsPinnedToNameSpaceTree", "REG_DWORD", "0")?;
    // The batch script also loads/unloads HKU\Default and deletes a Run key, which is more complex.

    // Microsoft Edge
    println!("  -> Removing Microsoft Edge...");
    powershell(r"taskkill /f /im msedge.exe")?;
    powershell(r"Remove-Item -Path 'C:\Program Files (x86)\Microsoft\Edge' -Recurse -Force -ErrorAction SilentlyContinue")?;
    powershell(r"Remove-Item -Path 'C:\Program Files (x86)\Microsoft\EdgeCore' -Recurse -Force -ErrorAction SilentlyContinue")?;
    powershell(r"Remove-Item -Path 'C:\Program Files (x86)\Microsoft\EdgeUpdate' -Recurse -Force -ErrorAction SilentlyContinue")?;
    powershell(r"Remove-Item -Path 'C:\Program Files (x86)\Microsoft\EdgeWebView' -Recurse -Force -ErrorAction SilentlyContinue")?;
    powershell(r"Remove-Item -Path 'C:\Program Files (x86)\Microsoft\Temp' -Recurse -Force -ErrorAction SilentlyContinue")?;

    // Windows Widgets
    println!("  -> Removing Windows Widgets...");
    powershell(r#"winget uninstall --silent --accept-source-agreements "Windows web experience Pack""#)?; 


    // Need to handle wildcards in path for takeown/icacls/del
    // This is complex, for now, just print a warning.
    println!("⚠️  Manual deletion of WidgetService.exe and Widgets.exe may be required due to complex pathing.");

    // UsoClient / UsoCoreWorker
    println!("  -> Removing UsoClient / UsoCoreWorker...");
    let system_root = std::env::var("SystemRoot").unwrap_or_default();
    let usoclient_path = format!(r"{}\\System32\\UsoClient.exe", system_root);
    let mousocoreworker_path = format!(r"{}\\UUS\\amd64\\MoUsoCoreWorker.exe", system_root);
    let files_to_delete = vec![usoclient_path, mousocoreworker_path];
    for file_path in files_to_delete {
        let p = std::path::Path::new(&file_path);
        if p.exists() {
            println!("    -> Taking ownership of {}", file_path);
            Command::new("takeown").arg("/F").arg(&file_path).status()?;
            println!("    -> Granting admin permissions on {}", file_path);
            Command::new("icacls").arg(&file_path).arg("/grant").arg("administrators:F").status()?;
            println!("    -> Deleting {}", file_path);
            std::fs::remove_file(p)?;
        } else {
            println!("    -> {} not found, skipping.", file_path);
        }
    }

    // Individual EXE Files
    println!("  -> Removing individual executable files...");
    let gamebar_path = format!(r"{}\\System32\\GameBarPresenceWriter.exe", system_root);
    let smartscreen_path1 = format!(r"{}\\System32\\smartscreen.exe", system_root);
    let smartscreen_path2 = format!(r"{}\\SystemApps\\Microsoft.Windows.AppRep.ChxApp_*\\CHXSmartScreen.exe", system_root);
    let lockapp_path = format!(r"{}\\SystemApps\\Microsoft.LockApp_*\\LockApp.exe", system_root);

    let individual_exes = vec![gamebar_path, smartscreen_path1, smartscreen_path2, lockapp_path];
    for file_path in individual_exes {
        let p = std::path::Path::new(&file_path);
        if p.exists() {
            println!("    -> Taking ownership of {}", file_path);
            Command::new("takeown").arg("/F").arg(&file_path).status()?;
            println!("    -> Granting admin permissions on {}", file_path);
            Command::new("icacls").arg(&file_path).arg("/grant").arg("administrators:F").status()?;
            println!("    -> Deleting {}", file_path);
            std::fs::remove_file(p)?;
        } else {
            println!("    -> {} not found, skipping.", file_path);
        }
    }

    println!("✅ Bloatware removal complete.");
    Ok(())
}

/// Creates a system restore point
fn create_restore_point() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🛡️  It is highly recommended to create a system restore point before proceeding.");
    if prompt_yes_no("Do you want to create a restore point now?")? {
        println!("  -> Enabling System Restore...");
        powershell("Enable-ComputerRestore -Drive \"C:\"")?;

        println!("  -> Creating restore point... (This may take a moment)");
        let description = format!("OneClick Optimizer v{} Restore Point", VERSION);
        let command = format!("Checkpoint-Computer -Description \"{}\"", description);
        powershell(&command)?;

        println!("✅ Restore point created successfully.");
    } else {
        println!("Skipping restore point creation.");
    }
    Ok(())
}


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

    // Check for admin rights
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

    // Get OS build info
    let mut sys = System::new_all();
    sys.refresh_all();
    let os_version = sys.os_version().unwrap_or_default();
    let build_number: u32 = sys.kernel_version().unwrap_or_default().split('.').last().unwrap_or("0").parse().unwrap_or(0);
    let is_win11 = os_version.contains("Windows 11");

    SystemInfo {
        is_admin,
        is_win11,
        build_number,
    }
}

/// Get the GUID of the primary active network adapter
fn get_active_network_adapter_guid() -> Option<String> {
    if let Ok(adapters) = ipconfig::get_adapters() {
        adapters.iter().find_map(|adapter| {
            if adapter.oper_status() == ipconfig::OperStatus::IfOperStatusUp && adapter.ip_addresses().iter().any(|ip| ip.is_ipv4()) {
                Some(adapter.adapter_name().to_string())
            } else {
                None
            }
        })
    } else {
        None
    }
}


/// Apply general performance tweaks via the Registry
fn apply_basic_tweaks() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n⚙️  Applying basic system tweaks...");

    // Disable Nagle's Algorithm (improves network latency)
    if let Some(guid) = get_active_network_adapter_guid() {
        println!("  -> Found active network adapter: {}", guid);
        let key_path = format!("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{}", guid);
        reg_add(
            "HKLM",
            &key_path,
            "TcpNoDelay",
            "REG_DWORD",
            "1",
        )?;
        reg_add(
            "HKLM",
            &key_path,
            "TcpAckFrequency",
            "REG_DWORD",
            "1",
        )?;
    } else {
        println!("⚠️  Could not find active network adapter. Skipping network tweaks.");
    }

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

    // Clear DNS Cache and other network settings
    println!("  -> Cleaning network settings...");
    powershell("ipconfig /flushdns")?;
    powershell("ipconfig /release")?;
    powershell("ipconfig /renew")?;
    powershell("arp -d *")?;
    powershell("nbtstat -R")?;
    powershell("nbtstat -RR")?;

    // Clean Windows Update cache (BITS)
    println!("  -> Cleaning Windows Update cache...");
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
    println!("  (Original Oneclick project by Quaked, inspiring SwiftOptimizer)");

    // Download all dependencies needed for the "core" features initially
    let required = vec!["core".to_string()];
    manager.download_required(&required).await?;

    // If the user wants to download ALL dependencies, uncomment the line below:
    // manager.download_required(&[]).await?;

    println!("✅ Dependencies status updated.");
    Ok(())
}
