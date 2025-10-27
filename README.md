# SwifttOptimizer (Rust Rewrite of OneClick Optimizer)

![SwifttOptimizer Banner](https://raw.githubusercontent.com/QuakedK/Oneclick/main/Images/Banner.png)

## Project Background

SwifttOptimizer is a complete **Rust rewrite** of the original **Oneclick-V7.0.bat** project. The original batch script automated various system and gaming performance tweaks using Windows command-line utilities. This Rust rewrite aims to modernize the tool with enhanced stability, structure, and performance, while maintaining the same optimization goals.

## Project Overview

SwifttOptimizer is a **Rust-based command-line utility for Windows** designed to apply performance tweaks, manage dependencies, and perform system cleaning. It offers a **menu-driven interface** that replicates and enhances the behavior of the original batch script, providing better error handling, modularity, and cross-version compatibility.

## Features

SwifttOptimizer provides a comprehensive set of optimization features, accessible through an interactive, colored CLI menu:

### Core Actions:
*   **Create Restore Point**: Creates a system restore point, allowing you to revert changes if needed.

### System Tweaks:

*   **Apply Basic Tweaks (Registry)**: Applies fundamental system optimizations via registry modifications.
*   **Apply Latency Tweaks (BCD/Reg)**: Reduces system latency through Boot Configuration Data (BCD) and registry adjustments.
*   **Apply System & Privacy Tweaks**: Enhances system privacy and applies general performance-oriented system settings.
*   **Apply Advanced System Tweaks**: Implements advanced system optimizations using NSudo and other powerful methods.
*   **Disable Unnecessary Services**: Disables a wide range of non-essential Windows services to free up resources.
*   **Apply Additional Service Tweaks**: Applies specific service configurations from curated lists (e.g., PiF, Quaked's tweaks).
*   **Disable Scheduled Tasks**: Disables various scheduled tasks that can consume system resources.
*   **Set Win32PrioritySeparation**: Configures CPU scheduling to prioritize foreground or background tasks, with multiple profiles for gaming and general use.
*   **Disable Unnecessary Devices**: Disables non-essential Plug and Play (PnP) devices.
*   **Apply GPU & Interrupt Tweaks**: Applies optimizations specific to GPU performance and interrupt handling (currently supports Nvidia).
*   **Set Windows Process Priorities**: Sets custom CPU priorities for core Windows processes.

### Specific Optimizations:

*   **Apply Game Tweaks**: Applies tweaks specifically designed to improve gaming performance.
*   **Apply Game/App Optimizations**: Optimizes specific games and applications for better performance and resource usage.
*   **Manage Windows Defender**: Provides options to manage Windows Defender settings.
*   **Replace Windows Search**: Replaces the default Windows Search with Open-Shell for a lighter alternative, with automated theme application.
*   **Apply O&O ShutUp10 Tweaks**: Integrates O&O ShutUp10 to apply a set of privacy and system tweaks using a custom configuration.

### Tools & Utilities:

*   **Clean System (Temp Files)**: Cleans temporary files, cache, and prefetch data to free up disk space.
*   **Remove Bloatware**: Removes pre-installed and bloatware applications, including core Windows components like Edge and OneDrive.
*   **Disable Startup Apps**: Disables all applications configured to run at system startup.
*   **Extras**: Access to additional utilities and experimental features.

## Building and Running

### Prerequisites

*   **Rust and Cargo**: Ensure you have Rust and Cargo installed. If not, you can install them from [rustup.rs](https://rustup.rs/).
*   **Windows Operating System**: This tool is designed specifically for Windows.

### Building the Project

To compile the project in release mode, run the following command in your terminal:

```sh
cargo build --release
```

### Running the Application

To execute the tool via Cargo:

```sh
cargo run
```

Alternatively, you can navigate to the `target/release` directory after building and run the compiled executable directly:

```sh
.\target\release\swift_optimizer.exe
```

**Note**: The application requires Administrator privileges to apply most system tweaks. It will prompt you if not run as Administrator.


## Legacy Reference

**`Oneclick-V7.0.bat`** — The original batch-based optimizer that inspired this rewrite. Its functionality, logic flow, and tweak sets form the foundation of SwifttOptimizer’s architecture, now rebuilt in Rust for improved reliability and maintainability.
