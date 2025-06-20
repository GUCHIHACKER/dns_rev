use std::process::Command;
use anyhow::{Result, anyhow};

#[cfg(target_os = "windows")]
pub fn run_command(cmd: &str) -> Result<String> {
    let output = Command::new("powershell")
        .args(["-Command", cmd])
        .output()
        .map_err(|_| anyhow!(""))?;
    
    let mut result = String::new();
    if !output.stdout.is_empty() {
        result.push_str(&String::from_utf8_lossy(&output.stdout));
    }
    if !output.stderr.is_empty() {
        if !result.is_empty() {
            result.push_str("\n");
        }
        result.push_str(&format!("Error (código {}): {}", 
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr)));
    }
    Ok(result)
}

#[cfg(not(target_os = "windows"))]
pub fn run_command(cmd: &str) -> Result<String> {
    let output = Command::new("sh")
        .args(["-c", cmd])
        .output()?;
    
    let mut result = String::new();
    if !output.stdout.is_empty() {
        result.push_str(&String::from_utf8_lossy(&output.stdout));
    }
    if !output.stderr.is_empty() {
        result.push_str(&String::from_utf8_lossy(&output.stderr));
    }
    Ok(result)
} 