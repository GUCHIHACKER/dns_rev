use anyhow::{Result, anyhow};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};

pub struct Cipher {
    cipher: ChaCha20Poly1305,
    nonce: Vec<u8>,
}

impl Cipher {
    pub fn new(key: &[u8], nonce: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            return Err(anyhow!(""));
        }
        if nonce.len() != 12 {
            return Err(anyhow!(""));
        }

        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| anyhow!(""))?;

        Ok(Self {
            cipher,
            nonce: nonce.to_vec(),
        })
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let nonce = Nonce::from_slice(&self.nonce);
        self.cipher
            .encrypt(nonce, data)
            .map_err(|_| anyhow!(""))
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let nonce = Nonce::from_slice(&self.nonce);
        self.cipher
            .decrypt(nonce, data)
            .map_err(|_| anyhow!(""))
    }
}

pub fn hex_encode(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(s.len() / 2);
    let mut chars = s.chars();
    
    while let (Some(a), Some(b)) = (chars.next(), chars.next()) {
        let byte_str = format!("{}{}", a, b);
        let byte = u8::from_str_radix(&byte_str, 16)
            .map_err(|_| anyhow!(""))?;
        bytes.push(byte);
    }
    
    Ok(bytes)
} 