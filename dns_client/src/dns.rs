use anyhow::Result;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts, NameServerConfig};
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::proto::rr::RecordType;
use std::net::SocketAddr;
use std::time::Duration;
use std::str::FromStr;

pub struct DnsClient {
    resolver: TokioAsyncResolver,
    timeout: Duration,
}

impl DnsClient {
    pub async fn new(dns_server: &str, timeout: Duration) -> Result<Self> {
        let mut opts = ResolverOpts::default();
        opts.use_hosts_file = false;
        opts.timeout = timeout;
        
        let addr = SocketAddr::from_str(&format!("{}:53", dns_server))
            .map_err(|_| anyhow::anyhow!(""))?;
        let name_server_config = NameServerConfig::new(addr, trust_dns_resolver::config::Protocol::Udp);
        
        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::from_parts(
                None,
                vec![],
                vec![name_server_config],
            ),
            opts,
        );

        Ok(Self { 
            resolver, 
            timeout,
        })
    }

    pub async fn query_txt(&mut self, name: &str) -> Result<Option<String>> {
        match tokio::time::timeout(self.timeout, self.resolver.lookup(name, RecordType::TXT)).await {
            Ok(Ok(response)) => {
                if let Some(txt) = response.iter().next() {
                    if let Some(txt_data) = txt.as_txt() {
                        let txt_str = txt_data.txt_data()
                            .iter()
                            .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
                            .collect::<String>();
                        if txt_str.is_empty() {
                            return Ok(None);
                        }
                        return Ok(Some(txt_str));
                    }
                }
                Ok(None)
            },
            Ok(Err(e)) => {
                let error_msg = e.to_string();
                if error_msg.contains("10054") {
                    return Err(anyhow::anyhow!(""));
                }
                Ok(None)
            },
            Err(_) => {
                Ok(None)
            }
        }
    }

    pub async fn query_a(&mut self, name: &str) -> Result<Option<String>> {
        match tokio::time::timeout(self.timeout, self.resolver.lookup(name, RecordType::A)).await {
            Ok(Ok(response)) => {
                if let Some(record) = response.iter().next() {
                    if let Some(ip) = record.as_a() {
                        let hex_str = ip.octets()
                            .iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<String>();
                        return Ok(Some(hex_str));
                    }
                }
                Ok(None)
            },
            Ok(Err(e)) => {
                let error_msg = e.to_string();
                if error_msg.contains("10054") {
                    return Err(anyhow::anyhow!(""));
                }
                Ok(None)
            },
            Err(_) => {
                Ok(None)
            }
        }
    }
} 