//! HTTP-based signing implementation for external signing services.
//!
//! This module provides support for signing using external HTTP endpoints,
//! with optional mutual TLS (mTLS) authentication.

use crate::crypto::{MessageDigest, SignatureAlgorithm, SigningPrivateKey, SigningPublicKey};
use crate::error::CoseError;

use std::collections::HashMap;
use std::fs;
use std::time::Duration;

/// Default request template: `{"message":"{payload}"}`
const DEFAULT_REQUEST_TEMPLATE: &str = r#"{"message":"{payload}"}"#;

/// Default response template: `{"signature":"{signature}"}`
const DEFAULT_RESPONSE_TEMPLATE: &str = r#"{"signature":"{signature}"}"#;

/// Placeholder for payload in request template
const PAYLOAD_PLACEHOLDER: &str = "{payload}";

/// Placeholder for signature in response template
const SIGNATURE_PLACEHOLDER: &str = "{signature}";

/// HTTP request timeout in seconds
const HTTP_TIMEOUT_SECS: u64 = 30;

/// Configuration for HTTP-based signing.
#[derive(Debug, Clone)]
pub struct HttpSigningConfig {
    /// The base URL for the signing endpoint
    pub url: String,
    /// Optional path to client certificate for mTLS
    pub client_cert_path: Option<String>,
    /// Optional path to client private key for mTLS
    pub client_key_path: Option<String>,
    /// Optional path to a trusted CA certificate (PEM) to use for TLS verification.
    /// Can be supplied via the URL parameter `;ca=/path/to/ca.pem`.
    pub ca_path: Option<String>,
    /// Request template with {payload} placeholder
    pub request_template: String,
    /// Response template with {signature} placeholder
    pub response_template: String,
    /// Signing algorithm (ES384 or ES512, defaults to ES384)
    pub algorithm: SignatureAlgorithm,
    /// Support pre digest values
    pub pre_digest: bool,
}

impl HttpSigningConfig {
    /// Parse an HTTP signing URL into a configuration.
    ///
    /// # Format
    ///
    /// ```text
    /// https://host:port/path;algorithm={algo};client_cert={path};client_key={path};request_template={base64};response_template={base64}
    /// ```
    pub fn parse(url_str: &str) -> Result<Self, CoseError> {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        // Split by semicolon to get URL and parameters
        let parts: Vec<&str> = url_str.splitn(2, ';').collect();
        let base_url = parts[0].to_string();

        // Validate URL starts with https://
        if !base_url.starts_with("https://") {
            return Err(CoseError::UnsupportedError(
                "HTTP signing URL must use HTTPS".to_string(),
            ));
        }

        // Parse parameters if present
        let mut params: HashMap<String, String> = HashMap::new();
        if parts.len() > 1 {
            for param in parts[1].split(';') {
                if let Some((key, value)) = param.split_once('=') {
                    params.insert(key.to_string(), value.to_string());
                }
            }
        }

        // Extract client certificate and key paths
        let client_cert_path = params.get("client_cert").cloned();
        let client_key_path = params.get("client_key").cloned();

        // Validate that both cert and key are provided together
        if client_cert_path.is_some() != client_key_path.is_some() {
            return Err(CoseError::UnsupportedError(
                "Both client_cert and client_key must be provided for mTLS".to_string(),
            ));
        }

        // Extract CA path from URL param "ca" (if present)
        let ca_path = params.get("ca").cloned();

        // Parse request template (base64 encoded)
        let request_template = match params.get("request_template") {
            Some(b64) => {
                let decoded = BASE64.decode(b64).map_err(|e| {
                    CoseError::UnsupportedError(format!(
                        "Failed to decode request_template: {}",
                        e
                    ))
                })?;
                String::from_utf8(decoded).map_err(|e| {
                    CoseError::UnsupportedError(format!(
                        "Invalid UTF-8 in request_template: {}",
                        e
                    ))
                })?
            }
            None => DEFAULT_REQUEST_TEMPLATE.to_string(),
        };

        // Parse response template (base64 encoded)
        let response_template = match params.get("response_template") {
            Some(b64) => {
                let decoded = BASE64.decode(b64).map_err(|e| {
                    CoseError::UnsupportedError(format!(
                        "Failed to decode response_template: {}",
                        e
                    ))
                })?;
                String::from_utf8(decoded).map_err(|e| {
                    CoseError::UnsupportedError(format!(
                        "Invalid UTF-8 in response_template: {}",
                        e
                    ))
                })?
            }
            None => DEFAULT_RESPONSE_TEMPLATE.to_string(),
        };

        // Validate templates contain required placeholders
        if !request_template.contains(PAYLOAD_PLACEHOLDER) {
            return Err(CoseError::UnsupportedError(format!(
                "Request template must contain {} placeholder",
                PAYLOAD_PLACEHOLDER
            )));
        }
        if !response_template.contains(SIGNATURE_PLACEHOLDER) {
            return Err(CoseError::UnsupportedError(format!(
                "Response template must contain {} placeholder",
                SIGNATURE_PLACEHOLDER
            )));
        }

        // Parse algorithm (defaults to ES384)
        let algorithm = match params.get("algorithm") {
            Some(alg_str) => alg_str.parse::<SignatureAlgorithm>()?,
            None => SignatureAlgorithm::ES384,
        };

        // Parse algorithm (defaults to ES384)
        let pre_digest = match params.get("pre_digest") {
            Some(pre_digest_str) => {
                match pre_digest_str.parse::<bool>() {
                    Ok(resp) => {resp}
                    Err(err) => {
                        return Err(CoseError::UnsupportedError(format!(
                            "Failed to parse pre_digest as bool error {}",
                            err
                        )));
                    }
                }
            },
            None => true,
        };

        // // Validate algorithm is ES384 or ES512 (not ES256)
        // if matches!(algorithm, SignatureAlgorithm::ES256) {
        //     return Err(CoseError::UnsupportedError(
        //         "ES256 is not supported for HTTP signing. Use ES384 or ES512.".to_string(),
        //     ));
        // }

        Ok(HttpSigningConfig {
            url: base_url,
            client_cert_path,
            client_key_path,
            ca_path,
            request_template,
            response_template,
            algorithm,
            pre_digest
        })
    }
}

/// Check if a private key string is an HTTP signing URL.
pub fn is_http_signing_url(key_location: &str) -> bool {
    key_location.starts_with("https://")
}

/// HTTP-based signing key for external signing services.
pub struct HttpSigningKey {
    config: HttpSigningConfig,
    client: reqwest::blocking::Client,
}

impl HttpSigningKey {
    /// Create a new HTTP signing key from a URL string.
    ///
    /// # Arguments
    ///
    /// * `url_str` - The HTTP signing URL with optional parameters
    ///
    /// # Example URL formats
    ///
    /// ```text
    /// https://signing.example.com/v2/core/sign/ecdsa
    /// https://signing.example.com/sign;algorithm=ES512
    /// https://signing.example.com/sign;client_cert=/path/cert.pem;client_key=/path/key.pem
    /// ```
    pub fn new(url_str: &str) -> Result<Self, CoseError> {
        let config = HttpSigningConfig::parse(url_str)?;
        let client = Self::build_client(&config)?;
        Ok(HttpSigningKey { config, client })
    }

    /// Build an HTTP client with optional mTLS configuration.
    fn build_client(config: &HttpSigningConfig) -> Result<reqwest::blocking::Client, CoseError> {
        let mut builder = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
            .danger_accept_invalid_certs(false);

        // Configure mTLS if client cert and key are provided
        if let (Some(cert_path), Some(key_path)) =
            (&config.client_cert_path, &config.client_key_path)
        {
            let cert_pem = fs::read(cert_path).map_err(|e| {
                CoseError::UnsupportedError(format!(
                    "Failed to read client certificate '{}': {}",
                    cert_path, e
                ))
            })?;

            let key_pem = fs::read(key_path).map_err(|e| {
                CoseError::UnsupportedError(format!(
                    "Failed to read client key '{}': {}",
                    key_path, e
                ))
            })?;

            // Combine cert and key into a single PEM for Identity
            let mut identity_pem = cert_pem;
            identity_pem.extend_from_slice(b"\n");
            identity_pem.extend_from_slice(&key_pem);

            let identity = reqwest::Identity::from_pem(&identity_pem).map_err(|e| {
                CoseError::UnsupportedError(format!("Failed to create client identity: {}", e))
            })?;

            builder = builder.identity(identity);
        }

        // Configure custom root CA if provided via config.ca_path
        if let Some(ca_path) = &config.ca_path {
            let ca_pem = fs::read(ca_path).map_err(|e| {
                CoseError::UnsupportedError(format!(
                    "Failed to read CA certificate '{}': {}",
                    ca_path, e
                ))
            })?;
            let cert = reqwest::Certificate::from_pem(&ca_pem).map_err(|e| {
                CoseError::UnsupportedError(format!(
                    "Failed to parse CA certificate '{}': {}",
                    ca_path, e
                ))
            })?;
            builder = builder.add_root_certificate(cert);
        }

        builder
            .build()
            .map_err(|e| CoseError::UnsupportedError(format!("Failed to build HTTP client: {}", e)))
    }

    /// Get the signing algorithm.
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.config.algorithm
    }

    /// Get the URL of the signing endpoint.
    pub fn url(&self) -> &str {
        &self.config.url
    }

    /// Send a signing request to the HTTP endpoint.
    ///
    /// # Arguments
    ///
    /// * `payload` - The raw bytes to sign (typically a hash)
    ///
    /// # Returns
    ///
    /// The signature bytes on success.
    fn send_signing_request(&self, payload: &[u8]) -> Result<Vec<u8>, CoseError> {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        // Base64 encode the payload
        let payload_b64 = BASE64.encode(payload);

        // Build request body from template
        let request_body = self
            .config
            .request_template
            .replace(PAYLOAD_PLACEHOLDER, &payload_b64);

        // Parse as JSON to validate and send
        let request_json: serde_json::Value = serde_json::from_str(&request_body).map_err(|e| {
            CoseError::UnsupportedError(format!(
                "Request template produced invalid JSON: {}",
                e
            ))
        })?;

        // Send POST request
        let response = self
            .client
            .post(&self.config.url)
            .header("Content-Type", "application/json")
            .json(&request_json)
            .send()
            .map_err(|e| {
                CoseError::SignatureError(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("HTTP request failed: {}", e),
                )))
            })?;

        // Check response status
        if !response.status().is_success() {
            return Err(CoseError::SignatureError(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "HTTP request returned status {}: {}",
                    response.status(),
                    response.text().unwrap_or_default()
                ),
            ))));
        }

        // Parse response body
        let response_text = response.text().map_err(|e| {
            CoseError::SignatureError(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to read response body: {}", e),
            )))
        })?;

        // Extract signature from response using template
        let signature_b64 = self.extract_signature(&response_text)?;

        // Decode base64 signature
        let signature = BASE64.decode(&signature_b64).map_err(|e| {
            CoseError::SignatureError(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to decode signature: {}", e),
            )))
        })?;

        // Convert signature (DER/ASN.1 or raw) into raw R||S format expected by library
        let key_len = self.config.algorithm.key_length();
        let raw_signature = convert_server_signature(&signature, key_len)?;

        Ok(raw_signature)
    }

    /// Extract signature from response using the response template.
    fn extract_signature(&self, response_text: &str) -> Result<String, CoseError> {
        // Parse response as JSON
        let response_json: serde_json::Value =
            serde_json::from_str(response_text).map_err(|e| {
                CoseError::SignatureError(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Response is not valid JSON: {}", e),
                )))
            })?;

        // Find the path to the signature in the template
        let signature_path = self.find_signature_path()?;

        // Navigate to the signature value
        let mut current = &response_json;
        for key in &signature_path {
            current = current.get(key).ok_or_else(|| {
                CoseError::SignatureError(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!(
                        "Response missing expected field '{}'. Response: {}",
                        key, response_text
                    ),
                )))
            })?;
        }

        // Extract string value
        current
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| {
                CoseError::SignatureError(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Signature field is not a string. Response: {}", response_text),
                )))
            })
    }

    /// Find the JSON path to the signature placeholder in the response template.
    fn find_signature_path(&self) -> Result<Vec<String>, CoseError> {
        let template_json: serde_json::Value =
            serde_json::from_str(&self.config.response_template).map_err(|e| {
                CoseError::UnsupportedError(format!(
                    "Response template is not valid JSON: {}",
                    e
                ))
            })?;

        let mut path = Vec::new();
        if self.find_placeholder_path(&template_json, SIGNATURE_PLACEHOLDER, &mut path) {
            Ok(path)
        } else {
            Err(CoseError::UnsupportedError(
                "Could not find signature placeholder in response template".to_string(),
            ))
        }
    }

    /// Recursively find the path to a placeholder in a JSON value.
    fn find_placeholder_path(
        &self,
        value: &serde_json::Value,
        placeholder: &str,
        path: &mut Vec<String>,
    ) -> bool {
        match value {
            serde_json::Value::String(s) if s == placeholder => true,
            serde_json::Value::Object(map) => {
                for (key, val) in map {
                    path.push(key.clone());
                    if self.find_placeholder_path(val, placeholder, path) {
                        return true;
                    }
                    path.pop();
                }
                false
            }
            serde_json::Value::Array(arr) => {
                for (idx, val) in arr.iter().enumerate() {
                    path.push(idx.to_string());
                    if self.find_placeholder_path(val, placeholder, path) {
                        return true;
                    }
                    path.pop();
                }
                false
            }
            _ => false,
        }
    }
}

/// Convert a server-returned signature into raw R||S format (big-endian padded to key_len)
fn convert_server_signature(sig_bytes: &[u8], key_len: usize) -> Result<Vec<u8>, CoseError> {
    use openssl::ecdsa::EcdsaSig;

    // Try DER parse first
    if let Ok(der_sig) = EcdsaSig::from_der(sig_bytes) {
        let r_vec = der_sig.r().to_vec();
        let s_vec = der_sig.s().to_vec();

        assert!(r_vec.len() <= key_len);
        assert!(s_vec.len() <= key_len);

        let mut signature_bytes = vec![0u8; key_len * 2];
        let offset_r = key_len - r_vec.len();
        signature_bytes[offset_r..offset_r + r_vec.len()].copy_from_slice(&r_vec);
        let offset_s = key_len - s_vec.len() + key_len;
        signature_bytes[offset_s..offset_s + s_vec.len()].copy_from_slice(&s_vec);
        return Ok(signature_bytes);
    }

    // If not DER, maybe already raw R||S
    if sig_bytes.len() == key_len * 2 {
        return Ok(sig_bytes.to_vec());
    }

    // As a last resort, try to interpret as ASN.1 DER sequence manually via EcdsaSig::from_der failed;
    // report unsupported format
    Err(CoseError::SignatureError(Box::new(std::io::Error::new(
        std::io::ErrorKind::Other,
        format!("Unsupported signature format or unexpected length: {} bytes", sig_bytes.len()),
    ))))
}

impl SigningPublicKey for HttpSigningKey {
    fn get_parameters(&self) -> Result<(SignatureAlgorithm, MessageDigest), CoseError> {
        Ok((
            self.config.algorithm,
            self.config.algorithm.suggested_message_digest(),
        ))
    }

    fn verify(&self, _digest: &[u8], _signature: &[u8]) -> Result<bool, CoseError> {
        // HTTP signing keys cannot verify signatures locally
        // Verification would need to be done by the signing service or using the certificate
        Err(CoseError::UnsupportedError(
            "HTTP signing keys do not support local signature verification".to_string(),
        ))
    }
}

impl SigningPrivateKey for HttpSigningKey {
    /// Sign data using the HTTP endpoint.
    ///
    /// # Arguments
    ///
    /// * `digest` - The hash digest to sign
    ///
    /// # Returns
    ///
    /// The signature bytes in raw format (R || S)
    fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, CoseError> {
        self.send_signing_request(digest)
    }

    fn sign_with_digest(&self) -> bool {
        self.config.pre_digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_http_signing_url() {
        assert!(is_http_signing_url("https://example.com/sign"));
        assert!(is_http_signing_url("https://localhost:8443/v2/sign"));
        assert!(!is_http_signing_url("http://example.com/sign"));
        assert!(!is_http_signing_url("/path/to/key.pem"));
        assert!(!is_http_signing_url("arn:aws:kms:us-west-2:123:key/abc"));
    }

    #[test]
    fn test_parse_basic_url() {
        let config = HttpSigningConfig::parse("https://example.com/v2/sign").unwrap();
        assert_eq!(config.url, "https://example.com/v2/sign");
        assert!(config.client_cert_path.is_none());
        assert!(config.client_key_path.is_none());
        assert_eq!(config.request_template, DEFAULT_REQUEST_TEMPLATE);
        assert_eq!(config.response_template, DEFAULT_RESPONSE_TEMPLATE);
        assert!(matches!(config.algorithm, SignatureAlgorithm::ES384));
    }

    #[test]
    fn test_parse_url_with_mtls() {
        let url =
            "https://example.com/sign;client_cert=/path/to/cert.pem;client_key=/path/to/key.pem";
        let config = HttpSigningConfig::parse(url).unwrap();
        assert_eq!(config.url, "https://example.com/sign");
        assert_eq!(
            config.client_cert_path,
            Some("/path/to/cert.pem".to_string())
        );
        assert_eq!(
            config.client_key_path,
            Some("/path/to/key.pem".to_string())
        );
    }

    #[test]
    fn test_parse_url_with_algorithm_es384() {
        let config =
            HttpSigningConfig::parse("https://example.com/sign;algorithm=ES384").unwrap();
        assert!(matches!(config.algorithm, SignatureAlgorithm::ES384));
    }

    #[test]
    fn test_parse_url_with_algorithm_es512() {
        let config =
            HttpSigningConfig::parse("https://example.com/sign;algorithm=ES512").unwrap();
        assert!(matches!(config.algorithm, SignatureAlgorithm::ES512));
    }

    #[test]
    fn test_parse_url_http_rejected() {
        let result = HttpSigningConfig::parse("http://example.com/sign");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_url_mtls_incomplete() {
        // Only cert, no key
        let result =
            HttpSigningConfig::parse("https://example.com/sign;client_cert=/path/cert.pem");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_url_with_custom_templates() {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        let req_template_b64 = BASE64.encode(r#"{"data":"{payload}"}"#);
        let resp_template_b64 = BASE64.encode(r#"{"sig":"{signature}"}"#);

        let url = format!(
            "https://example.com/sign;request_template={};response_template={}",
            req_template_b64, resp_template_b64
        );
        let config = HttpSigningConfig::parse(&url).unwrap();
        assert_eq!(config.request_template, r#"{"data":"{payload}"}"#);
        assert_eq!(config.response_template, r#"{"sig":"{signature}"}"#);
    }

    #[test]
    fn test_parse_url_invalid_request_template() {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        // Template without {payload} placeholder
        let bad_template_b64 = BASE64.encode(r#"{"data":"fixed"}"#);
        let url = format!(
            "https://example.com/sign;request_template={}",
            bad_template_b64
        );
        let result = HttpSigningConfig::parse(&url);
        assert!(result.is_err());
    }

    #[test]
    #[ignore = "run manually, requires local server"]
    fn test_http_signing_key_sign_sha384() {
        std::env::set_var("RUST_LOG", "trace");
        let bytes: [u8; 48] = [42, 24, 37, 97, 171, 250, 172, 219, 37, 215, 152, 47, 101, 223, 49, 28, 17, 246, 42, 7, 66, 10, 162, 186, 9, 164, 3, 193, 208, 254, 125, 10, 103, 97, 40, 97, 104, 142, 211, 78, 252, 167, 27, 200, 39, 171, 152, 59, ];
        let signing_key =
            HttpSigningKey::new("https://127.0.0.1:8098/v2/core/sign/ecdsa-sha384;algorithm=ES384;ca=root-ca.pem").unwrap();
        signing_key.sign(&bytes).unwrap();
    }
}
