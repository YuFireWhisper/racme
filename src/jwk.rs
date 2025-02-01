use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::{base64::Base64, key_pair::KeyPair};

/// JWK相關操作的錯誤類型。
///
/// 此錯誤類型涵蓋JWK產生與序列化過程中可能發生的錯誤，
/// 並提供對應的錯誤訊息以輔助除錯。
#[derive(Debug, Error)]
pub enum JwkError {
    /// 不支援的演算法。
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    /// 金鑰轉換失敗。
    #[error("Failed to convert key: {0}")]
    KeyConversionError(String),
    /// 序列化錯誤。
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

/// JSON Web Key (JWK) 的封裝，目前僅支援 RSA 格式。
///
/// 此列舉未來可以擴充以支援其他金鑰類型。
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kty")]
pub enum Jwk {
    /// RSA 格式的 JWK。
    #[serde(rename = "RSA")]
    Rsa(RsaJwk),
}

/// RSA 格式的 JWK 結構，包含必要的公開參數。
#[derive(Debug, Serialize, Deserialize)]
pub struct RsaJwk {
    n: String,
    e: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alg: Option<String>,
}

impl RsaJwk {
    /// 根據給定的金鑰對產生 RSA 格式的 JWK。
    ///
    /// # 參數
    ///
    /// * `key_pair` - 包含公鑰資訊的金鑰對。
    /// * `kid` - 可選的金鑰識別符 (Key ID)。
    ///
    /// # 返回
    ///
    /// 成功時返回構造好的 `RsaJwk`，否則返回 `JwkError`。
    fn from_key_pair(key_pair: &KeyPair, kid: Option<String>) -> Result<Self, JwkError> {
        let rsa = key_pair
            .pub_key
            .rsa()
            .map_err(|e| JwkError::KeyConversionError(e.to_string()))?;

        let n = Base64::new(rsa.n().to_vec()).base64_url();
        let e = Base64::new(rsa.e().to_vec()).base64_url();
        let alg = Some(String::from("RS256"));

        Ok(RsaJwk { n, e, kid, alg })
    }

    /// 產生符合 ACME 協議要求的 JSON 表示。
    ///
    /// # 返回
    ///
    /// 成功時返回 JSON 格式字串，否則返回 `JwkError`。
    pub fn to_acme_json(&self) -> Result<String, JwkError> {
        let mut map = Map::new();
        map.insert("e".to_string(), Value::String(self.e.clone()));
        map.insert("kty".to_string(), Value::String("RSA".to_string()));
        map.insert("n".to_string(), Value::String(self.n.clone()));

        serde_json::to_string(&Value::Object(map)).map_err(JwkError::from)
    }
}

impl Jwk {
    /// 根據給定的金鑰對建立對應的 JWK。
    ///
    /// # 參數
    ///
    /// * `key_pair` - 包含演算法資訊與公鑰的金鑰對。
    /// * `kid` - 可選的金鑰識別符。
    ///
    /// # 返回
    ///
    /// 成功時返回對應類型的 `Jwk`，否則返回 `JwkError`。
    pub fn new(key_pair: &KeyPair, kid: Option<String>) -> Result<Self, JwkError> {
        match key_pair.alg_name.as_str() {
            "RSA" => Ok(Jwk::Rsa(RsaJwk::from_key_pair(key_pair, kid)?)),
            alg => Err(JwkError::UnsupportedAlgorithm(alg.to_string())),
        }
    }

    /// 取得 JWK 的金鑰識別符 (kid)。
    ///
    /// # 返回
    ///
    /// 若 JWK 包含 `kid`，則返回對應的字串切片，否則返回 `None`。
    pub fn kid(&self) -> Option<&str> {
        match self {
            Jwk::Rsa(jwk) => jwk.kid.as_deref(),
        }
    }

    /// 取得 JWK 所使用的演算法。
    ///
    /// # 返回
    ///
    /// 若 JWK 包含演算法資訊，則返回對應的字串切片，否則返回 `None`。
    pub fn algorithm(&self) -> Option<&str> {
        match self {
            Jwk::Rsa(jwk) => jwk.alg.as_deref(),
        }
    }

    /// 將 JWK 序列化為 JSON 格式字串。
    ///
    /// # 返回
    ///
    /// 成功時返回 JSON 字串，否則返回 `JwkError`。
    pub fn to_json(&self) -> Result<String, JwkError> {
        serde_json::to_string(self).map_err(JwkError::from)
    }

    /// 將 JWK 轉換為符合 ACME 協議要求的 JSON 表示。
    ///
    /// # 返回
    ///
    /// 成功時返回 ACME 格式的 JSON 字串，否則返回 `JwkError`。
    pub fn to_acme_json(&self) -> Result<String, JwkError> {
        match self {
            Jwk::Rsa(jwk) => jwk.to_acme_json(),
        }
    }
}
