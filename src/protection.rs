use crate::{
    base64::Base64,
    nonce::{NonceError, NonceT},
};
use serde::Serialize;
use serde_json::Value as JsonValue;
use thiserror::Error;

/// 定義保護機制中可能產生的錯誤類型。
#[derive(Debug, Error)]
pub enum ProtectionError {
    /// JSON 序列化錯誤
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    /// Nonce 相關錯誤
    #[error("Nonce error: {0}")]
    Nonce(#[from] NonceError),
}

/// 自定義的結果型別，錯誤類型為 [`ProtectionError`]
type Result<T> = std::result::Result<T, ProtectionError>;

/// 用於生成保護頭（Protected Header）的結構體，
/// 該頭部包含數字簽章中必要的參數，如演算法、nonce、目標 URL 等。
pub struct Protection<'a> {
    nonce: &'a dyn NonceT,
    alg: String,
    value: Option<JsonValue>,
}

/// 表示數字簽章保護頭部的資料結構，
/// 此結構體可序列化為 JSON，並可轉換為 Base64 編碼字串。
#[derive(Debug, Serialize)]
pub struct ProtectedHeader {
    /// 簽章演算法
    alg: String,
    /// 用於防止重放攻擊的隨機數
    nonce: String,
    /// 請求目標 URL
    url: String,
    /// 可選的 JSON Web Key (JWK)
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<JsonValue>,
    /// 可選的密鑰標識符 (Key ID)
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
}

impl ProtectedHeader {
    /// 將 [`ProtectedHeader`] 序列化後轉換為 Base64 格式，
    /// 可用於傳遞至需要該格式的 API 中。
    ///
    /// # Errors
    ///
    /// 如果序列化過程中發生錯誤，將返回 [`ProtectionError::Serialization`]。
    pub fn to_base64(&self) -> Result<Base64> {
        let json_str = self.to_string();
        Ok(Base64::new(json_str.as_bytes()))
    }
}

impl<'a> Protection<'a> {
    /// 建立一個新的 [`Protection`] 實例。
    ///
    /// 會根據傳入的演算法參數（不區分大小寫）正規化為支援的格式，
    /// 預設演算法為 `RS256`。
    ///
    /// # 參數
    ///
    /// - `nonce`: 實現了 [`NonceT`] trait 的 nonce 取得器。
    /// - `alg`: 指定用於簽章的演算法，如 "RS256"、"ES256" 等。
    pub fn new(nonce: &'a dyn NonceT, alg: impl AsRef<str>) -> Self {
        let alg = match alg.as_ref().to_uppercase().as_str() {
            "RS256" | "RSA" => "RS256",
            "ES256" | "ECDSA" => "ES256",
            _ => "RS256",
        }
        .to_string();

        Self {
            nonce,
            alg,
            value: None,
        }
    }

    /// 為保護頭設定一個附加值，該值會在生成保護頭時用於填充 `jwk` 或 `kid` 欄位。
    ///
    /// 傳入的 `value` 將被序列化成 JSON 值。當 `value` 為 JSON 物件時，
    /// 會優先填充到 `jwk` 欄位，否則填充到 `kid` 欄位。
    ///
    /// # 參數
    ///
    /// - `value`: 任意可序列化的資料，作為附加資訊加入保護頭中。
    ///
    /// # Returns
    ///
    /// 返回可鏈式調用的 mutable 引用。
    ///
    /// # Errors
    ///
    /// 若序列化過程失敗，則返回 [`ProtectionError::Serialization`]。
    pub fn set_value<T: Serialize>(&mut self, value: T) -> Result<&mut Self> {
        self.value = Some(serde_json::to_value(value)?);
        Ok(self)
    }

    /// 根據目前設定的參數生成一個 [`ProtectedHeader`]。
    ///
    /// 該方法會從 `nonce` 提供器中取得最新的 nonce 值，
    /// 並根據內部的 `value` 決定是填充 `jwk` 還是 `kid` 欄位。
    ///
    /// # 參數
    ///
    /// - `url`: 目標 URL，將填入保護頭的 `url` 欄位。
    ///
    /// # Returns
    ///
    /// 返回一個生成好的 [`ProtectedHeader`] 實例。
    ///
    /// # Errors
    ///
    /// 若取得 nonce 或處理值時發生錯誤，則返回相應的 [`ProtectionError`]。
    pub fn create_header(&self, url: impl Into<String>) -> Result<ProtectedHeader> {
        let nonce = self.nonce.get()?;
        let url = url.into();

        let (jwk, kid) = match &self.value {
            Some(value) if value.is_object() => (Some(value.clone()), None),
            Some(value) => (
                None,
                Some(
                    value
                        .as_str()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| value.to_string()),
                ),
            ),
            None => (None, None),
        };

        Ok(ProtectedHeader {
            alg: self.alg.clone(),
            nonce,
            url,
            jwk,
            kid,
        })
    }
}

impl std::fmt::Display for ProtectedHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        serde_json::to_string(self)
            .map_err(|_| std::fmt::Error)
            .and_then(|s| write!(f, "{}", s))
    }
}

#[cfg(test)]
mod tests {
    use crate::nonce::MockNonce;

    use super::*;
    use serde_json::json;

    #[test]
    fn test_alg_normalization() {
        let nonce = MockNonce::new("test-nonce");
        let cases = vec![
            ("rs256", "RS256"),
            ("RSA", "RS256"),
            ("es256", "ES256"),
            ("ECDSA", "ES256"),
            ("invalid", "RS256"),
        ];

        for (input, expected) in cases {
            let protection = Protection::new(&nonce, input);
            assert_eq!(protection.alg, expected);
        }
    }

    #[test]
    fn test_jwk_handling() -> Result<()> {
        let nonce = MockNonce::new("test-nonce");
        let jwk = json!({"kty": "EC", "crv": "P-256"});

        let mut protection = Protection::new(&nonce, "ES256");
        protection.set_value(&jwk)?;
        let header = protection.create_header("https://example.com")?;

        assert!(header.jwk.is_some());
        assert_eq!(header.jwk, Some(jwk));
        assert!(header.kid.is_none());
        Ok(())
    }

    #[test]
    fn test_kid_handling() -> Result<()> {
        let nonce = MockNonce::new("test-nonce");

        let mut protection = Protection::new(&nonce, "RS256");
        protection.set_value("key_id_123")?;
        let header = protection.create_header("https://example.com")?;
        assert_eq!(header.kid, Some("key_id_123".to_string()));
        assert!(header.jwk.is_none());

        let mut protection = Protection::new(&nonce, "RS256");
        protection.set_value(42)?;
        let header = protection.create_header("https://example.com")?;
        assert_eq!(header.kid, Some("42".to_string()));

        Ok(())
    }

    #[test]
    fn test_header_serialization() -> Result<()> {
        let nonce = MockNonce::new("test-nonce");
        let header = Protection::new(&nonce, "ES256").create_header("https://example.com")?;

        let json = header.to_string();
        assert!(json.contains("\"nonce\":\"test-nonce\""));
        assert!(json.contains("\"url\":\"https://example.com\""));
        assert!(json.contains("\"alg\":\"ES256\""));
        Ok(())
    }
}
