use reqwest::blocking::Client;
use thiserror::Error;

/// 表示在取得 Nonce 時可能發生的錯誤狀況。
#[derive(Error, Debug)]
pub enum NonceError {
    /// 當請求過程中發生錯誤時回傳此錯誤。
    #[error("Failed to make request: {0}")]
    RequestFailed(#[from] reqwest::Error),
    /// 當回應中缺少 `Replay-Nonce` 標頭時回傳此錯誤。
    #[error("No Replay-Nonce header found in response")]
    NoNonceHeader,
    /// 當標頭值無法轉換成字串時回傳此錯誤。
    #[error("Invalid header value: {0}")]
    InvalidHeaderValue(#[from] reqwest::header::ToStrError),
}

/// 定義取得 Nonce 的行為。
pub trait NonceT {
    /// 嘗試取得 Nonce，回傳包含 Nonce 字串或錯誤的 `Result`。
    fn get(&self) -> Result<String, NonceError>;
}

/// 透過 HTTP 請求取得 `Replay-Nonce` 的實作。
#[derive(Debug)]
pub struct Nonce {
    client: Client,
    url: String,
}

impl Nonce {
    /// 建立一個新的 `Nonce` 實例，透過給定的 URL 來發送 HTTP 請求。
    ///
    /// # 參數
    ///
    /// * `url` - 用來請求 Nonce 的目標 URL，可以是字串或其他可轉換成 `String` 的型別。
    ///
    /// # 範例
    ///
    /// ```
    /// # use your_crate::Nonce;
    /// let nonce = Nonce::new("https://example.com/acme/new-nonce");
    /// ```
    pub fn new(url: impl Into<String>) -> Self {
        Nonce {
            client: Client::new(),
            url: url.into(),
        }
    }
}

impl NonceT for Nonce {
    /// 透過 HTTP HEAD 請求取得回應中的 `Replay-Nonce` 標頭。
    ///
    /// 若標頭存在，則回傳該 Nonce；否則回傳 `NonceError::NoNonceHeader`。
    fn get(&self) -> Result<String, NonceError> {
        let response = self.client.head(&self.url).send()?;

        match response.headers().get("Replay-Nonce") {
            Some(nonce) => Ok(nonce.to_str()?.to_string()),
            None => Err(NonceError::NoNonceHeader),
        }
    }
}

/// 模擬 Nonce 實作，通常用於測試環境中提供固定的 Nonce 值。
#[derive(Debug, Clone)]
pub struct MockNonce {
    value: String,
}

impl MockNonce {
    /// 建立一個新的 `MockNonce` 實例，並指定固定的 Nonce 值。
    ///
    /// # 參數
    ///
    /// * `value` - 模擬的 Nonce 值，可以是字串或其他可轉換成 `String` 的型別。
    ///
    /// # 範例
    ///
    /// ```
    /// # use your_crate::MockNonce;
    /// let mock = MockNonce::new("固定測試值");
    /// ```
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }
}

impl NonceT for MockNonce {
    /// 直接回傳預設的 Nonce 值，適用於測試情境。
    fn get(&self) -> Result<String, NonceError> {
        Ok(self.value.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_nonce() {
        let nonce = MockNonce::new("test-nonce-123");
        assert_eq!(nonce.get().unwrap(), "test-nonce-123");
    }
}
