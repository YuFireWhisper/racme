//! 此模組提供用於處理 JSON Web Signature (JWS) 的基本結構與操作，
/// 例如建立 JWS 與序列化成 JSON 字串。請參考各 API 的說明了解如何使用。

use std::result;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::base64::{Base64, DecodeError};

/// 表示一個 JSON Web Signature (JWS) 物件。
///
/// 此物件包含三個部分：
/// - `header`：保護資料，經 Base64 URL 安全編碼後的字串。
/// - `payload`：負載資料，經 Base64 URL 安全編碼後的字串。
/// - `signature`：簽名，經 Base64 URL 安全編碼後的字串。
///
/// 注意：各部分皆已透過 `serde` 的註解處理欄位名稱映射，使其符合 JWS 標準。
#[derive(Serialize, Deserialize, Debug)]
pub struct Jws {
    /// 對應 JWS 中的 "protected" 欄位，包含已編碼的 header 資訊。
    #[serde(rename = "protected")]
    header: String,
    /// JWS 中的 payload 部分，經 Base64 URL 安全編碼。
    payload: String,
    /// JWS 中的簽名部分，經 Base64 URL 安全編碼。
    signature: String,
}

/// 表示與 JWS 相關的錯誤。
///
/// 包含在 Base64 解碼或 JSON 處理過程中可能發生的錯誤。
#[derive(Error, Debug)]
pub enum JwsError {
    /// 當 Base64 解碼失敗時回傳此錯誤。
    #[error("Base64 decode error: {0}")]
    Base64DecodeError(#[from] DecodeError),
    /// 當 JSON 序列化或反序列化過程中發生錯誤時回傳此錯誤。
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

type Result<T> = result::Result<T, JwsError>;

impl Jws {
    /// 建立一個新的 `Jws` 實例。
    ///
    /// 傳入的 `header_b64`、`payload_b64` 與 `signature_b64` 均應為已完成 Base64 URL
    /// 安全編碼的資料物件，該函式將提取編碼後的字串並構造一個 `Jws` 實例。
    ///
    /// # 參數
    ///
    /// - `header_b64`: 包含 header 資訊的 Base64 資料物件。
    /// - `payload_b64`: 包含 payload 資訊的 Base64 資料物件。
    /// - `signature_b64`: 包含簽名的 Base64 資料物件。
    ///
    /// # 回傳
    ///
    /// 回傳一個 `Result` 包含成功建立的 `Jws` 實例，或是遇到錯誤時回傳相應錯誤。
    pub fn new(
        header_b64: &Base64,
        payload_b64: &Base64,
        signature_b64: &Base64,
    ) -> Result<Self> {
        Ok(Jws {
            header: header_b64.base64_url(),
            payload: payload_b64.base64_url(),
            signature: signature_b64.base64_url(),
        })
    }

    /// 將 `Jws` 實例序列化為 JSON 格式的字串。
    ///
    /// 此函式使用 `serde_json` 來序列化物件，回傳一個 JSON 字串表示此 JWS，
    /// 便於傳輸或儲存。
    ///
    /// # 回傳
    ///
    /// - 成功時，回傳包含 JWS JSON 表示的 `String`。
    /// - 發生序列化錯誤時，回傳 `JwsError::JsonError`。
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }
}

