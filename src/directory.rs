use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// 表示處理目錄操作時可能發生的錯誤類型。
#[derive(Debug, Error)]
pub enum DirectoryError {
    /// JSON 解析或序列化錯誤。
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// HTTP 請求錯誤。
    #[error("Request error: {0}")]
    Request(#[from] reqwest::Error),
    /// 儲存操作錯誤。
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
}

/// 簡化目錄操作結果的型別。
type DirectoryResult<T> = std::result::Result<T, DirectoryError>;

use crate::{
    base64::Base64,
    storage::{Storage, StorageError},
};

/// 表示與目錄相關的 API 結構，包含與帳號、nonce、訂單、續期資訊及撤銷憑證相關的 URL。
#[derive(Debug, Deserialize, Serialize)]
pub struct Directory {
    /// 用於新帳號註冊的 API 路徑。
    #[serde(rename = "newAccount")]
    pub new_account: String,
    /// 用於取得新的 nonce 值的 API 路徑。
    #[serde(rename = "newNonce")]
    pub new_nonce: String,
    /// 用於訂單相關操作的 API 路徑。
    #[serde(rename = "newOrder")]
    pub new_order: String,
    /// 用於取得續期資訊的 API 路徑，可能不存在。
    #[serde(rename = "renewalInfo")]
    pub renewal_info: Option<String>,
    /// 用於撤銷憑證的 API 路徑。
    #[serde(rename = "revokeCert")]
    pub revoke_cert: String,
}

impl Directory {
    /// 建立並取得 `Directory` 實例。
    ///
    /// 此方法會先檢查指定儲存系統中是否已有目錄資料，
    /// 若存在則直接反序列化並回傳；否則從指定 URL 發送 GET 請求以取得目錄資料，
    /// 並將取得的資料序列化後儲存至儲存系統中。
    ///
    /// # 參數
    ///
    /// - `storage`: 實作了 `Storage` 特徵的儲存系統，用以讀取與寫入目錄資料。
    /// - `url`: 取得目錄資料的 API URL。
    ///
    /// # 回傳
    ///
    /// 成功時回傳 `Directory` 實例，否則回傳 `DirectoryError` 錯誤。
    pub fn new<T: Storage>(storage: &T, url: &str) -> DirectoryResult<Self> {
        // 利用 URL 的 Base64 編碼作為儲存系統中的鍵值
        let storage_key = Base64::new(url.as_bytes()).base64_url();

        // 嘗試從儲存系統中讀取現有的目錄資料
        match storage.read_file(&storage_key) {
            Ok(data) => {
                return Ok(serde_json::from_slice(&data)?);
            }
            Err(StorageError::NotFound(_)) => {} // 資料不存在，繼續後續操作
            Err(e) => {
                return Err(DirectoryError::Storage(e));
            }
        }

        // 若儲存系統中無資料，則發送 HTTP GET 請求以取得目錄資料
        let client = Client::new();
        let response = client.get(url).send()?;
        let directory: Directory = response.json()?;

        // 將取得的目錄資料序列化後存入儲存系統中
        let serialized = serde_json::to_vec(&directory)?;
        storage.write_file(&storage_key, &serialized)?;

        Ok(directory)
    }
}

