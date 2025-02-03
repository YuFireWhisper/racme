//! 模塊提供與 ACME 帳戶管理相關的功能，包括帳戶創建、JWS 簽名、以及文件存儲操作。

use std::{env, path::PathBuf, string::FromUtf8Error};

use reqwest::blocking::Client;
use serde_json::Value;
use thiserror::Error;

use crate::{
    certificate::{Certificate, CertificateError},
    directory::{Directory, DirectoryError},
    jwk::{Jwk, JwkError},
    key_pair::{KeyError, KeyPair},
    nonce::Nonce,
    payload::{NewAccountPayload, PayloadT},
    protection::{Protection, ProtectionError},
    signature::{create_signature, SignatureError},
    storage::{FileStorage, Storage, StorageError},
};

/// 錯誤類型，用於描述在處理 ACME 帳戶相關操作時可能發生的各類錯誤。
#[derive(Debug, Error)]
pub enum AccountError {
    #[error("Request error: {0}")]
    RequestError(#[from] reqwest::Error),
    #[error("Request header error: {0}")]
    RequestHeaderError(#[from] reqwest::header::ToStrError),
    #[error("Request failed: {status:?}, {headers:?}, {body:?}")]
    RequestErrorDetailed {
        status: reqwest::StatusCode,
        headers: reqwest::header::HeaderMap,
        body: String,
    },
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("UTF-8 error: {0}")]
    Utf8Error(#[from] FromUtf8Error),
    #[error("Storage error: {0}")]
    StorageError(#[from] StorageError),
    #[error("JWK error: {0}")]
    JwkError(#[from] JwkError),
    #[error("Protection error: {0}")]
    ProtectionError(#[from] ProtectionError),
    #[error("Signature error: {0}")]
    SignatureError(#[from] SignatureError),
    #[error("Key error: {0}")]
    KeyError(#[from] KeyError),
    #[error("Directory error: {0}")]
    DirectoryError(#[from] DirectoryError),
    #[error("Certificate error: {0}")]
    CertificateError(#[from] CertificateError),
}

/// 結果類型，當操作成功返回 `T`，失敗則返回 [`AccountError`].
pub type Result<T> = std::result::Result<T, AccountError>;

/// 表示 ACME 帳戶的結構體，包含註冊信息、密鑰對、目錄與存儲操作等。
#[derive(Debug)]
pub struct Account {
    /// 帳戶所屬電子郵件地址。
    pub email: String,
    /// 帳戶使用的密鑰對。
    pub key_pair: KeyPair,
    /// ACME 服務目錄。
    pub dir: Directory,
    /// ACME 帳戶 URL。
    pub account_url: String,
    /// 用於防止重放攻擊的 nonce。
    pub nonce: Nonce,
    /// 文件存儲接口，用於保存帳戶相關資料。
    pub storage: Box<dyn Storage>,
}

impl Account {
    /// 預設的密鑰算法名稱。
    const DEFAULT_KEY_ALG: &'static str = "RSA";
    /// 預設的密鑰位數。
    const DEFAULT_KEY_BITS: u32 = 2048;
    /// 預設的 ACME 目錄 URL。
    const DEFAULT_DIR_URL: &'static str = "https://acme-v02.api.letsencrypt.org/directory";

    /// 使用指定電子郵件創建一個新的 [`Account`] 實例。
    ///
    /// 此方法內部使用 [`AccountBuilder`] 來構建並初始化帳戶，如果之前已存在帳戶資料，
    /// 則直接從存儲中讀取，否則執行帳戶創建流程。
    ///
    /// # Errors
    ///
    /// 返回 [`AccountError`] 當創建過程中發生 I/O、網絡或簽名錯誤時。
    pub fn new(email: &str) -> Result<Self> {
        let builder = AccountBuilder::new(email);
        Self::from_builder(builder)
    }

    /// 根據當前應用及環境，返回預設的存儲路徑。
    ///
    /// 目前僅在 Linux 系統上支持，根據 `$HOME` 環境變量返回相應的路徑。
    fn get_defalut_storage_path() -> PathBuf {
        let app_name = env!("CARGO_PKG_NAME");

        #[cfg(target_os = "linux")]
        {
            let base_dir = env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/var/lib"));

            base_dir.join(".local/share").join(app_name)
        }
    }

    /// 根據 [`AccountBuilder`] 中的配置構建 [`Account`] 實例。
    ///
    /// 如果存儲中已存在帳戶數據，則直接讀取並初始化相應字段；否則，
    /// 生成新的密鑰對、創建帳戶並將數據寫入存儲中。
    ///
    /// # Errors
    ///
    /// 返回 [`AccountError`] 當文件操作、密鑰生成、或帳戶創建失敗時。
    fn from_builder(builder: AccountBuilder) -> Result<Self> {
        let storage = FileStorage::open(builder.storage_path)?;
        let account_url_path = format!("{}/account_url", builder.email);
        let account_key_pair_path = format!("{}/account_key_pair", builder.email);
        let dir_url_path = format!("{}/dir_url", builder.email);

        if let Ok(account_url) = storage.read_file(&account_url_path) {
            let account_url = String::from_utf8(account_url)?;
            let key_pair = KeyPair::from_file(&storage, &account_key_pair_path)?;
            let dir_data = storage.read_file(&dir_url_path)?;
            let dir = Directory::new(&storage, &String::from_utf8_lossy(&dir_data))?;
            let nonce = Nonce::new(&dir.new_nonce);

            return Ok(Account {
                email: builder.email,
                key_pair,
                dir,
                account_url,
                nonce,
                storage: Box::new(storage),
            });
        }

        let key_pair = KeyPair::new(
            &storage,
            &builder.key_pair_alg,
            Some(builder.key_pair_bits),
            Some(&account_key_pair_path),
        )?;
        let dir = Directory::new(&storage, &builder.dir_url)?;
        storage.write_file(&dir_url_path, builder.dir_url.as_bytes())?;
        let account_url = Account::create_account(&dir, &key_pair, &builder.email)?;
        storage.write_file(&account_url_path, account_url.as_bytes())?;
        let nonce = Nonce::new(&dir.new_nonce);

        Ok(Account {
            email: builder.email,
            key_pair,
            dir,
            account_url,
            nonce,
            storage: Box::new(storage),
        })
    }

    /// 使用 ACME 目錄信息與密鑰對創建新帳戶，並返回帳戶 URL。
    ///
    /// 該方法會執行 JWS 簽名流程，並通過 HTTP 請求向 ACME 服務發送註冊請求。
    ///
    /// # Arguments
    ///
    /// * `dir` - ACME 目錄信息，包含帳戶創建和 nonce 獲取的 URL。
    /// * `key_pair` - 用於帳戶創建的密鑰對。
    /// * `email` - 帳戶關聯的電子郵件地址。
    ///
    /// # Errors
    ///
    /// 返回 [`AccountError`] 當網絡請求失敗、HTTP 響應不符合預期或者簽名生成錯誤時。
    pub fn create_account(dir: &Directory, key_pair: &KeyPair, email: &str) -> Result<String> {
        let new_account_api = &dir.new_account;
        let nonce = Nonce::new(&dir.new_nonce);

        let jwk = Jwk::new(key_pair, None)?;
        let header = Protection::new(&nonce, &key_pair.alg_name)
            .set_value(jwk)?
            .create_header(new_account_api)?
            .to_base64()?;
        let payload = NewAccountPayload::new(email).to_base64()?;
        let signature = create_signature(&header, &payload, key_pair)?.base64_url();

        let jws = serde_json::to_string(&Value::Object({
            let mut map = serde_json::Map::new();
            map.insert("protected".to_string(), header.base64_url().into());
            map.insert("payload".to_string(), payload.base64_url().into());
            map.insert("signature".to_string(), signature.into());
            map
        }))?;

        let client = Client::new();
        let response = client
            .post(new_account_api)
            .header("Content-Type", "application/jose+json")
            .body(jws)
            .send()?;

        let status = response.status();
        if !status.is_success() {
            let headers = response.headers().clone();
            let body = response.text()?;
            return Err(AccountError::RequestErrorDetailed {
                status,
                headers,
                body,
            });
        }

        let account_url = response
            .headers()
            .get("Location")
            .ok_or_else(|| AccountError::RequestErrorDetailed {
                status: response.status(),
                headers: response.headers().clone(),
                body: "Location header not found".to_string(),
            })?
            .to_str()?
            .to_string();

        Ok(account_url)
    }

    /// 用於獲取該帳戶中指定域名的憑證。
    ///
    /// 該方法會從存儲中讀取指定域名的憑證，並返回 [`Certificate`] 實例。
    ///
    /// # Arguments
    ///
    /// * `domain` - 指定的域名。
    ///
    /// # Errors
    ///
    /// 返回 [`StorageError`] 當讀取憑證文件失敗，或者 [`CertificateError`] 當解析憑證失敗時。
    pub fn get_certificate(&self, domain: &str) -> Result<Certificate> {
        let cert_pem_path = format!("{}/{}/cert", &self.email, domain);
        let cert_pem = self.storage.read_file(&cert_pem_path)?;

        Ok(Certificate::new(&String::from_utf8_lossy(&cert_pem))?)
    }

    /// 返回帳戶中指定域名的密鑰對。
    ///
    /// 該方法會從存儲中讀取指定域名的密鑰對，並返回 [`KeyPair`] 實例。
    ///
    /// # Arguments
    ///
    /// * `domain` - 指定的域名。
    ///
    /// # Errors
    ///
    /// 返回 [`StorageError`] 當讀取密鑰文件失敗，或者 [`KeyError`] 當解析密鑰失敗時。
    pub fn get_cert_key(&self, domain: &str) -> Result<KeyPair> {
        let cert_key_path = format!("{}/{}/cert_key", &self.email, domain);
        Ok(KeyPair::from_file(&*self.storage, &cert_key_path)?)
    }
}

/// 用於構建 [`Account`] 實例的構造器，採用 builder 模式。
///
/// 這個構造器允許使用者根據需求定制帳戶的各項配置，如密鑰算法、密鑰位數、目錄 URL 以及存儲路徑。
pub struct AccountBuilder {
    email: String,
    key_pair_alg: String,
    key_pair_bits: u32,
    dir_url: String,
    storage_path: PathBuf,
}

impl AccountBuilder {
    /// 創建一個新的 [`AccountBuilder`] 實例，並設置預設值。
    ///
    /// 預設值包括：
    /// - 密鑰算法：`"RSA"`
    /// - 密鑰位數：`2048`
    /// - ACME 目錄 URL：`"https://acme-v02.api.letsencrypt.org/directory"`
    /// - 存儲路徑：根據當前環境獲取預設存儲路徑（目前僅支持 Linux）
    ///
    /// # Arguments
    ///
    /// * `email` - 用於創建帳戶的電子郵件地址。
    pub fn new(email: &str) -> Self {
        AccountBuilder {
            email: email.to_string(),
            key_pair_alg: Account::DEFAULT_KEY_ALG.to_string(),
            key_pair_bits: Account::DEFAULT_KEY_BITS,
            dir_url: Account::DEFAULT_DIR_URL.to_string(),
            storage_path: Account::get_defalut_storage_path(),
        }
    }

    /// 設置密鑰算法。
    ///
    /// # Arguments
    ///
    /// * `key_pair_alg` - 使用的密鑰算法名稱。
    pub fn key_pair_alg(mut self, key_pair_alg: &str) -> Self {
        self.key_pair_alg = key_pair_alg.to_string();
        self
    }

    /// 設置密鑰位數。
    ///
    /// # Arguments
    ///
    /// * `key_pair_bits` - 指定的密鑰位數。
    pub fn key_pair_bits(mut self, key_pair_bits: u32) -> Self {
        self.key_pair_bits = key_pair_bits;
        self
    }

    /// 設置 ACME 目錄 URL。
    ///
    /// # Arguments
    ///
    /// * `dir_url` - ACME 服務目錄的 URL。
    pub fn dir_url(mut self, dir_url: &str) -> Self {
        self.dir_url = dir_url.to_string();
        self
    }

    /// 設置文件存儲路徑。
    ///
    /// # Arguments
    ///
    /// * `storage_path` - 用於存儲帳戶資料的路徑。
    pub fn storage_path(mut self, storage_path: &str) -> Self {
        self.storage_path = PathBuf::from(storage_path);
        self
    }

    /// 根據當前的配置構建 [`Account`] 實例。
    ///
    /// # Errors
    ///
    /// 返回 [`AccountError`] 當帳戶構建過程中發生錯誤時。
    pub fn build(self) -> Result<Account> {
        Account::from_builder(self)
    }
}
