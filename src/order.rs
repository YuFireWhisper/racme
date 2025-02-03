use std::{
    collections::HashMap,
    fs, io,
    str::FromStr,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    account::Account,
    base64::Base64,
    challenge::{Challenge, ChallengeError, ChallengeType},
    csr::CSR,
    jws::{Jws, JwsError},
    key_pair::{KeyError, KeyPair},
    payload::{FinalizeOrderPayload, Identifier, NewOrderPayload, PayloadT},
    protection::{Protection, ProtectionError},
    signature::{create_signature, SignatureError},
    storage::StorageError,
};

/// 定義所有訂單操作可能產生的錯誤。
/// 此錯誤列舉涵蓋從驗證、網路請求到儲存等各種操作可能出現的問題。
#[derive(Debug, Error)]
pub enum OrderError {
    #[error("Protection error: {0}")]
    Protection(#[from] ProtectionError),
    #[error("Signature error: {0}")]
    Signature(#[from] SignatureError),
    #[error("Request error: {0}")]
    Request(#[from] reqwest::Error),
    #[error("JWS error: {0}")]
    Jws(#[from] JwsError),
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("Challenge error: {0}")]
    Challenge(#[from] ChallengeError),
    #[error("Missing Location header: {status:?}, {headers:?}, {body:?}")]
    MissingLocationHeader {
        status: reqwest::StatusCode,
        headers: reqwest::header::HeaderMap,
        body: String,
    },
    #[error("Invalid Location header")]
    InvalidLocationHeader,
    #[error("Invalid status value")]
    InvalidStatus,
    #[error("Account thumbprint calculation failed")]
    ThumbprintError,
    #[error("Serde JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Request header error: {0}")]
    RequestHeaderError(#[from] reqwest::header::ToStrError),
    #[error("Request failed: {status:?}, {headers:?}, {body:?}")]
    RequestErrorDetailed {
        status: reqwest::StatusCode,
        headers: reqwest::header::HeaderMap,
        body: String,
    },
    #[error("Key pair error: {0}")]
    KeyPair(#[from] KeyError),
    #[error("CSR error: {0}")]
    Csr(#[from] crate::csr::CsrError),
    #[error("OpenSSL error: {0}")]
    OpenSSL(#[from] openssl::error::ErrorStack),
    #[error("Order is not valid")]
    OrderNotValid,
    #[error("Order is not ready")]
    OrderNotReady,
    #[error("Order is invalid")]
    OrderInvalid,
    #[error("Cloudflare API error: {0}")]
    Cloudflare(String),
    #[error("No DNS challenge found")]
    NoDnsChallenge,
    #[error("Challenge not found")]
    ChallengeNotFound,
    #[error("DNS validation failed: {0}")]
    DnsValidation(String),
    #[error("Unknown DNS provider: {0}")]
    UnknownDnsProvider(String),
    #[error("File I/O error: {0}")]
    Io(#[from] io::Error),
}

type Result<T> = std::result::Result<T, OrderError>;

const DNS_CHECK_INTERVAL: Duration = Duration::from_secs(5);
const DNS_CHECK_TIMEOUT: Duration = Duration::from_secs(120);

/// 訂單狀態，目前支援的狀態有 pending、ready、processing、valid 與 invalid。
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OrderStatus {
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
}

impl FromStr for OrderStatus {
    type Err = OrderError;

    /// 根據字串內容解析對應的訂單狀態
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "pending" => Ok(Self::Pending),
            "ready" => Ok(Self::Ready),
            "processing" => Ok(Self::Processing),
            "valid" => Ok(Self::Valid),
            "invalid" => Ok(Self::Invalid),
            _ => Err(OrderError::InvalidStatus),
        }
    }
}

/// 表示訂單資料，並提供建立、挑戰驗證、訂單下訂與憑證下載等操作。
#[derive(Debug, Deserialize)]
pub struct Order {
    /// 訂單當前狀態
    pub status: OrderStatus,
    /// 過期時間（ISO8601 格式字串）
    pub expires: String,
    /// 證書主題（Domain）識別符
    pub identifiers: Vec<Identifier>,
    /// 授權 URL 列表
    pub authorizations: Vec<String>,
    /// 最終確認 URL
    pub finalize: String,
    /// 伺服器回傳的訂單 URL（本地不序列化）
    #[serde(skip)]
    pub order_url: String,
    /// 憑證 URL（僅在有效時存在）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    /// 存放各種挑戰（鍵為 ChallengeType）
    #[serde(skip)]
    pub challenges: HashMap<ChallengeType, Challenge>,
    /// 若使用 HTTP 驗證，存放驗證文件路徑
    #[serde(skip)]
    pub http_challenge_path: Option<String>,
    /// 本地儲存 order_url 的檔案路徑
    #[serde(skip)]
    order_storage_path: String,
    /// 此訂單所屬的域名
    #[serde(skip)]
    domain: String,
}

impl Order {
    /// 建立新訂單：
    ///
    /// * 若存在有效的訂單則直接取得並更新挑戰資訊
    /// * 否則發出新訂單請求，並將訂單 URL 寫入儲存中
    ///
    /// # 參數
    ///
    /// - `account`: 用於進行認證及儲存的帳號參考
    /// - `domain`: 要下訂的域名
    ///
    /// # 回傳
    ///
    /// 回傳新的 `Order` 實例，或發生錯誤時回傳 `OrderError`
    pub fn new(account: &mut Account, domain: &str) -> Result<Self> {
        let order_storage_path = format!("{}/{}/order_url", &account.email, domain);
        if let Ok(order_url_bytes) = account.storage.read_file(&order_storage_path) {
            if let Ok(order_url) = String::from_utf8(order_url_bytes) {
                if let Ok(mut order) = Self::get_order(&order_url) {
                    if order.status != OrderStatus::Invalid {
                        order.fetch_challenges(account)?;
                        order.domain = domain.to_owned();
                        order.order_storage_path = order_storage_path;
                        order.order_url = order_url;
                        return Ok(order);
                    }
                }
            }
        }
        let payload = NewOrderPayload::new(vec![domain]).to_base64()?;
        let jws = Self::build_jws(account, &payload)?;
        let response = Client::new()
            .post(&account.dir.new_order)
            .header("Content-Type", "application/jose+json")
            .body(jws.to_json()?)
            .send()?;
        if !response.status().is_success() {
            return Err(OrderError::RequestErrorDetailed {
                status: response.status(),
                headers: response.headers().clone(),
                body: response.text()?,
            });
        }
        let order_url = response
            .headers()
            .get("Location")
            .ok_or_else(|| OrderError::MissingLocationHeader {
                status: response.status(),
                headers: response.headers().clone(),
                body: "Location header not found".to_string(),
            })?
            .to_str()?
            .to_string();
        account
            .storage
            .write_file(&order_storage_path, order_url.as_bytes())?;
        let mut order: Self = response.json()?;
        order.domain = domain.to_owned();
        order.order_storage_path = order_storage_path;
        order.order_url = order_url.clone();
        order.fetch_challenges(account)?;
        Ok(order)
    }

    /// 強制重新建立一個新的訂單：
    ///
    /// 此方法會先刪除儲存中的舊訂單資料，再呼叫 `Order::new`
    /// 以建立新訂單，適用於需要更新憑證的情境。
    ///
    /// # 參數
    ///
    /// - `account`: 用於操作訂單與儲存的帳號參考
    /// - `domain`: 要下訂的域名
    ///
    /// # 回傳
    ///
    /// 成功則回傳新的 `Order` 實例，否則回傳相應錯誤。
    pub fn renew(account: &mut Account, domain: &str) -> Result<Self> {
        let order_storage_path = format!("{}/{}/order_url", &account.email, domain);
        account.storage.remove(&order_storage_path)?;
        Order::new(account, domain)
    }

    /// 設定 DNS Provider。
    ///
    /// 當 provider 為 Default 且 token 為空時，不做任何操作；否則兩者必須同時提供有效值。
    /// 當 provider 為 Cloudflare 時，會進行 Cloudflare DNS 設定。
    ///
    /// # 參數
    ///
    /// - `provider`: 指定使用的 DNS 提供者
    /// - `token`: 用於驗證 API 請求的金鑰
    ///
    /// # 回傳
    ///
    /// 若設定成功則回傳更新後的 `Order` 實例，否則回傳相應錯誤
    pub fn dns_provider(mut self, provider: DnsProvider, token: &str) -> Result<Self> {
        match (&provider, token.is_empty()) {
            (DnsProvider::Default, true) => { /* 不執行任何動作 */ }
            (DnsProvider::Default, false) | (_, true) => {
                return Err(OrderError::UnknownDnsProvider(
                    "請同時設定正確的 DNS Provider 與 token".into(),
                ))
            }
            (DnsProvider::Cloudflare, false) => {
                self.handle_cloudflare_dns(token)?;
            }
        }
        Ok(self)
    }

    /// 設定 HTTP 驗證：
    ///
    /// 將 Http-01 挑戰的 key authorization 寫入指定的檔案路徑，
    /// 以便讓外部驗證伺服器存取。
    ///
    /// # 參數
    ///
    /// - `path`: 要寫入驗證內容的檔案系統路徑
    ///
    /// # 回傳
    ///
    /// 回傳更新後的 `Order` 實例，或發生錯誤時回傳 `OrderError`
    pub fn setup_http_challenge(mut self, path: &str) -> Result<Self> {
        self.http_challenge_path = Some(path.to_owned());
        let challenge = self
            .challenges
            .get(&ChallengeType::Http01)
            .ok_or(OrderError::ChallengeNotFound)?;
        let content = challenge
            .http_content()
            .ok_or(OrderError::ChallengeNotFound)?;
        fs::write(path, content)?;
        Ok(self)
    }

    /// 顯示所有挑戰提示訊息，可傳入語言代碼（例如 "zh-tw"），
    /// 若代碼字串為空則使用預設 "zh-tw"。
    ///
    /// 此方法主要用於協助使用者根據提示完成挑戰配置。
    ///
    /// # 參數
    ///
    /// - `lang`: 語言代碼參數(允許為空)
    ///
    /// # 回傳
    ///
    /// 回傳對自身的不可變參考，方便鏈式調用。
    pub fn display_challenges(&self, lang: &str) -> &Self {
        // 如果 lang 為空，則預設為 "zh-tw"
        let lang = if lang.is_empty() { "zh-tw" } else { lang };

        println!("===== 挑戰提示 =====");
        for (ctype, challenge) in &self.challenges {
            println!("- {:?} 挑戰：", ctype);
            println!("  {}", challenge.get_instructions(lang));
        }
        println!("====================");
        self
    }

    /// 驗證挑戰：
    ///
    /// 若訂單狀態已為 valid、processing 或 ready，則直接回傳；否則嘗試進行挑戰驗證。
    ///
    /// # 參數
    ///
    /// - `account`: 用於驗證挑戰時所需的帳號資訊
    ///
    /// # 回傳
    ///
    /// 回傳可變的 `Order` 引用，供後續操作使用；驗證失敗則回傳相應錯誤
    pub fn validate_challenge(&mut self, account: &Account) -> Result<&mut Self> {
        // 若訂單狀態已屬於 Valid、Processing 或 Ready，則直接回傳
        if matches!(
            self.status,
            OrderStatus::Valid | OrderStatus::Processing | OrderStatus::Ready
        ) {
            return Ok(self);
        }
        self.attempt_validation(account)?;
        if matches!(
            self.status,
            OrderStatus::Valid | OrderStatus::Processing | OrderStatus::Ready
        ) {
            Ok(self)
        } else {
            Err(OrderError::DnsValidation("驗證未通過".into()))
        }
    }

    /// 重試挑戰驗證：
    ///
    /// 以指定間隔重試驗證操作，最多嘗試 `attempts` 次。
    ///
    /// # 參數
    ///
    /// - `account`: 用於驗證挑戰時所需的帳號資訊
    /// - `interval`: 每次重試前等待的時間間隔
    /// - `attempts`: 最大重試次數
    ///
    /// # 回傳
    ///
    /// 驗證成功則回傳可變的 `Order` 引用，否則回傳錯誤。
    pub fn validation_with_retry(
        &mut self,
        account: &Account,
        interval: Duration,
        attempts: usize,
    ) -> Result<&mut Self> {
        for attempt in 0..attempts {
            match self.status {
                OrderStatus::Valid | OrderStatus::Processing | OrderStatus::Ready => {
                    return Ok(self)
                }
                OrderStatus::Pending => {}
                OrderStatus::Invalid => return Err(OrderError::OrderInvalid),
            }
            self.attempt_validation(account)?;
            if matches!(
                self.status,
                OrderStatus::Valid | OrderStatus::Processing | OrderStatus::Ready
            ) {
                return Ok(self);
            }
            if attempt == attempts - 1 {
                break;
            }
            thread::sleep(interval);
        }
        Err(OrderError::DnsValidation("重試後驗證仍未通過".into()))
    }

    /// 下訂（finalize）操作：
    ///
    /// 若訂單狀態已為 valid，直接回傳；否則發出 finalize 請求以完成下訂流程，
    /// 並嘗試根據伺服器回傳更新狀態及憑證資訊。
    ///
    /// # 參數
    ///
    /// - `account`: 用於簽名及請求認證的帳號資訊
    ///
    /// # 回傳
    ///
    /// 回傳對自身的不可變參考；若訂單狀態不符合下訂要求則回傳錯誤
    pub fn finalize(&mut self, account: &Account) -> Result<&Self> {
        if self.status == OrderStatus::Valid {
            return Ok(self);
        }
        if self.status != OrderStatus::Ready {
            return Err(OrderError::OrderNotReady);
        }
        let cert_key_storage_path = format!("{}/{}/cert_key", &account.email, &self.domain);
        let cert_key_pair = KeyPair::new(
            &*account.storage,
            &account.key_pair.alg_name,
            Some(account.key_pair.key_parameters()?),
            Some(&cert_key_storage_path),
        )?;
        let csr = Base64::new(
            CSR::new()?
                .set_san(&self.domain)
                .build(&cert_key_pair)?
                .to_der()?,
        );
        let header = Protection::new(&account.nonce, &account.key_pair.alg_name)
            .set_value(&account.account_url)?
            .create_header(&self.finalize)?
            .to_base64()?;
        let payload = FinalizeOrderPayload::new(&csr).to_base64()?;
        let signature = create_signature(&header, &payload, &account.key_pair)?;
        let jws = Jws::new(&header, &payload, &signature)?;
        let response = Client::new()
            .post(&self.finalize)
            .header("Content-Type", "application/jose+json")
            .body(jws.to_json()?)
            .send()?;
        if !response.status().is_success() {
            return Err(OrderError::RequestErrorDetailed {
                status: response.status(),
                headers: response.headers().clone(),
                body: response.text()?,
            });
        }
        let response: OrderUpdateResponse = response.json()?;
        self.status = response.status;
        self.certificate = response.certificate;
        Ok(self)
    }

    /// 下載憑證：
    ///
    /// 當訂單狀態為 Processing 時，等待狀態更新至 Valid 再進行下載，
    /// 並將憑證內容寫入指定的儲存路徑中。
    ///
    /// # 參數
    ///
    /// - `account`: 用於儲存憑證檔案的帳號資訊
    ///
    /// # 回傳
    ///
    /// 下載成功回傳 `()`，否則回傳相應錯誤
    pub fn download_certificate(&self, account: &Account) -> Result<()> {
        let cert_storage_path = format!("{}/{}/cert", &account.email, &self.domain);
        if self.status == OrderStatus::Processing {
            loop {
                let order = Self::get_order(&self.order_url)?;
                if order.status == OrderStatus::Valid {
                    break;
                }
                thread::sleep(Duration::from_secs(5));
            }
        }
        if self.certificate.is_none() || self.status != OrderStatus::Valid {
            return Err(OrderError::OrderNotValid);
        }
        let client = Client::new();
        let response = client.get(self.certificate.as_ref().unwrap()).send()?;
        if !response.status().is_success() {
            return Err(OrderError::RequestErrorDetailed {
                status: response.status(),
                headers: response.headers().clone(),
                body: response.text()?,
            });
        }
        let cert_bytes = response.bytes()?;
        account
            .storage
            .write_file(&cert_storage_path, &cert_bytes)?;
        Ok(())
    }

    /// 嘗試驗證挑戰：
    ///
    /// 本方法優先使用 DNS 驗證，若 DNS 驗證未通過則檢查 HTTP 驗證（前提是已設定相關路徑）。
    /// 驗證成功後會更新訂單狀態。
    ///
    /// # 注意
    ///
    /// 若訂單狀態已為 valid、processing 或 ready 則不會再次嘗試驗證。
    fn attempt_validation(&mut self, account: &Account) -> Result<()> {
        // 若訂單已屬於 Valid、Processing 或 Ready，不再嘗試
        if matches!(
            self.status,
            OrderStatus::Valid | OrderStatus::Processing | OrderStatus::Ready
        ) {
            return Ok(());
        }
        // 優先進行 DNS 驗證
        if let Some(dns_challenge) = self.challenges.get_mut(&ChallengeType::Dns01) {
            let txt_value = dns_challenge.dns_txt_value();
            let record_name = format!("_acme-challenge.{}", self.domain);
            let start_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let mut dns_ok = false;
            loop {
                match self.check_dns_record(&record_name, &txt_value) {
                    Ok(true) => {
                        dns_ok = true;
                        break;
                    }
                    Ok(false) => {}
                    Err(e) => return Err(e),
                }
                if SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    - start_time
                    > DNS_CHECK_TIMEOUT.as_secs()
                {
                    break;
                }
                thread::sleep(DNS_CHECK_INTERVAL);
            }
            if dns_ok {
                let dns_challenge = self.challenges.get_mut(&ChallengeType::Dns01).unwrap();
                dns_challenge.validate(account)?;
                self.update_status()?;
                return Ok(());
            }
        }
        // 檢查 HTTP 驗證（若有設定驗證路徑）
        if let (Some(http_challenge), Some(path)) = (
            self.challenges.get_mut(&ChallengeType::Http01),
            &self.http_challenge_path,
        ) {
            let content = fs::read_to_string(path)?;
            let expected = http_challenge
                .http_content()
                .ok_or(OrderError::ChallengeNotFound)?;
            if content.trim() == expected {
                http_challenge.validate(account)?;
                self.update_status()?;
                return Ok(());
            }
        }
        Err(OrderError::DnsValidation("DNS 與 HTTP 驗證皆未通過".into()))
    }

    /// 更新訂單狀態：
    ///
    /// 從遠端訂單 URL 重新取得最新狀態資訊並更新本地狀態。
    fn update_status(&mut self) -> Result<()> {
        let updated = Self::get_order(&self.order_url)?;
        self.status = updated.status;
        Ok(())
    }

    /// 取得訂單資料：
    ///
    /// 從訂單 URL 發送 GET 請求並解析回傳的 JSON 資料建立 `Order` 實例。
    ///
    /// # 參數
    ///
    /// - `order_url`: 訂單資料所在的 URL
    ///
    /// # 回傳
    ///
    /// 回傳取得的 `Order` 實例；發生錯誤則回傳 `OrderError`
    fn get_order(order_url: &str) -> Result<Self> {
        let response = Client::new()
            .get(order_url)
            .header("Content-Type", "application/jose+json")
            .send()?;
        let mut order: Self = response.json()?;
        order.order_url = order_url.to_owned();
        Ok(order)
    }

    /// 取得授權挑戰：
    ///
    /// 根據帳號中的 thumbprint 資訊，從各個授權 URL 中拉取並整合挑戰資料。
    ///
    /// # 參數
    ///
    /// - `account`: 提供 thumbprint 計算所需的帳號資訊
    ///
    /// # 回傳
    ///
    /// 成功時更新 `Order` 中的 `challenges` 欄位；否則回傳錯誤
    fn fetch_challenges(&mut self, account: &Account) -> Result<()> {
        let thumbprint = account
            .key_pair
            .thumbprint()
            .map_err(|_| OrderError::ThumbprintError)?;
        self.challenges = self
            .authorizations
            .iter()
            .flat_map(
                |auth_url| match Challenge::fetch_challenges(auth_url, &thumbprint) {
                    Ok(challenges) => challenges.into_iter(),
                    Err(_) => Vec::new().into_iter(),
                },
            )
            .map(|c| (c.challenge_type.clone(), c))
            .collect();
        Ok(())
    }

    /// 建立用於 new order 請求的 JWS。
    ///
    /// 此方法依據帳號資訊與 payload 建立簽名並回傳組合好的 JWS 物件。
    ///
    /// # 參數
    ///
    /// - `account`: 用於取得 nonce、account URL 與金鑰資訊
    /// - `payload_b64`: 已 Base64 編碼的 payload 資料
    ///
    /// # 回傳
    ///
    /// 回傳組合完成的 `Jws` 實例；若失敗則回傳錯誤
    fn build_jws(account: &Account, payload_b64: &Base64) -> Result<Jws> {
        let header = Protection::new(&account.nonce, &account.key_pair.alg_name)
            .set_value(&account.account_url)?
            .create_header(&account.dir.new_order)?
            .to_base64()?;
        let signature = create_signature(&header, payload_b64, &account.key_pair)?;
        Jws::new(&header, payload_b64, &signature).map_err(Into::into)
    }

    /// 檢查 DNS TXT 記錄是否包含預期內容。
    ///
    /// 本方法透過 Google DNS API 取得記錄，並判斷是否包含預期的值。
    ///
    /// # 參數
    ///
    /// - `record_name`: DNS 記錄名稱
    /// - `expected`: 預期應該出現在 TXT 記錄中的內容
    ///
    /// # 回傳
    ///
    /// 回傳 `true` 表示記錄中存在預期內容，`false` 表示不存在；發生錯誤則回傳 `OrderError`
    fn check_dns_record(&self, record_name: &str, expected: &str) -> Result<bool> {
        let client = Client::new();
        let url = format!("https://dns.google/resolve?name={}&type=TXT", record_name);
        let response = client.get(&url).send()?;
        let json: serde_json::Value = serde_json::from_str(&response.text()?)?;
        let records = json["Answer"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|entry| entry["data"].as_str())
            .map(|s| s.trim_matches('"').to_string())
            .collect::<Vec<_>>();
        Ok(records.contains(&expected.to_string()))
    }

    /// 針對 Cloudflare DNS 驗證進行處理：
    ///
    /// 依據所設定的 token 與帳號資訊，處理 DNS TXT 記錄的刪除與新增動作，以符合驗證要求。
    ///
    /// # 參數
    ///
    /// - `token`: 用於 Cloudflare API 驗證的金鑰
    ///
    /// # 回傳
    ///
    /// 成功則回傳 `()`；失敗則回傳相應錯誤
    fn handle_cloudflare_dns(&mut self, token: &str) -> Result<()> {
        let client = Client::new();
        let challenges: Vec<&Challenge> = self
            .challenges
            .values()
            .filter(|c| c.challenge_type == ChallengeType::Dns01)
            .collect();
        if challenges.is_empty() {
            return Err(OrderError::NoDnsChallenge);
        }
        let zone_id = self.get_cloudflare_zone_id(&client, token)?;
        for challenge in challenges {
            let record_name = format!("_acme-challenge.{}", self.domain);
            self.delete_existing_txt_records(&client, token, &zone_id, &record_name)?;
            let content = format!("\"{}\"", challenge.dns_txt_value());
            self.create_cloudflare_txt_record(&client, token, &zone_id, &record_name, &content)?;
        }
        Ok(())
    }

    /// 刪除 Cloudflare 中已存在的 TXT 記錄。
    ///
    /// # 參數
    ///
    /// - `client`: 用於發送 HTTP 請求的 Client 實例
    /// - `token`: Cloudflare API 驗證金鑰
    /// - `zone_id`: 所屬 zone 的 ID
    /// - `record_name`: 要刪除的記錄名稱
    ///
    /// # 回傳
    ///
    /// 成功則回傳 `()`；失敗則回傳錯誤
    fn delete_existing_txt_records(
        &self,
        client: &Client,
        token: &str,
        zone_id: &str,
        record_name: &str,
    ) -> Result<()> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records?type=TXT&name={}",
            zone_id, record_name
        );
        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()?;
        let list: CloudflareDnsListResponse = response.json()?;
        if !list.success {
            return Err(OrderError::Cloudflare(format_cloudflare_errors(
                list.errors,
            )));
        }
        for record in list.result {
            let delete_url = format!(
                "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
                zone_id, record.id
            );
            let del_response = client
                .delete(&delete_url)
                .header("Authorization", format!("Bearer {}", token))
                .send()?;
            let del_result: CloudflareDnsResponse = del_response.json()?;
            if !del_result.success {
                return Err(OrderError::Cloudflare(format_cloudflare_errors(
                    del_result.errors,
                )));
            }
        }
        Ok(())
    }

    /// 取得 Cloudflare Zone ID：
    ///
    /// 根據當前訂單域名從 Cloudflare API 取得對應的 Zone ID。
    ///
    /// # 參數
    ///
    /// - `client`: 用於發送 HTTP 請求的 Client 實例
    /// - `token`: Cloudflare API 驗證金鑰
    ///
    /// # 回傳
    ///
    /// 回傳取得的 Zone ID；若找不到則回傳錯誤
    fn get_cloudflare_zone_id(&self, client: &Client, token: &str) -> Result<String> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones?name={}",
            self.domain
        );
        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()?;
        let result: CloudflareZoneResponse = response.json()?;
        if !result.success {
            return Err(OrderError::Cloudflare(format_cloudflare_errors(
                result.errors,
            )));
        }
        result
            .result
            .first()
            .map(|z| z.id.clone())
            .ok_or_else(|| OrderError::Cloudflare("Zone not found".into()))
    }

    /// 建立 Cloudflare TXT 記錄：
    ///
    /// 依據指定參數在 Cloudflare 上建立一筆新的 TXT 記錄，用於 DNS 驗證。
    ///
    /// # 參數
    ///
    /// - `client`: 用於發送 HTTP 請求的 Client 實例
    /// - `token`: Cloudflare API 驗證金鑰
    /// - `zone_id`: 所屬 zone 的 ID
    /// - `name`: 要建立的記錄名稱
    /// - `content`: TXT 記錄內容
    ///
    /// # 回傳
    ///
    /// 成功則回傳 `()`；失敗則回傳錯誤
    fn create_cloudflare_txt_record(
        &self,
        client: &Client,
        token: &str,
        zone_id: &str,
        name: &str,
        content: &str,
    ) -> Result<()> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
            zone_id
        );
        let record = CloudflareDnsRecord {
            record_type: "TXT".into(),
            name: name.into(),
            content: content.into(),
            ttl: 60,
        };
        let response = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(&record)
            .send()?;
        let result: CloudflareDnsResponse = response.json()?;
        if !result.success {
            return Err(OrderError::Cloudflare(format_cloudflare_errors(
                result.errors,
            )));
        }
        Ok(())
    }
}

/// 用於格式化 Cloudflare API 回傳的錯誤訊息。
///
/// 此輔助函式將 Cloudflare 回傳的錯誤訊息組合成單一字串，便於顯示。
fn format_cloudflare_errors(errors: Vec<CloudflareError>) -> String {
    errors
        .into_iter()
        .map(|e| format!("{}: {}", e.code, e.message))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Cloudflare 相關的 DNS Provider 選項。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsProvider {
    Default,
    Cloudflare,
}

impl FromStr for DnsProvider {
    type Err = OrderError;

    /// 根據字串解析對應的 DNS Provider 選項
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "default" => Ok(Self::Default),
            "cloudflare" => Ok(Self::Cloudflare),
            unknown => Err(OrderError::UnknownDnsProvider(unknown.to_string())),
        }
    }
}

/// 用於在 Cloudflare 上建立 DNS TXT 記錄的資料結構。
#[derive(Debug, Serialize)]
struct CloudflareDnsRecord {
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    content: String,
    ttl: u32,
}

/// Cloudflare DNS TXT 記錄列表回應資料結構。
#[derive(Debug, Deserialize)]
struct CloudflareDnsListResponse {
    success: bool,
    result: Vec<CloudflareDnsRecordItem>,
    errors: Vec<CloudflareError>,
}

/// Cloudflare DNS 記錄項目，僅包含 ID 資訊。
#[derive(Debug, Deserialize)]
struct CloudflareDnsRecordItem {
    id: String,
}

/// Cloudflare Zone 回應資料結構。
#[derive(Debug, Deserialize)]
struct CloudflareZoneResponse {
    success: bool,
    result: Vec<CloudflareZone>,
    errors: Vec<CloudflareError>,
}

/// Cloudflare Zone 基本資料結構，包含 Zone ID。
#[derive(Debug, Deserialize)]
struct CloudflareZone {
    id: String,
}

/// Cloudflare DNS 操作回應資料結構。
#[derive(Debug, Deserialize)]
struct CloudflareDnsResponse {
    success: bool,
    errors: Vec<CloudflareError>,
}

/// Cloudflare API 錯誤訊息結構。
#[derive(Debug, Deserialize)]
struct CloudflareError {
    code: u32,
    message: String,
}

/// 用於解析 finalize 回傳資料的結構。
#[derive(Debug, Deserialize)]
struct OrderUpdateResponse {
    status: OrderStatus,
    certificate: Option<String>,
}
