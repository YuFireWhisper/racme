use serde::{Deserialize, Serialize};
use std::error::Error;

use crate::base64::Base64;

/// 定義所有 API 載荷（Payload）必須實作的功能。
///
/// 該 trait 要求實作者能夠序列化、反序列化，並提供轉換成 JSON 字串與 Base64 表示的功能，
/// 同時必須實作自定義的驗證邏輯。
pub trait PayloadT: Serialize + for<'de> Deserialize<'de> {
    /// 將載荷轉換成 JSON 格式的字串。
    ///
    /// # 範例
    ///
    /// ```
    /// # use serde::{Serialize, Deserialize};
    /// # #[derive(Serialize, Deserialize)]
    /// # struct MyPayload;
    /// # impl PayloadT for MyPayload {
    /// #   fn validate(&self) -> Result<(), Box<dyn std::error::Error>> { Ok(()) }
    /// # }
    /// let payload = MyPayload;
    /// let json = payload.to_json_string().unwrap();
    /// ```
    ///
    /// # 錯誤
    ///
    /// 若序列化失敗，則回傳 [`serde_json::Error`]。
    fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// 將載荷先轉換成 JSON 字串，再以 Base64 進行編碼。
    ///
    /// # 範例
    ///
    /// ```
    /// # use serde::{Serialize, Deserialize};
    /// # use crate::base64::Base64;
    /// # #[derive(Serialize, Deserialize)]
    /// # struct MyPayload;
    /// # impl PayloadT for MyPayload {
    /// #   fn validate(&self) -> Result<(), Box<dyn std::error::Error>> { Ok(()) }
    /// # }
    /// let payload = MyPayload;
    /// let b64 = payload.to_base64().unwrap();
    /// ```
    ///
    /// # 錯誤
    ///
    /// 若轉換過程中發生錯誤，則回傳 [`serde_json::Error`]。
    fn to_base64(&self) -> Result<Base64, serde_json::Error> {
        let json_string = self.to_json_string()?;
        Ok(Base64::new(json_string.as_bytes()))
    }

    /// 驗證載荷資料是否符合預期的規範。
    ///
    /// 實作者需要根據各自的業務邏輯來檢查資料的正確性。
    ///
    /// # 錯誤
    ///
    /// 若驗證失敗，則回傳對應的錯誤。
    fn validate(&self) -> Result<(), Box<dyn Error>>;
}

/// 表示建立新帳號所需的載荷資料。
///
/// 該結構主要用於 ACME 協議中建立帳號時所需要提供的聯絡資訊與使用者協議確認。
#[derive(Debug, Serialize, Deserialize)]
pub struct NewAccountPayload {
    contact: Vec<String>,
    #[serde(rename = "termsOfServiceAgreed")]
    terms_of_service_agreed: bool,
}

impl NewAccountPayload {
    /// 建立一個新的 `NewAccountPayload` 實例。
    ///
    /// 傳入的 `email` 參數會自動補足 `mailto:` 前綴，若已包含則不重複補充。
    ///
    /// # 參數
    ///
    /// - `email`: 用戶的電子郵件地址。
    ///
    /// # 回傳
    ///
    /// 回傳一個設定完成且已同意服務條款的 `NewAccountPayload` 實例。
    pub fn new(email: &str) -> Self {
        let contact = if email.starts_with("mailto:") {
            vec![email.to_string()]
        } else {
            vec![format!("mailto:{}", email)]
        };

        NewAccountPayload {
            contact,
            terms_of_service_agreed: true,
        }
    }
}

impl PayloadT for NewAccountPayload {
    /// 驗證新帳號載荷資料：
    ///
    /// - 必須提供聯絡資訊。
    /// - 使用者必須同意服務條款。
    fn validate(&self) -> Result<(), Box<dyn Error>> {
        if self.contact.is_empty() {
            return Err("Contact information is required".into());
        }
        if !self.terms_of_service_agreed {
            return Err("Terms of service must be agreed".into());
        }
        Ok(())
    }
}

/// 表示一個識別項，用來描述證書所涵蓋的主機名稱等資訊。
#[derive(Debug, Serialize, Deserialize)]
pub struct Identifier {
    #[serde(rename = "type")]
    pub type_: String,
    pub value: String,
}

/// 表示建立新訂單時所需的載荷資料。
///
/// 該載荷中包含一組識別項，代表需驗證的域名。
#[derive(Debug, Serialize, Deserialize)]
pub struct NewOrderPayload {
    pub identifiers: Vec<Identifier>,
}

impl NewOrderPayload {
    /// 建立一個新的 `NewOrderPayload` 實例。
    ///
    /// 給定一組域名，該方法會自動為每個域名建立一個識別項，其類型固定為 `"dns"`。
    ///
    /// # 參數
    ///
    /// - `domains`: 包含域名的字串切片向量。
    ///
    /// # 回傳
    ///
    /// 回傳包含所有識別項的 `NewOrderPayload` 實例。
    pub fn new(domains: Vec<&str>) -> Self {
        let identifiers = domains
            .into_iter()
            .map(|domain| Identifier {
                type_: "dns".to_string(),
                value: domain.to_string(),
            })
            .collect();

        NewOrderPayload { identifiers }
    }
}

impl PayloadT for NewOrderPayload {
    /// 驗證新訂單載荷資料：
    ///
    /// - 必須至少包含一個識別項。
    /// - 所有識別項的類型必須為 `"dns"` 且值不得為空。
    fn validate(&self) -> Result<(), Box<dyn Error>> {
        if self.identifiers.is_empty() {
            return Err("At least one identifier is required".into());
        }
        for identifier in &self.identifiers {
            if identifier.type_ != "dns" {
                return Err("Identifier type must be 'dns'".into());
            }
            if identifier.value.is_empty() {
                return Err("Identifier value cannot be empty".into());
            }
        }
        Ok(())
    }
}

/// 表示挑戰驗證的載荷資料。
///
/// 在某些情境下，挑戰驗證不需要額外的參數，因此使用空結構表示。
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ChallengeValidationPayload {}

impl ChallengeValidationPayload {
    /// 建立一個新的 `ChallengeValidationPayload` 實例。
    ///
    /// 由於該結構不包含任何欄位，此方法僅回傳預設值。
    pub fn new() -> Self {
        Self::default()
    }
}

impl PayloadT for ChallengeValidationPayload {
    /// 驗證挑戰驗證載荷資料。
    ///
    /// 由於無需額外檢查，因此始終回傳 `Ok(())`。
    fn validate(&self) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
}

/// 表示最終化訂單時所需的載荷資料。
///
/// 該載荷主要包含 CSR（證書簽署請求）的 Base64 URL 安全編碼字串。
#[derive(Debug, Serialize, Deserialize)]
pub struct FinalizeOrderPayload {
    #[serde(rename = "csr")]
    csr_b64_str: String,
}

impl FinalizeOrderPayload {
    /// 建立一個新的 `FinalizeOrderPayload` 實例。
    ///
    /// 將傳入的 Base64 表示的 CSR 轉換成 URL 安全的編碼字串。
    ///
    /// # 參數
    ///
    /// - `csr_b64`: CSR 的 Base64 表示，使用自定義的 [`Base64`] 型態。
    ///
    /// # 回傳
    ///
    /// 回傳包含 CSR 編碼字串的 `FinalizeOrderPayload` 實例。
    pub fn new(csr_b64: &Base64) -> Self {
        FinalizeOrderPayload {
            csr_b64_str: csr_b64.base64_url(),
        }
    }
}

impl PayloadT for FinalizeOrderPayload {
    /// 驗證最終化訂單載荷資料。
    ///
    /// 目前無需額外驗證，因此始終回傳 `Ok(())`。
    fn validate(&self) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
}
