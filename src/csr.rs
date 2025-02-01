use std::result;

use openssl::{
    hash::MessageDigest,
    stack::Stack,
    x509::{extension::SubjectAlternativeName, X509Req},
};
use thiserror::Error;

use crate::key_pair::KeyPair;

/// 用於描述建立 CSR（證書簽名請求）過程中可能發生的錯誤。
#[derive(Debug, Error)]
pub enum CsrError {
    #[error("Openssl error: {0}")]
    OpensslError(#[from] openssl::error::ErrorStack),
    #[error("No SAN entries")]
    NoSanEntries,
}

/// 為簡化錯誤處理定義 Result 類型
type Result<T> = result::Result<T, CsrError>;

/// 表示一個 CSR 建構器，主要用於生成包含主體替代名稱 (SAN) 擴展的證書簽名請求。
///
/// # 範例
///
/// ```
/// # use your_crate::csr::CSR;
/// # use your_crate::key_pair::KeyPair;
/// let key_pair = KeyPair::generate().expect("金鑰生成失敗");
/// let csr = CSR::new()
///     .set_san("example.com")
///     .build(&key_pair)
///     .expect("CSR 建立失敗");
/// ```
pub struct CSR {
    san_entries: Vec<String>,
}

impl CSR {
    /// 建立一個新的 CSR 實例。
    ///
    /// 此方法初始化一個空的 SAN 列表，之後可以藉由 `set_san` 方法新增域名。
    ///
    /// # 錯誤
    ///
    /// 如果初始化過程中遇到 OpenSSL 相關錯誤，將回傳 `CsrError::OpensslError`。
    pub fn new() -> Result<Self> {
        Ok(CSR {
            san_entries: Vec::new(),
        })
    }

    /// 新增一個 DNS 主體替代名稱 (SAN) 到 CSR 中。
    ///
    /// 該方法接受一個字串切片參數，代表 DNS 名稱，並將其加入內部的 SAN 清單中。
    ///
    /// # 範例
    ///
    /// ```
    /// # use your_crate::csr::CSR;
    /// let csr = CSR::new().expect("初始化失敗").set_san("example.com");
    /// ```
    pub fn set_san(mut self, dns_name: &str) -> Self {
        self.san_entries.push(dns_name.to_string());
        self
    }

    /// 根據當前設定的 SAN 項目以及指定的金鑰對構建一個 X509 證書簽名請求 (CSR)。
    ///
    /// 該方法會驗證是否已經設定至少一個 SAN 項目，否則會回傳 `CsrError::NoSanEntries`。
    /// 接著，會建立 SAN 擴展並加入到請求中，最後使用提供的金鑰對簽署 CSR。
    ///
    /// # 參數
    ///
    /// * `key_pair` - 用於簽署 CSR 的金鑰對，包含私鑰資訊。
    ///
    /// # 錯誤
    ///
    /// 若在過程中遇到 OpenSSL 的錯誤或未設定 SAN 項目，將回傳相對應的 `CsrError`。
    pub fn build(self, key_pair: &KeyPair) -> Result<X509Req> {
        let mut req_builder = X509Req::builder()?;

        if self.san_entries.is_empty() {
            return Err(CsrError::NoSanEntries);
        }

        let mut san_builder = SubjectAlternativeName::new();
        for entry in self.san_entries {
            san_builder.dns(&entry);
        }
        let san_extension = san_builder.build(&req_builder.x509v3_context(None))?;

        let mut stack = Stack::new()?;
        stack.push(san_extension)?;
        req_builder.add_extensions(&stack)?;

        req_builder.set_pubkey(&key_pair.pri_key)?;
        req_builder.sign(&key_pair.pri_key, MessageDigest::sha256())?;

        Ok(req_builder.build())
    }
}
