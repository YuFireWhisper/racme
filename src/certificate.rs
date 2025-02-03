use chrono::{DateTime, Utc};
use openssl::{asn1::Asn1Time, x509::X509};
use thiserror::Error;

/// 證書相關操作可能出現的錯誤類型
#[derive(Debug, Error)]
pub enum CertificateError {
    #[error("Failed to parse certificate: {0}")]
    ParseError(#[from] openssl::error::ErrorStack),
    #[error("Certificate expired since {0}")]
    Expired(DateTime<Utc>),
    #[error("Invalid expiration timestamp")]
    InvalidTimestamp,
    #[error("Failed to parse expiration time: {0}")]
    ExpirationTimeParseError(String),
}

/// 自定義結果型別，錯誤類型為 `CertificateError`
type Result<T> = std::result::Result<T, CertificateError>;

/// X.509 證書封裝結構，提供基本的證書解析與續約檢查功能
pub struct Certificate {
    /// 內部使用的 X509 證書對象
    pub cert: X509,
}

impl Certificate {
    /// 建立一個 `Certificate` 實例
    ///
    /// 根據傳入的 PEM 格式字串解析生成 X.509 證書，若格式錯誤將回傳對應錯誤。
    ///
    /// # 參數
    ///
    /// - `pem`: 包含證書資訊的 PEM 格式字串
    ///
    /// # 回傳
    ///
    /// 回傳一個封裝了 X.509 證書的 `Certificate` 實例，或錯誤類型 `CertificateError`
    pub fn new(pem: &str) -> Result<Self> {
        let cert = X509::from_pem(pem.as_bytes())?;
        Ok(Certificate { cert })
    }

    /// 判斷證書是否應該進行續約
    ///
    /// 此方法會計算證書剩餘的有效時間，並與給定的天數閾值進行比較，
    /// 當剩餘時間低於閾值時，表示證書需要續約。
    ///
    /// # 參數
    ///
    /// - `threshold_days`: 續約閾值（以天為單位），當證書剩餘有效時間低於該值時，
    ///   建議進行續約
    ///
    /// # 回傳
    ///
    /// 若證書剩餘有效時間小於閾值則回傳 `true`，否則回傳 `false`；遇到解析或計算錯誤時，
    /// 則回傳對應的 `CertificateError`
    pub fn should_renew(&self, threshold_days: u32) -> Result<bool> {
        let not_after = self.cert.not_after();
        let now_ts = Utc::now().timestamp();
        let now_asn1 = Asn1Time::from_unix(now_ts)?;
        let diff = not_after.diff(now_asn1.as_ref())?;
        let remaining_seconds = diff.days as i64 * 86400 + diff.secs as i64;
        let threshold_seconds = threshold_days as i64 * 86400;

        println!("Remaining seconds: {}", remaining_seconds);
        println!("Threshold seconds: {}", threshold_seconds);

        Ok(remaining_seconds <= 0 || -remaining_seconds > threshold_seconds)
    }
}
