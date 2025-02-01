use crate::{base64::Base64, key_pair::KeyPair};
use openssl::hash::MessageDigest;
use openssl::sign::Signer;
use std::error::Error;

/// 定義簽名操作可能遇到的錯誤類型。
#[derive(Debug)]
pub enum SignatureError {
    /// 簽名過程中發生錯誤，附帶錯誤訊息。
    SigningError(String),
    /// 不支援的簽名演算法，附帶未支援的演算法名稱。
    UnsupportedAlgorithm(String),
    /// 序列化過程中發生錯誤，附帶 `serde_json` 的錯誤。
    SerializationError(serde_json::Error),
}

impl std::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            SignatureError::UnsupportedAlgorithm(alg) => {
                write!(f, "Unsupported algorithm: {}", alg)
            }
            SignatureError::SigningError(msg) => write!(f, "Signing error: {}", msg),
            SignatureError::SerializationError(e) => write!(f, "Serialization error: {}", e),
        }
    }
}

impl From<serde_json::Error> for SignatureError {
    fn from(e: serde_json::Error) -> Self {
        SignatureError::SerializationError(e)
    }
}

impl Error for SignatureError {}

/// 定義簽名演算法的介面。
///
/// 實作此介面的類型需提供對指定資料進行簽名的功能。
trait SignatureAlgorithmT {
    /// 使用指定的金鑰對資料進行簽名。
    ///
    /// # 參數
    ///
    /// - `data`: 要簽名的資料位元組陣列。
    /// - `key_pair`: 包含私鑰的金鑰對，用於進行簽名。
    ///
    /// # 回傳
    ///
    /// 若簽名成功，回傳簽名後的位元組陣列；否則回傳 `SignatureError`。
    fn sign(&self, data: &[u8], key_pair: &KeyPair) -> Result<Vec<u8>, SignatureError>;
}

/// RSA 簽名演算法的實作。
struct RSASignature;

impl SignatureAlgorithmT for RSASignature {
    fn sign(&self, data: &[u8], key_pair: &KeyPair) -> Result<Vec<u8>, SignatureError> {
        // 建立使用 SHA-256 訊息摘要的簽名器
        let mut signer = Signer::new(MessageDigest::sha256(), &key_pair.pri_key)
            .map_err(|e| SignatureError::SigningError(e.to_string()))?;

        // 將資料更新到簽名器中
        signer
            .update(data)
            .map_err(|e| SignatureError::SigningError(e.to_string()))?;

        // 產生簽名並以位元組向量形式回傳
        signer
            .sign_to_vec()
            .map_err(|e| SignatureError::SigningError(e.to_string()))
    }
}

/// 簽名演算法工廠，用於根據演算法名稱取得對應的簽名演算法實作。
struct SignatureAlgorithmFactory;

impl SignatureAlgorithmFactory {
    /// 根據演算法名稱取得對應的簽名演算法。
    ///
    /// # 參數
    ///
    /// - `alg_name`: 指定的演算法名稱（不區分大小寫）。
    ///
    /// # 回傳
    ///
    /// 若支援該演算法，回傳封裝在 Box 中的 `SignatureAlgorithmT` 實作；否則回傳 `SignatureError`。
    fn get_algorithm(alg_name: &str) -> Result<Box<dyn SignatureAlgorithmT>, SignatureError> {
        match alg_name.to_uppercase().as_str() {
            "RSA" => Ok(Box::new(RSASignature)),
            _ => Err(SignatureError::UnsupportedAlgorithm(alg_name.to_string())),
        }
    }
}

/// 根據提供的 header、payload 與金鑰對，生成對應的簽名。
///
/// 此函式首先會依據 header 與 payload 的 Base64 URL 編碼值組合出簽名輸入，
/// 然後依據金鑰對所指定的演算法取得相應的簽名演算法實作進行簽名，
/// 最後將簽名結果以 Base64 形式回傳。
///
/// # 參數
///
/// - `header_b64`: 已進行 Base64 URL 編碼的標頭資料。
/// - `payload_b64`: 已進行 Base64 URL 編碼的有效負載資料。
/// - `key_pair`: 包含私鑰與演算法名稱的金鑰對，用於簽名。
///
/// # 回傳
///
/// 成功時回傳簽名後的 Base64 編碼資料；失敗時回傳 `SignatureError`。
pub fn create_signature(
    header_b64: &Base64,
    payload_b64: &Base64,
    key_pair: &KeyPair,
) -> Result<Base64, SignatureError> {
    let signing_input = format!("{}.{}", header_b64.base64_url(), payload_b64.base64_url());
    let algorithm = SignatureAlgorithmFactory::get_algorithm(&key_pair.alg_name)?;

    let signature = algorithm.sign(signing_input.as_bytes(), key_pair)?;

    Ok(Base64::new(&signature))
}
