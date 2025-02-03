use openssl::{
    error::ErrorStack,
    pkey::{Id, PKey, Private, Public},
    rsa::Rsa,
    sha::sha256,
};
use thiserror::Error;

use crate::{
    base64::Base64,
    jwk::{Jwk, JwkError},
    storage::{Storage, StorageError},
};

/// 鍵相關操作的錯誤列舉，涵蓋 OpenSSL、存儲、JWK 與其他相關錯誤。
#[derive(Debug, Error)]
pub enum KeyError {
    #[error("OpenSSL error: {0}")]
    OpenSSL(#[from] ErrorStack),
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("Unsupported algorithm")]
    UnsupportedAlgorithm,
    #[error("JWK error")]
    KeyConversionFailed,
    #[error("Thumbprint error")]
    ThumbprintError,
    #[error("JWK error")]
    JwkError(#[from] JwkError),
}

/// 本模組使用的結果類型，當中錯誤皆為 `KeyError`。
type Result<T> = std::result::Result<T, KeyError>;

/// 表示一組非對稱加密的金鑰對。
///
/// 此結構包含演算法名稱、私鑰與對應的公鑰，並提供產生、轉換與相關操作的方法。
#[derive(Debug)]
pub struct KeyPair {
    /// 加密演算法名稱，目前僅支援 "RSA"。
    pub alg_name: String,
    /// 私鑰，使用 OpenSSL 的 `PKey` 封裝。
    pub pri_key: PKey<Private>,
    /// 公鑰，從私鑰派生而來。
    pub pub_key: PKey<Public>,
}

impl KeyPair {
    /// 根據參數建立一組金鑰對，並可選擇從指定存儲位置讀取現有私鑰。
    ///
    /// # 參數
    ///
    /// - `storage`: 實現了 `Storage` 特性的存儲對象，用於讀寫私鑰資料。
    /// - `alg_name`: 金鑰所使用的加密演算法名稱，目前僅支援 "RSA"。
    /// - `bits`: 可選的金鑰長度，若未提供則預設為 2048 位元（僅適用於 RSA）。
    /// - `path`: 可選的檔案路徑，若指定則嘗試從該路徑讀取私鑰；若不存在則產生新金鑰並寫入。
    ///
    /// # 回傳
    ///
    /// 成功回傳建立好的 `KeyPair`，否則回傳對應的 `KeyError`。
    pub fn new(
        storage: &dyn Storage,
        alg_name: &str,
        bits: Option<u32>,
        path: Option<&str>,
    ) -> Result<Self> {
        let alg_name = Self::normalize_algorithm_name(alg_name)?;

        if path.is_none() {
            let pri_key = Self::generate_key(&alg_name, bits)?;
            let pub_key = Self::derive_public_key(&pri_key)?;

            return Ok(Self {
                alg_name,
                pri_key,
                pub_key,
            });
        }

        let path = path.unwrap();
        match storage.read_file(path) {
            Ok(pri_key_data) => {
                let pri_key = PKey::private_key_from_pem(&pri_key_data)?;
                let pub_key = Self::derive_public_key(&pri_key)?;
                return Ok(Self {
                    alg_name,
                    pri_key,
                    pub_key,
                });
            }
            Err(StorageError::NotFound(_)) => {}
            Err(e) => {
                return Err(KeyError::Storage(e));
            }
        }

        let pri_key = Self::generate_key(&alg_name, bits)?;
        let pub_key = Self::derive_public_key(&pri_key)?;

        storage.write_file(path, &pri_key.private_key_to_pem_pkcs8()?)?;

        Ok(Self {
            alg_name,
            pri_key,
            pub_key,
        })
    }

    /// 將輸入的演算法名稱標準化，目前僅支援 "RSA" 演算法。
    ///
    /// # 參數
    ///
    /// - `name`: 輸入的演算法名稱（不分大小寫）。
    ///
    /// # 回傳
    ///
    /// 標準化後的演算法名稱，或當演算法不支援時回傳 `KeyError::UnsupportedAlgorithm`。
    fn normalize_algorithm_name(name: &str) -> Result<String> {
        match name.to_uppercase().as_str() {
            "RSA" => Ok("RSA".to_owned()),
            _ => Err(KeyError::UnsupportedAlgorithm),
        }
    }

    /// 根據私鑰派生出對應的公鑰。
    ///
    /// # 參數
    ///
    /// - `pri_key`: 參考私鑰。
    ///
    /// # 回傳
    ///
    /// 成功回傳對應的公鑰，否則回傳 `KeyError::UnsupportedAlgorithm` 或其他相關錯誤。
    fn derive_public_key(pri_key: &PKey<Private>) -> Result<PKey<Public>> {
        match pri_key.id() {
            Id::RSA => {
                let rsa = pri_key.rsa()?;
                let pub_rsa =
                    Rsa::from_public_components(rsa.n().to_owned()?, rsa.e().to_owned()?)?;
                Ok(PKey::from_rsa(pub_rsa)?)
            }
            _ => Err(KeyError::UnsupportedAlgorithm),
        }
    }

    /// 根據指定演算法與金鑰長度產生新的私鑰。
    ///
    /// # 參數
    ///
    /// - `alg_name`: 標準化的演算法名稱，目前僅支援 "RSA"。
    /// - `bits`: 可選的金鑰長度，若未提供則預設為 2048 位元（僅適用於 RSA）。
    ///
    /// # 回傳
    ///
    /// 成功回傳新產生的私鑰，否則回傳 `KeyError::UnsupportedAlgorithm` 或其他相關錯誤。
    fn generate_key(alg_name: &str, bits: Option<u32>) -> Result<PKey<Private>> {
        match alg_name {
            "RSA" => {
                let rsa = Rsa::generate(bits.unwrap_or(2048))?;
                Ok(PKey::from_rsa(rsa)?)
            }
            _ => Err(KeyError::UnsupportedAlgorithm),
        }
    }

    /// 計算並回傳金鑰對的縮影（thumbprint），用於唯一識別金鑰。
    ///
    /// 透過 JWK 格式轉換與 SHA-256 雜湊運算產生縮影，最後以 URL-safe Base64 字串回傳。
    ///
    /// # 回傳
    ///
    /// 成功回傳 thumbprint 字串，否則回傳相對應的錯誤。
    pub fn thumbprint(&self) -> Result<String> {
        let jwk = Jwk::new(self, None)?;
        let hash = sha256(jwk.to_acme_json()?.as_bytes());
        Ok(Base64::new(hash).base64_url())
    }

    /// 根據 PEM 格式的私鑰資料建立一組金鑰對。
    ///
    /// # 參數
    ///
    /// - `pri_key_pem`: 私鑰的 PEM 格式位元組切片。
    ///
    /// # 回傳
    ///
    /// 成功回傳建立好的 `KeyPair`，否則回傳對應的錯誤。
    pub fn from_pem(pri_key_pem: &[u8]) -> Result<Self> {
        let pri_key = PKey::private_key_from_pem(pri_key_pem)?;
        let pub_key = Self::derive_public_key(&pri_key)?;

        Ok(Self {
            alg_name: "RSA".to_owned(),
            pri_key,
            pub_key,
        })
    }

    /// 從指定的檔案路徑讀取 PEM 格式的私鑰並建立金鑰對。
    ///
    /// # 參數
    ///
    /// - `storage`: 實現了 `Storage` 特性的存儲對象。
    /// - `path`: 儲存私鑰 PEM 資料的檔案路徑。
    ///
    /// # 回傳
    ///
    /// 成功回傳建立好的 `KeyPair`，否則回傳對應的錯誤。
    pub fn from_file(storage: &dyn Storage, path: &str) -> Result<Self> {
        let pri_key_data = storage.read_file(path)?;
        Self::from_pem(&pri_key_data)
    }

    /// 取得金鑰的參數，例如 RSA 金鑰的位元長度。
    ///
    /// # 回傳
    ///
    /// 成功回傳金鑰的位元長度（例如 2048 表示 2048 位元），否則回傳 `KeyError::UnsupportedAlgorithm` 或其他相關錯誤。
    pub fn key_parameters(&self) -> Result<u32> {
        match self.pri_key.id() {
            Id::RSA => {
                let rsa = self.pri_key.rsa()?;
                Ok(rsa.size() * 8)
            }
            _ => Err(KeyError::UnsupportedAlgorithm),
        }
    }
}
