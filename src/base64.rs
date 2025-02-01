use thiserror::Error;

/// 錯誤類型，用於描述 Base64 編碼與解碼過程中的各種錯誤情形。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DecodeError {
    /// 當遇到無效字符時返回此錯誤，包含該無效字符的 ASCII 值。
    #[error("Invalid character: {0}")]
    InvalidCharacter(u8),

    /// 當 Base64 字符串的填充（`=`）不符合規範時返回此錯誤。
    #[error("Invalid padding")]
    InvalidPadding,

    /// 當 Base64 字符串的長度不符合要求（必須是 4 的倍數）時返回此錯誤。
    #[error("Invalid length")]
    InvalidLength,
}

/// 提供 Base64 編碼與解碼功能的結構體。
///
/// # 示例
///
/// ```
/// # use your_crate::Base64;
/// let data = "Hello, World!";
/// let b64 = Base64::new(data);
/// assert_eq!(b64.as_str(), "SGVsbG8sIFdvcmxkIQ==");
/// ```
pub struct Base64 {
    encoded: String,
}

impl Base64 {
    // Base64 的字符映射表，包含標準 Base64 編碼所需的所有字符。
    const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// 根據輸入數據生成 Base64 編碼。
    ///
    /// 該函數接受任何可轉換為字節切片的類型（例如 `&str` 或 `Vec<u8>`），
    /// 並返回一個包含標準 Base64 編碼字符串的 `Base64` 實例。
    ///
    /// # 示例
    ///
    /// ```
    /// # use your_crate::Base64;
    /// let b64 = Base64::new("abc");
    /// assert_eq!(b64.as_str(), "YWJj");
    /// ```
    pub fn new<T: AsRef<[u8]>>(input: T) -> Self {
        let bytes = input.as_ref();
        let mut output = Vec::with_capacity((bytes.len() + 2) / 3 * 4);
        let chunks = bytes.chunks(3);

        for chunk in chunks {
            let b1 = chunk[0];
            let b2 = chunk.get(1).copied().unwrap_or(0);
            let b3 = chunk.get(2).copied().unwrap_or(0);

            let c1 = Self::BASE64_CHARS[(b1 >> 2) as usize];
            let c2 = Self::BASE64_CHARS[((b1 & 0x03) << 4 | (b2 >> 4)) as usize];

            let c3 = if chunk.len() > 1 {
                Self::BASE64_CHARS[((b2 & 0x0F) << 2 | (b3 >> 6)) as usize]
            } else {
                b'='
            };

            let c4 = if chunk.len() > 2 {
                Self::BASE64_CHARS[(b3 & 0x3F) as usize]
            } else {
                b'='
            };

            output.extend_from_slice(&[c1, c2, c3, c4]);
        }

        let encoded = String::from_utf8(output).expect("Invalid UTF-8 sequence");
        Self { encoded }
    }

    /// 根據已編碼的 Base64 字符串生成 `Base64` 實例，並進行基礎驗證。
    ///
    /// 如果傳入的字符串不符合 Base64 規範（例如長度不正確或存在無效字符），
    /// 該函數會返回對應的 [`DecodeError`]。
    ///
    /// # 錯誤
    ///
    /// 可能返回 [`DecodeError::InvalidLength`], [`DecodeError::InvalidCharacter`] 或
    /// [`DecodeError::InvalidPadding`] 之一。
    pub fn from_encoded(encoded: &str) -> Result<Self, DecodeError> {
        validate_base64(encoded)?;
        Ok(Self {
            encoded: encoded.to_string(),
        })
    }

    /// 從 URL 安全格式的 Base64 字符串生成 `Base64` 實例。
    ///
    /// URL 安全格式將 `+` 替換為 `-`，`/` 替換為 `_`，並且通常去掉填充符號 `=`
    /// 。此函數會將 URL 安全格式轉換回標準 Base64 格式後進行驗證。
    ///
    /// # 錯誤
    ///
    /// 同 [`from_encoded`](Self::from_encoded)。
    pub fn from_url(url_encoded: &str) -> Result<Self, DecodeError> {
        let mut encoded = url_encoded.replace('-', "+").replace('_', "/");
        let mod4 = encoded.len() % 4;
        if mod4 != 0 {
            encoded.push_str(&"=".repeat(4 - mod4));
        }
        Self::from_encoded(&encoded)
    }

    /// 將當前 Base64 編碼的數據解碼為原始二進制數據。
    ///
    /// 該函數將標準 Base64 字符串解碼為 [`Vec<u8>`]，如果解碼過程中發現任何問題，
    /// 例如遇到無效字符或填充錯誤，則返回相應的 [`DecodeError`]。
    ///
    /// # 錯誤
    ///
    /// 可能返回 [`DecodeError::InvalidCharacter`] 或 [`DecodeError::InvalidPadding`]。
    pub fn decode(&self) -> Result<Vec<u8>, DecodeError> {
        let encoded = self.encoded.as_bytes();
        let mut buffer = Vec::with_capacity((encoded.len() / 4) * 3);

        for chunk in encoded.chunks_exact(4) {
            let c1 = decode_char(chunk[0])?;
            let c2 = decode_char(chunk[1])?;
            let (c3, c4, valid_bytes) = match (chunk[2], chunk[3]) {
                (b'=', b'=') => (0, 0, 1),
                (b'=', _) => return Err(DecodeError::InvalidPadding),
                (_, b'=') => (decode_char(chunk[2])?, 0, 2),
                _ => (decode_char(chunk[2])?, decode_char(chunk[3])?, 3),
            };

            let group = (c1 as u32) << 18 | (c2 as u32) << 12 | (c3 as u32) << 6 | (c4 as u32);

            buffer.push((group >> 16) as u8);
            if valid_bytes >= 2 {
                buffer.push((group >> 8 & 0xFF) as u8);
            }
            if valid_bytes >= 3 {
                buffer.push((group & 0xFF) as u8);
            }
        }

        Ok(buffer)
    }

    /// 將標準 Base64 編碼轉換為 URL 安全的 Base64 字符串。
    ///
    /// 轉換規則為：
    /// - 將 `+` 替換為 `-`
    /// - 將 `/` 替換為 `_`
    /// - 移除填充符號 `=`
    pub fn base64_url(&self) -> String {
        self.encoded
            .replace('+', "-")
            .replace('/', "_")
            .replace('=', "")
    }

    /// 返回內部存儲的標準 Base64 編碼字符串的引用。
    ///
    /// 這允許用戶直接訪問原始的 Base64 編碼結果。
    pub fn as_str(&self) -> &str {
        &self.encoded
    }
}

/// 驗證給定字符串是否符合標準 Base64 格式要求。
///
/// 檢查內容包括：
/// - 字符串長度是否為 4 的倍數。
/// - 填充符號 `=` 是否出現在合理的位置。
/// - 除填充符號外，所有字符是否在有效的 Base64 字符集合中。
///
/// # 錯誤
///
/// 返回 [`DecodeError::InvalidLength`], [`DecodeError::InvalidPadding`] 或
/// [`DecodeError::InvalidCharacter`] 當檢查失敗時。
fn validate_base64(s: &str) -> Result<(), DecodeError> {
    if s.len() % 4 != 0 {
        return Err(DecodeError::InvalidLength);
    }

    let bytes = s.as_bytes();
    let mut padding_start = None;

    for (i, &c) in bytes.iter().enumerate() {
        if c == b'=' {
            if padding_start.is_none() {
                padding_start = Some(i);
            }
            if i < bytes.len() - 2 {
                return Err(DecodeError::InvalidPadding);
            }
        } else if !is_valid_base64_char(c) {
            return Err(DecodeError::InvalidCharacter(c));
        }
    }

    if let Some(start) = padding_start {
        if bytes.len() - start > 2 {
            return Err(DecodeError::InvalidPadding);
        }
    }

    Ok(())
}

/// 根據 Base64 字符返回其對應的數值。
///
/// # 錯誤
///
/// 當字符不在有效的 Base64 字符範圍內時返回 [`DecodeError::InvalidCharacter`]。
fn decode_char(c: u8) -> Result<u8, DecodeError> {
    match c {
        b'A'..=b'Z' => Ok(c - b'A'),
        b'a'..=b'z' => Ok(c - b'a' + 26),
        b'0'..=b'9' => Ok(c - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(DecodeError::InvalidCharacter(c)),
    }
}

/// 判斷給定字符是否屬於有效的 Base64 字符集合。
fn is_valid_base64_char(c: u8) -> bool {
    matches!(c, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_encoding() {
        let input = "Hello, World!";
        let base64 = Base64::new(input);
        assert_eq!(base64.as_str(), "SGVsbG8sIFdvcmxkIQ==");
    }

    #[test]
    fn test_url_safe_encoding() {
        let input = "Hello+World/123=";
        let base64 = Base64::new(input);
        let url_safe = base64.base64_url();
        assert!(!url_safe.contains('+'));
        assert!(!url_safe.contains('/'));
        assert!(!url_safe.contains('='));
    }

    #[test]
    fn test_different_lengths() {
        let base64 = Base64::new("a");
        assert_eq!(base64.as_str(), "YQ==");

        let base64 = Base64::new("ab");
        assert_eq!(base64.as_str(), "YWI=");

        let base64 = Base64::new("abc");
        assert_eq!(base64.as_str(), "YWJj");
    }

    #[test]
    fn test_binary_data() {
        let input = vec![0xFF, 0x00, 0xFF];
        let base64 = Base64::new(input);
        assert_eq!(base64.as_str(), "/wD/");
    }

    #[test]
    fn test_decode_basic() {
        let base64 = Base64::from_encoded("SGVsbG8sIFdvcmxkIQ==").unwrap();
        assert_eq!(base64.decode().unwrap(), b"Hello, World!");
    }

    #[test]
    fn test_from_url() {
        let base64 = Base64::from_url("SGVsbG8sIFdvcmxkIQ").unwrap();
        assert_eq!(base64.encoded, "SGVsbG8sIFdvcmxkIQ==");
        assert_eq!(base64.decode().unwrap(), b"Hello, World!");
    }

    #[test]
    fn test_invalid_char() {
        assert!(matches!(
            Base64::from_encoded("SGVsbG8$Ww=="),
            Err(DecodeError::InvalidCharacter(b'$'))
        ));
    }

    #[test]
    fn test_invalid_padding() {
        assert!(matches!(
            Base64::from_encoded("A==="),
            Err(DecodeError::InvalidPadding)
        ));
    }

    #[test]
    fn test_invalid_length() {
        assert!(matches!(
            Base64::from_encoded("AAA"),
            Err(DecodeError::InvalidLength)
        ));
    }
}

