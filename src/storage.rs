use std::{
    collections::HashMap,
    fmt,
    io::{self, BufRead, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use thiserror::Error;

/// 儲存操作可能發生的錯誤類型。
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Key is invalid: {0}")]
    InvalidKey(String),
    #[error("Key not found: {0}")]
    NotFound(String),
    #[error("Key is a dir: {0}")]
    IsDir(String),
    #[error("Not a directory: {0}")]
    NotDirectory(String),
    #[error("Lock poisoned")]
    LockPoisoned,
    #[error("File is corrupted")]
    CorruptedFile,
}

/// 儲存操作的結果類型，封裝 [`StorageError`]。
pub type Result<T> = std::result::Result<T, StorageError>;

/// 定義儲存系統所需實現的 API，支援檔案與目錄的建立、讀取、寫入及刪除等操作。
pub trait Storage: Send + Sync + fmt::Debug {
    /// 建立指定 key 所對應的目錄樹，若不存在則自動建立。
    ///
    /// # 參數
    ///
    /// - `key`: 目錄路徑，必須符合儲存系統的路徑規範。
    ///
    /// # 回傳
    ///
    /// 回傳 `Ok(())` 表示成功建立目錄，否則回傳錯誤。
    fn create_dir_all(&self, key: &str) -> Result<()>;

    /// 讀取指定 key 所對應檔案的內容。
    ///
    /// # 參數
    ///
    /// - `key`: 檔案路徑，必須符合儲存系統的路徑規範。
    ///
    /// # 回傳
    ///
    /// 成功時回傳檔案內容的位元組向量；若檔案不存在或該 key 為目錄，則回傳錯誤。
    fn read_file(&self, key: &str) -> Result<Vec<u8>>;

    /// 將資料寫入指定 key 所對應的檔案中。
    ///
    /// # 參數
    ///
    /// - `key`: 檔案路徑，必須符合儲存系統的路徑規範。
    /// - `value`: 欲寫入的位元組資料。
    ///
    /// # 回傳
    ///
    /// 成功時回傳 `Ok(())`，否則回傳錯誤。
    fn write_file(&self, key: &str, value: &[u8]) -> Result<()>;

    /// 刪除指定 key 所對應的檔案或目錄。
    ///
    /// # 參數
    ///
    /// - `key`: 檔案或目錄的路徑。
    ///
    /// # 回傳
    ///
    /// 成功時回傳 `Ok(())`，否則回傳錯誤。
    fn remove(&self, key: &str) -> Result<()>;

    /// 檢查指定 key 是否存在於儲存系統中。
    ///
    /// # 參數
    ///
    /// - `key`: 檔案或目錄的路徑。
    ///
    /// # 回傳
    ///
    /// 回傳 `true` 表示存在且未被刪除，否則回傳 `false`。
    fn exists(&self, key: &str) -> Result<bool>;

    /// 判斷指定 key 是否為目錄。
    ///
    /// # 參數
    ///
    /// - `key`: 路徑字串。
    ///
    /// # 回傳
    ///
    /// 回傳 `true` 表示該 key 為目錄且未被刪除，否則回傳 `false`。
    fn is_dir(&self, key: &str) -> Result<bool>;
}

/// 私有工具，提供 key 正規化與驗證等輔助函式。
struct KeyUtils;

impl KeyUtils {
    /// 正規化 key 字串為絕對路徑，並檢查不合法字元與格式。
    ///
    /// # 參數
    ///
    /// - `key`: 原始的 key 字串。
    ///
    /// # 回傳
    ///
    /// 成功時回傳正規化後的 [`PathBuf`]，否則回傳 [`StorageError::InvalidKey`]。
    fn normalize(key: &str) -> Result<PathBuf> {
        if key.is_empty() {
            return Err(StorageError::InvalidKey("Empty key".to_string()));
        }

        if key.contains('\0') || key.contains('\n') || key.contains('\r') {
            return Err(StorageError::InvalidKey(format!(
                "Invalid characters in key: {}",
                key
            )));
        }

        if key.contains("//") {
            return Err(StorageError::InvalidKey(format!(
                "Double slashes not allowed in key: {}",
                key
            )));
        }

        let path = Path::new(key);
        let mut normalized = PathBuf::from("/");

        for component in path.components() {
            match component {
                std::path::Component::RootDir => normalized = PathBuf::from("/"),
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    if normalized.as_os_str() == "/" {
                        return Err(StorageError::InvalidKey(format!(
                            "Cannot use '..' to escape root directory: {}",
                            key
                        )));
                    }
                    normalized.pop();
                }
                std::path::Component::Normal(name) => {
                    if let Some(name_str) = name.to_str() {
                        if name_str.contains('/') || name_str.contains('\\') {
                            return Err(StorageError::InvalidKey(format!(
                                "Invalid path component: {}",
                                name_str
                            )));
                        }
                        normalized.push(name_str);
                    } else {
                        return Err(StorageError::InvalidKey(format!(
                            "Non-UTF8 path component in: {}",
                            key
                        )));
                    }
                }
                _ => return Err(StorageError::InvalidKey(format!("Invalid path: {}", key))),
            }
        }

        Ok(normalized)
    }

    /// 取得指定路徑的父目錄。
    ///
    /// # 參數
    ///
    /// - `path`: 來源路徑。
    ///
    /// # 回傳
    ///
    /// 若存在父目錄，回傳其 [`PathBuf`]，否則回傳 `None`。
    fn parent(path: &Path) -> Option<PathBuf> {
        path.parent().map(|p| p.to_path_buf())
    }

    /// 驗證並轉換目錄 key，確保其格式正確，並以斜線結尾。
    ///
    /// # 參數
    ///
    /// - `key`: 原始目錄 key 字串。
    ///
    /// # 回傳
    ///
    /// 成功時回傳正規化且以斜線結尾的 [`PathBuf`]，否則回傳錯誤。
    fn verify_directory_key(key: &str) -> Result<PathBuf> {
        let path = Self::normalize(key)?;
        if path.to_string_lossy().ends_with('/') {
            Ok(path)
        } else {
            let mut path = path;
            path.push("");
            Ok(path)
        }
    }

    /// 驗證並轉換檔案 key，確保其格式正確且不以斜線結尾。
    ///
    /// # 參數
    ///
    /// - `key`: 原始檔案 key 字串。
    ///
    /// # 回傳
    ///
    /// 成功時回傳正規化後的 [`PathBuf`]，否則回傳錯誤。
    fn verify_file_key(key: &str) -> Result<PathBuf> {
        let path = Self::normalize(key)?;

        if key.ends_with('/') || path.to_string_lossy().ends_with('/') {
            return Err(StorageError::InvalidKey(format!(
                "File key cannot end with '/': {}",
                key
            )));
        }

        Ok(path)
    }
}

/// 基於檔案的儲存實作，將資料存放於單一檔案中，並維護索引以快速查詢。
#[derive(Debug)]
pub struct FileStorage {
    index: Arc<RwLock<StorageIndex>>,
    file: Arc<RwLock<std::fs::File>>,
}

/// 檔案儲存的索引結構，用於儲存各個 entry 的 metadata。
#[derive(Debug)]
struct StorageIndex {
    entries: HashMap<PathBuf, EntryMetadata>,
}

/// Entry 的元資料，包括在檔案中的偏移量、是否為目錄以及是否已刪除。
#[derive(Debug, Clone, Copy)]
struct EntryMetadata {
    offset: u64,
    is_dir: bool,
    is_deleted: bool,
}

impl FileStorage {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = {
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                std::fs::OpenOptions::new()
                    .read(true)
                    .create(true)
                    .append(true)
                    .mode(0o600) // 只有擁有者可讀寫
                    .open(path)?
            }
        };

        let index = Self::build_index(&file)?;

        let storage = Self {
            index: Arc::new(RwLock::new(index)),
            file: Arc::new(RwLock::new(file)),
        };

        // 若索引為空則建立根目錄
        if storage
            .index
            .read()
            .map_err(|_| StorageError::LockPoisoned)?
            .entries
            .is_empty()
        {
            storage.write_entry(Path::new("/"), &[], true)?;
        }

        Ok(storage)
    }

    /// 從檔案中讀取所有 entry，並建構索引。
    ///
    /// # 參數
    ///
    /// - `file`: 已開啟的儲存檔案參考。
    ///
    /// # 回傳
    ///
    /// 成功時回傳 [`StorageIndex`]，否則回傳錯誤。
    fn build_index(file: &std::fs::File) -> Result<StorageIndex> {
        let mut reader = io::BufReader::new(file);
        let mut entries = HashMap::new();
        let mut offset = 0u64;

        loop {
            let entry_offset = offset;

            let buffer = reader.fill_buf()?;
            if buffer.is_empty() {
                break;
            }

            if buffer.len() < 8 {
                break;
            }

            let header: [u8; 8] = buffer[..8].try_into().unwrap();
            reader.consume(8);
            offset += 8;

            let (key_len, flags) = Self::parse_header(&header);

            let mut key_buf = vec![0u8; key_len as usize];
            if let Err(e) = reader.read_exact(&mut key_buf) {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    break;
                } else {
                    return Err(e.into());
                }
            }
            offset += key_len as u64;
            let key = String::from_utf8_lossy(&key_buf);
            let path = KeyUtils::normalize(&key)?;

            let mut size_buf = [0u8; 4];
            if let Err(e) = reader.read_exact(&mut size_buf) {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    break;
                } else {
                    return Err(e.into());
                }
            }
            offset += 4;
            let size = u32::from_le_bytes(size_buf);

            let skipped = io::copy(&mut (&mut reader).take(size as u64), &mut io::sink())?;
            if skipped != size as u64 {
                break;
            }
            offset += size as u64;

            entries.insert(
                path,
                EntryMetadata {
                    offset: entry_offset,
                    is_dir: flags & 1 == 1,
                    is_deleted: flags & 2 == 2,
                },
            );
        }

        Ok(StorageIndex { entries })
    }

    /// 解析 entry header，從前 8 個位元組中取得 key 長度及旗標資訊。
    ///
    /// # 參數
    ///
    /// - `header`: 包含 header 資訊的位元組陣列。
    ///
    /// # 回傳
    ///
    /// 回傳一個元組，第一個元素為 key 長度，第二個元素為旗標。
    fn parse_header(header: &[u8; 8]) -> (u32, u8) {
        let key_len = u32::from_le_bytes(header[0..4].try_into().unwrap());
        let flags = header[4];
        (key_len, flags)
    }

    /// 將一筆 entry 寫入儲存檔案，並更新索引。
    ///
    /// # 參數
    ///
    /// - `key`: 欲寫入 entry 的路徑。
    /// - `value`: entry 的內容。
    /// - `is_dir`: 若為目錄則為 `true`，否則為 `false`。
    ///
    /// # 回傳
    ///
    /// 成功時回傳 `Ok(())`，否則回傳錯誤。
    fn write_entry(&self, key: &Path, value: &[u8], is_dir: bool) -> Result<()> {
        let mut file = self.file.write().map_err(|_| StorageError::LockPoisoned)?;
        let key_str = key.to_string_lossy();
        let key_bytes = key_str.as_bytes();

        let header = Self::create_header(key_bytes.len() as u32, is_dir, false);
        file.write_all(&header)?;

        file.write_all(key_bytes)?;
        let size = value.len() as u32;
        file.write_all(&size.to_le_bytes())?;
        file.write_all(value)?;

        let offset = file.stream_position()? - size as u64 - key_bytes.len() as u64 - 12;
        let mut index = self.index.write().map_err(|_| StorageError::LockPoisoned)?;
        index.entries.insert(
            key.to_path_buf(),
            EntryMetadata {
                offset,
                is_dir,
                is_deleted: false,
            },
        );

        Ok(())
    }

    /// 建立 entry header，內含 key 長度與旗標資訊（是否為目錄及是否已刪除）。
    ///
    /// # 參數
    ///
    /// - `key_len`: key 的長度。
    /// - `is_dir`: 是否為目錄。
    /// - `is_deleted`: 是否已刪除。
    ///
    /// # 回傳
    ///
    /// 回傳固定長度的 8 位元組 header。
    fn create_header(key_len: u32, is_dir: bool, is_deleted: bool) -> [u8; 8] {
        let mut header = [0u8; 8];
        header[0..4].copy_from_slice(&key_len.to_le_bytes());
        header[4] = if is_dir { 1 } else { 0 } | if is_deleted { 2 } else { 0 };
        header
    }
}

impl Storage for FileStorage {
    fn create_dir_all(&self, key: &str) -> Result<()> {
        let path = KeyUtils::verify_directory_key(key)?;

        let mut current = PathBuf::from("/");
        // 逐層檢查並建立目錄
        for component in path.components().skip(1) {
            current.push(component);

            if self.exists(&current.to_string_lossy())? {
                if !self.is_dir(&current.to_string_lossy())? {
                    return Err(StorageError::NotDirectory(
                        current.to_string_lossy().into_owned(),
                    ));
                }
            } else {
                self.write_entry(&current, &[], true)?;
            }
        }

        Ok(())
    }

    fn read_file(&self, key: &str) -> Result<Vec<u8>> {
        let path = KeyUtils::verify_file_key(key)?;
        let index = self.index.read().map_err(|_| StorageError::LockPoisoned)?;

        if let Some(metadata) = index.entries.get(&path) {
            if metadata.is_deleted {
                return Err(StorageError::NotFound(key.to_string()));
            }

            if metadata.is_dir {
                return Err(StorageError::IsDir(key.to_string()));
            }

            let mut file = self.file.write().map_err(|_| StorageError::LockPoisoned)?;
            file.seek(SeekFrom::Start(metadata.offset))?;

            let mut header = [0u8; 8];
            file.read_exact(&mut header)?;
            let key_len = u32::from_le_bytes(header[0..4].try_into().unwrap());
            file.seek(SeekFrom::Current(key_len as i64))?;

            let mut size_buf = [0u8; 4];
            file.read_exact(&mut size_buf)?;
            let size = u32::from_le_bytes(size_buf);

            let mut data = vec![0u8; size as usize];
            file.read_exact(&mut data)?;

            Ok(data)
        } else {
            Err(StorageError::NotFound(key.to_string()))
        }
    }

    fn write_file(&self, key: &str, value: &[u8]) -> Result<()> {
        let path = KeyUtils::verify_file_key(key)?;

        if let Some(parent) = KeyUtils::parent(&path) {
            if !self.exists(&parent.to_string_lossy())? {
                self.create_dir_all(&parent.to_string_lossy())?;
            }
            if !self.is_dir(&parent.to_string_lossy())? {
                return Err(StorageError::NotDirectory(
                    parent.to_string_lossy().into_owned(),
                ));
            }
        }

        self.write_entry(&path, value, false)
    }

    fn remove(&self, key: &str) -> Result<()> {
        let path = KeyUtils::normalize(key)?;
        let mut index = self.index.write().map_err(|_| StorageError::LockPoisoned)?;

        if let Some(metadata) = index.entries.get_mut(&path) {
            metadata.is_deleted = true;

            let mut file = self.file.write().map_err(|_| StorageError::LockPoisoned)?;
            file.seek(SeekFrom::Start(metadata.offset + 4))?;
            file.write_all(&[if metadata.is_dir { 3 } else { 2 }])?;
        }

        Ok(())
    }

    fn exists(&self, key: &str) -> Result<bool> {
        let path = KeyUtils::normalize(key)?;
        let index = self.index.read().map_err(|_| StorageError::LockPoisoned)?;
        Ok(index.entries.get(&path).is_some_and(|m| !m.is_deleted))
    }

    fn is_dir(&self, key: &str) -> Result<bool> {
        let path = KeyUtils::normalize(key)?;
        let index = self.index.read().map_err(|_| StorageError::LockPoisoned)?;
        Ok(index
            .entries
            .get(&path)
            .is_some_and(|m| m.is_dir && !m.is_deleted))
    }
}

/// 基於記憶體的儲存實作，資料與目錄結構皆保存在記憶體中。
#[derive(Debug)]
pub struct MemStorage {
    data: Arc<RwLock<HashMap<PathBuf, Vec<u8>>>>,
    dirs: Arc<RwLock<HashMap<PathBuf, ()>>>,
}

impl Default for MemStorage {
    /// 透過 [`MemStorage::new`] 建立預設實例。
    fn default() -> Self {
        Self::new()
    }
}

impl MemStorage {
    /// 建立一個新的記憶體儲存實例，並初始化根目錄 `/`。
    pub fn new() -> Self {
        let mut dirs = HashMap::new();
        dirs.insert(PathBuf::from("/"), ());

        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
            dirs: Arc::new(RwLock::new(dirs)),
        }
    }
}

impl Storage for MemStorage {
    fn create_dir_all(&self, key: &str) -> Result<()> {
        let path = KeyUtils::verify_directory_key(key)?;
        let mut current = PathBuf::from("/");

        let mut dirs = self.dirs.write().map_err(|_| StorageError::LockPoisoned)?;
        // 逐層建立目錄，若同時存在檔案則回傳錯誤
        for component in path.components().skip(1) {
            current.push(component);

            if self
                .data
                .read()
                .map_err(|_| StorageError::LockPoisoned)?
                .contains_key(&current)
            {
                return Err(StorageError::NotDirectory(
                    current.to_string_lossy().into_owned(),
                ));
            }

            dirs.entry(current.clone()).or_insert(());
        }

        Ok(())
    }

    fn read_file(&self, key: &str) -> Result<Vec<u8>> {
        let path = KeyUtils::verify_file_key(key)?;
        let data = self.data.read().map_err(|_| StorageError::LockPoisoned)?;
        if let Some(value) = data.get(&path) {
            Ok(value.clone())
        } else {
            Err(StorageError::NotFound(key.to_string()))
        }
    }

    fn write_file(&self, key: &str, value: &[u8]) -> Result<()> {
        let path = KeyUtils::verify_file_key(key)?;

        if let Some(parent) = KeyUtils::parent(&path) {
            if !self.exists(&parent.to_string_lossy())? {
                self.create_dir_all(&parent.to_string_lossy())?;
            }
            if !self.is_dir(&parent.to_string_lossy())? {
                return Err(StorageError::NotDirectory(
                    parent.to_string_lossy().into_owned(),
                ));
            }
        }

        self.data
            .write()
            .map_err(|_| StorageError::LockPoisoned)?
            .insert(path, value.to_vec());

        Ok(())
    }

    fn remove(&self, key: &str) -> Result<()> {
        let path = KeyUtils::normalize(key)?;
        self.data
            .write()
            .map_err(|_| StorageError::LockPoisoned)?
            .remove(&path);
        self.dirs
            .write()
            .map_err(|_| StorageError::LockPoisoned)?
            .remove(&path);
        Ok(())
    }

    fn exists(&self, key: &str) -> Result<bool> {
        let path = KeyUtils::normalize(key)?;
        Ok(self
            .data
            .read()
            .map_err(|_| StorageError::LockPoisoned)?
            .contains_key(&path)
            || self
                .dirs
                .read()
                .map_err(|_| StorageError::LockPoisoned)?
                .contains_key(&path))
    }

    fn is_dir(&self, key: &str) -> Result<bool> {
        let path = KeyUtils::normalize(key)?;
        Ok(self
            .dirs
            .read()
            .map_err(|_| StorageError::LockPoisoned)?
            .contains_key(&path))
    }
}
