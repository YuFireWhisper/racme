use std::{
    collections::HashMap,
    fmt,
    io::{self, BufRead, Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
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
    fn create_dir_all(&self, key: &str) -> Result<()>;

    /// 讀取指定 key 所對應檔案的內容。
    fn read_file(&self, key: &str) -> Result<Vec<u8>>;

    /// 將資料寫入指定 key 所對應的檔案中。
    fn write_file(&self, key: &str, value: &[u8]) -> Result<()>;

    /// 刪除指定 key 所對應的檔案或目錄。
    fn remove(&self, key: &str) -> Result<()>;

    /// 檢查指定 key 是否存在於儲存系統中。
    fn exists(&self, key: &str) -> Result<bool>;

    /// 判斷指定 key 是否為目錄。
    fn is_dir(&self, key: &str) -> Result<bool>;

    /// 預設方法：確保給定路徑的父目錄存在且為目錄，否則嘗試建立。
    fn ensure_parent_directory(&self, path: &Path) -> Result<()> {
        if let Some(parent) = KeyUtils::parent(path) {
            let parent_key = parent.to_string_lossy();
            if !self.exists(&parent_key)? {
                self.create_dir_all(&parent_key)?;
            } else if !self.is_dir(&parent_key)? {
                return Err(StorageError::NotDirectory(parent_key.into_owned()));
            }
        }
        Ok(())
    }
}

/// 私有工具，提供 key 正規化與驗證等輔助函式。
struct KeyUtils;

impl KeyUtils {
    /// 正規化 key 字串為絕對路徑，並檢查不合法字元與格式。
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
                Component::RootDir => normalized = PathBuf::from("/"),
                Component::CurDir => {}
                Component::ParentDir => {
                    if normalized.as_os_str() == "/" {
                        return Err(StorageError::InvalidKey(format!(
                            "Cannot use '..' to escape root directory: {}",
                            key
                        )));
                    }
                    normalized.pop();
                }
                Component::Normal(name) => {
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
    fn parent(path: &Path) -> Option<PathBuf> {
        path.parent().map(|p| p.to_path_buf())
    }

    /// 驗證並轉換目錄 key，確保格式正確並以斜線結尾。
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

    /// 驗證並轉換檔案 key，確保格式正確且不以斜線結尾。
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
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .mode(0o600)
                    .open(&path)?
            }
        };

        let index = Self::build_index(&file)?;

        let needs_cleanup = index.entries.values().any(|m| m.is_deleted);

        let storage = Self {
            index: Arc::new(RwLock::new(index)),
            file: Arc::new(RwLock::new(file)),
        };

        if storage
            .index
            .read()
            .map_err(|_| StorageError::LockPoisoned)?
            .entries
            .is_empty()
        {
            storage.write_entry(Path::new("/"), &[], true)?;
        }

        if needs_cleanup {
            storage.cleanup(&path)?;
        }

        Ok(storage)
    }

    fn cleanup<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let temp_path = {
            let mut temp = PathBuf::from(path.as_ref());
            temp.set_extension("temp");
            temp
        };

        let mut temp_file = {
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&temp_path)?
            }
        };

        let new_entries = {
            let index = self.index.read().map_err(|_| StorageError::LockPoisoned)?;
            let mut file = self.file.write().map_err(|_| StorageError::LockPoisoned)?;

            let mut new_entries = HashMap::new();
            let mut current_offset = 0u64;

            for (path, metadata) in index.entries.iter().filter(|(_, m)| !m.is_deleted) {
                file.seek(SeekFrom::Start(metadata.offset))?;

                let mut header = [0u8; 8];
                file.read_exact(&mut header)?;
                let (key_len, _) = Self::parse_header(&header);

                let mut key_buf = vec![0u8; key_len as usize];
                file.read_exact(&mut key_buf)?;

                let mut size_buf = [0u8; 4];
                file.read_exact(&mut size_buf)?;
                let size = u32::from_le_bytes(size_buf);

                let mut data = vec![0u8; size as usize];
                file.read_exact(&mut data)?;

                let key_str = path.to_string_lossy();
                let key_bytes = key_str.as_bytes();
                let new_header =
                    Self::create_header(key_bytes.len() as u32, metadata.is_dir, false);

                temp_file.write_all(&new_header)?;
                temp_file.write_all(key_bytes)?;
                temp_file.write_all(&size.to_le_bytes())?;
                temp_file.write_all(&data)?;

                new_entries.insert(
                    path.clone(),
                    EntryMetadata {
                        offset: current_offset,
                        is_dir: metadata.is_dir,
                        is_deleted: false,
                    },
                );

                current_offset += new_header.len() as u64
                    + key_bytes.len() as u64
                    + size_buf.len() as u64
                    + data.len() as u64;
            }
            new_entries
        };

        temp_file.sync_all()?;

        std::fs::rename(&temp_path, &path)?;

        let new_file = {
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                std::fs::OpenOptions::new()
                    .read(true)
                    .create(true)
                    .write(true)
                    .truncate(false)
                    .mode(0o600)
                    .open(&path)?
            }
        };

        *self.index.write().map_err(|_| StorageError::LockPoisoned)? = StorageIndex {
            entries: new_entries,
        };
        *self.file.write().map_err(|_| StorageError::LockPoisoned)? = new_file;

        Ok(())
    }

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

    /// 解析 entry header，取得 key 長度與旗標資訊。
    fn parse_header(header: &[u8; 8]) -> (u32, u8) {
        let key_len = u32::from_le_bytes(header[0..4].try_into().unwrap());
        let flags = header[4];
        (key_len, flags)
    }

    /// 將一筆 entry 寫入儲存檔案，並更新索引。
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
    fn create_header(key_len: u32, is_dir: bool, is_deleted: bool) -> [u8; 8] {
        let mut header = [0u8; 8];
        header[0..4].copy_from_slice(&key_len.to_le_bytes());
        header[4] = (if is_dir { 1 } else { 0 }) | (if is_deleted { 2 } else { 0 });
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
            let current_str = current.to_string_lossy();
            if self.exists(&current_str)? {
                if !self.is_dir(&current_str)? {
                    return Err(StorageError::NotDirectory(current_str.into_owned()));
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
            // 注意：由於 std::fs::File 的 seek 與 read_exact 需要可變引用，
            // 此處仍需獲取 write 鎖；未來可考慮拆分讀寫句柄來提升並發效能。
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
        // 確保父目錄存在且合法
        self.ensure_parent_directory(&path)?;
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
        // 確保父目錄存在且合法
        self.ensure_parent_directory(&path)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_mem_storage_basic_operations() -> Result<()> {
        let storage = MemStorage::new();
        storage.create_dir_all("dir1/")?;
        assert!(storage.is_dir("dir1/")?);

        storage.write_file("dir1/file1.txt", b"Hello, MemStorage")?;
        let content = storage.read_file("dir1/file1.txt")?;
        assert_eq!(content, b"Hello, MemStorage");

        assert!(storage.exists("dir1/file1.txt")?);
        storage.remove("dir1/file1.txt")?;
        assert!(!storage.exists("dir1/file1.txt")?);
        match storage.read_file("dir1/file1.txt") {
            Err(StorageError::NotFound(_)) => {}
            _ => panic!("預期 NotFound 錯誤"),
        }
        Ok(())
    }

    #[test]
    fn test_mem_storage_invalid_file_key() {
        let storage = MemStorage::new();
        let result = storage.write_file("invalid/", b"data");
        assert!(matches!(result, Err(StorageError::InvalidKey(_))));
    }

    #[test]
    fn test_automatic_parent_directory_creation_mem() -> Result<()> {
        let storage = MemStorage::new();
        storage.write_file("auto_dir/subdir/file.txt", b"Auto Parent")?;
        assert!(storage.exists("auto_dir/subdir/file.txt")?);
        Ok(())
    }

    #[test]
    fn test_file_storage_basic_operations() -> Result<()> {
        let temp_dir = tempdir()?;
        let file_path = temp_dir.path().join("storage.data");
        let storage = FileStorage::open(&file_path)?;

        storage.create_dir_all("dir2/")?;
        assert!(storage.is_dir("dir2/")?);

        storage.write_file("dir2/file2.txt", b"Hello, FileStorage")?;
        let content = storage.read_file("dir2/file2.txt")?;
        assert_eq!(content, b"Hello, FileStorage");

        assert!(storage.exists("dir2/file2.txt")?);
        storage.remove("dir2/file2.txt")?;
        assert!(!storage.exists("dir2/file2.txt")?);
        match storage.read_file("dir2/file2.txt") {
            Err(StorageError::NotFound(_)) => {}
            _ => panic!("預期 NotFound 錯誤"),
        }
        Ok(())
    }

    #[test]
    fn test_file_storage_invalid_file_key() -> Result<()> {
        let temp_dir = tempdir()?;
        let file_path = temp_dir.path().join("storage.data");
        let storage = FileStorage::open(&file_path)?;
        let result = storage.write_file("invalid/", b"data");
        assert!(matches!(result, Err(StorageError::InvalidKey(_))));
        Ok(())
    }

    #[test]
    fn test_automatic_parent_directory_creation_file() -> Result<()> {
        let temp_dir = tempdir()?;
        let file_path = temp_dir.path().join("storage.data");
        let storage = FileStorage::open(&file_path)?;
        storage.write_file("auto_dir/subdir/file.txt", b"Auto Parent")?;
        assert!(storage.exists("auto_dir/subdir/file.txt")?);
        Ok(())
    }

    #[test]
    fn test_storage_cleanup() -> Result<()> {
        let temp_dir = tempdir()?;
        let file_path = temp_dir.path().join("storage.data");

        {
            let storage = FileStorage::open(&file_path)?;
            storage.write_file("test1.txt", b"Test 1")?;
            storage.write_file("test2.txt", b"Test 2")?;
            storage.write_file("test3.txt", b"Test 3")?;

            storage.remove("test2.txt")?;
        }

        let original_size = std::fs::metadata(&file_path)?.len();

        {
            let storage = FileStorage::open(&file_path)?;

            assert!(storage.exists("test1.txt")?);
            assert!(!storage.exists("test2.txt")?);
            assert!(storage.exists("test3.txt")?);

            assert_eq!(storage.read_file("test1.txt")?, b"Test 1");
            assert_eq!(storage.read_file("test3.txt")?, b"Test 3");
        }

        let cleaned_size = std::fs::metadata(&file_path)?.len();

        assert!(
            cleaned_size < original_size,
            "Cleaned file size ({}) should be smaller than original size ({})",
            cleaned_size,
            original_size
        );

        Ok(())
    }

    #[test]
    fn test_storage_cleanup_with_concurrent_operations() -> Result<()> {
        let temp_dir = tempdir()?;
        let file_path = temp_dir.path().join("storage.data");

        {
            let storage = FileStorage::open(&file_path)?;
            for i in 0..10 {
                storage.write_file(
                    &format!("file{}.txt", i),
                    format!("content {}", i).as_bytes(),
                )?;
            }

            for i in (0..10).step_by(2) {
                storage.remove(&format!("file{}.txt", i))?;
            }
        }

        let storage = FileStorage::open(&file_path)?;

        for i in (1..10).step_by(2) {
            assert!(
                storage.exists(&format!("file{}.txt", i))?,
                "file{}.txt should exist",
                i
            );
            assert_eq!(
                storage.read_file(&format!("file{}.txt", i))?,
                format!("content {}", i).as_bytes(),
                "content of file{}.txt should match",
                i
            );
        }

        for i in (0..10).step_by(2) {
            assert!(
                !storage.exists(&format!("file{}.txt", i))?,
                "file{}.txt should not exist",
                i
            );
        }

        storage.write_file("new_file.txt", b"new content")?;
        assert_eq!(storage.read_file("new_file.txt")?, b"new content");

        Ok(())
    }
}
