//! # ACME Certificate Automation Library
//!
//! 本庫提供與 ACME 服務（例如 Let's Encrypt）交互的功能，主要涵蓋以下兩大模組：
//!
//! - **account**: 負責 ACME 帳戶的創建與管理，包含 JWS 簽名、密鑰對生成、非重放（nonce）管理以及與 ACME 目錄服務的交互。
//! - **order**: 用於證書訂單的處理，從新建訂單、挑戰驗證、最終訂單確認到證書下載，並支持 DNS 驗證（目前支援 Cloudflare）。
//!
//! ## 特性
//!
//! - 自動管理帳戶的密鑰對與持久化存儲
//! - 支持 ACME 新帳戶創建流程
//! - 提供訂單創建、挑戰驗證、CSR 生成與簽名、證書下載等全流程操作
//! - 支持 Cloudflare DNS API，實現 DNS TXT 記錄的創建與驗證
//!
//! ## 使用方式
//!
//! 使用者可以通過兩大主要 API 來完成證書申請流程：
//!
//! 1. **帳戶管理**（`account` 模組）：  
//!    使用 [`Account::new`] 或 [`AccountBuilder`] 建立 ACME 帳戶，該過程會自動處理密鑰對生成、目錄交互與帳戶註冊，並將相關資料持久化存儲。
//!
//! 2. **訂單管理**（`order` 模組）：  
//!    使用 [`Order::new`] 創建新訂單，然後透過 [`Order::finalize`]、[`Order::validate_challenge`] 與 [`Order::download_certificate`] 進行訂單的最終確認和證書下載。  
//!    如需使用 DNS 驗證，可搭配 [`Order::dns_provider`] 配置 Cloudflare 提供的 DNS TXT 記錄。
//!
//! ## 示例
//!
//! 以下是一個簡單的示例，展示如何使用該庫完成 ACME 帳戶與訂單的基本操作：
//!
//! ```rust
//! use acme_lib::{account::Account, order::{Order, DnsProvider}};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // 1. 創建 ACME 帳戶
//!     let mut account = Account::new("user@example.com")?;
//!
//!     // 2. 為指定域名建立訂單
//!     let domain = "example.com";
//!     let mut order = Order::new(&mut account, domain)?;
//!
//!     // 3. 如使用 DNS 驗證，先使用 Cloudflare 配置 DNS
//!     order = order.dns_provider(DnsProvider::Cloudflare, "your-cloudflare-api-token")?;
//!
//!     // 4. 驗證挑戰（假設使用 DNS-01 挑戰）
//!     order = order.validate_challenge(&account, order::ChallengeType::Dns01)?;
//!
//!     // 5. 當訂單處於 Ready 狀態，提交 CSR 以最終確認訂單
//!     order.finalize(&account)?;
//!
//!     // 6. 下載證書
//!     order.download_certificate(&account)?;
//!
//!     Ok(())
//! }
//! ```
//!
//! 更多詳細 API 說明請參考各個模組的文檔。

pub mod account;
pub mod base64;
pub mod certificate;
pub mod challenge;
pub mod csr;
pub mod directory;
pub mod jwk;
pub mod jws;
pub mod key_pair;
pub mod nonce;
pub mod order;
pub mod payload;
pub mod protection;
pub mod signature;
pub mod storage;
