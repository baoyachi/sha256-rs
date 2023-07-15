//! sha256 crypto digest util
//!
//! ```rust
//!
//! use sha256::{digest, try_digest};
//!
//! //sha256 digest String
//! let input = String::from("hello");
//! let val = digest(input);
//! assert_eq!(val,"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
//!
//! //sha256 digest &str
//! let input = "hello";
//! let val = digest(input);
//! assert_eq!(val,"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
//!
//! //sha256 digest bytes
//! let input = b"hello";
//! let val = digest(input);
//! assert_eq!(val,"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
//!
//! //sha256 digest file
//! use std::path::Path;
//! let input = Path::new("./foo.file");
//! let val = try_digest(input).unwrap();
//! assert_eq!(val,"433855b7d2b96c23a6f60e70c655eb4305e8806b682a9596a200642f947259b1");
//!
//! ```

#[cfg(feature = "native_openssl")]
use crate::openssl_sha256::OpenSslSha256;
use bytes::BytesMut;
use sha2::digest::Output;
use sha2::{Digest, Sha256};
use std::fmt::Debug;
use std::fs;
use std::io;
use std::io::{BufReader, Read};
use std::path::Path;
use tokio::io::AsyncReadExt;

/// sha256 digest string
///
/// # Examples
///
/// ```rust
/// use sha256::digest;
/// let input = "hello";
/// let val = digest(input);
/// assert_eq!(val,"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
/// ```
///
pub fn digest<D: Sha256Digest>(input: D) -> String {
    input.digest()
}

/// sha256 digest file
///
/// # Examples
///
/// ```rust
/// use sha256::try_digest;
/// use std::path::Path;
/// let input = Path::new("./foo.file");
/// let val = try_digest(input).unwrap();
/// assert_eq!(val,"433855b7d2b96c23a6f60e70c655eb4305e8806b682a9596a200642f947259b1")
/// ```
#[deprecated(
    since = "1.2.0",
    note = "Use new function `try_async_digest()` instead"
)]
pub fn try_digest<D: TrySha256Digest>(input: D) -> Result<String, D::Error> {
    input.digest()
}

/// sha256 digest file
///
/// # Examples
///
/// ```rust
/// use sha256::{try_async_digest};
/// use std::path::Path;
/// let input = Path::new("./foo.file");
/// tokio_test::block_on(async{ ///
/// let val = try_async_digest(input).await.unwrap();
/// assert_eq!(val,"433855b7d2b96c23a6f60e70c655eb4305e8806b682a9596a200642f947259b1")
/// });
///
/// ```
pub async fn try_async_digest<D: TrySha256Digest>(input: D) -> Result<String, D::Error> {
    input.async_digest().await
}

/// sha256 digest file
///
/// # Examples
///
/// ```rust
/// use sha256::{try_async_openssl_digest};
/// use std::path::Path;
/// let input = Path::new("./foo.file");
/// tokio_test::block_on(async{ ///
/// let val = try_async_openssl_digest(input).await.unwrap();
/// assert_eq!(val,"433855b7d2b96c23a6f60e70c655eb4305e8806b682a9596a200642f947259b1")
/// });
/// ```
#[cfg(feature = "native_openssl")]
pub async fn try_async_openssl_digest<D: TrySha256Digest>(input: D) -> Result<String, D::Error> {
    input.async_openssl_digest().await
}

/// sha256 digest bytes
///
/// # Examples
///
/// ```rust
/// use sha256::digest_bytes;
/// let input = b"hello";
/// let val = digest_bytes(input);
/// assert_eq!(val,"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
/// ```
///
#[deprecated(since = "1.1.0", note = "Use new function `digest()` instead")]
pub fn digest_bytes(input: &[u8]) -> String {
    __digest__(input)
}

/// sha256 digest file
///
/// # Examples
///
/// ```rust
/// use sha256::digest_file;
/// use std::path::Path;
/// let input = Path::new("./foo.file");
/// let val = digest_file(input).unwrap();
/// assert_eq!(val,"433855b7d2b96c23a6f60e70c655eb4305e8806b682a9596a200642f947259b1")
/// ```
#[deprecated(since = "1.1.0", note = "Use new function `try_digest()` instead")]
pub fn digest_file<P: AsRef<Path>>(path: P) -> Result<String, io::Error> {
    let bytes = fs::read(path)?;
    Ok(__digest__(&bytes))
}

pub trait Sha256Digest {
    fn digest(self) -> String;
}

#[async_trait::async_trait]
pub trait TrySha256Digest {
    type Error: Debug;

    fn digest(self) -> Result<String, Self::Error>;

    async fn async_digest(self) -> Result<String, Self::Error>;

    #[cfg(feature = "native_openssl")]
    async fn async_openssl_digest(self) -> Result<String, Self::Error>;
}

impl<const N: usize> Sha256Digest for &[u8; N] {
    fn digest(self) -> String {
        __digest__(self)
    }
}

impl Sha256Digest for &[u8] {
    fn digest(self) -> String {
        __digest__(self)
    }
}

impl Sha256Digest for &Vec<u8> {
    fn digest(self) -> String {
        __digest__(self)
    }
}

impl Sha256Digest for Vec<u8> {
    fn digest(self) -> String {
        __digest__(&self)
    }
}

impl Sha256Digest for String {
    fn digest(self) -> String {
        __digest__(self.as_bytes())
    }
}

impl Sha256Digest for &str {
    fn digest(self) -> String {
        __digest__(self.as_bytes())
    }
}

impl Sha256Digest for &String {
    fn digest(self) -> String {
        __digest__(self.as_bytes())
    }
}

#[async_trait::async_trait]
impl<P> TrySha256Digest for P
where
    P: AsRef<Path> + Send,
{
    type Error = io::Error;

    fn digest(self) -> Result<String, Self::Error> {
        let f = fs::File::open(self)?;
        let reader = BufReader::new(f);
        let sha = Sha256::new();
        calc(reader, sha)
    }

    async fn async_digest(self) -> Result<String, Self::Error> {
        let f = tokio::fs::File::open(self).await?;
        let reader = tokio::io::BufReader::new(f);
        let sha = Sha256::new();
        async_calc(reader, sha).await
    }

    #[cfg(feature = "native_openssl")]
    async fn async_openssl_digest(self) -> Result<String, Self::Error> {
        let f = tokio::fs::File::open(self).await?;
        let reader = tokio::io::BufReader::new(f);
        let sha = OpenSslSha256::new();
        async_calc(reader, sha).await
    }
}

fn __digest__(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

trait CalculatorInput {
    fn read_inner(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
}

#[async_trait::async_trait]
trait AsyncCalculatorInput {
    async fn read_inner(&mut self, buf: &mut BytesMut) -> std::io::Result<usize>;
}

impl<T> CalculatorInput for T
where
    T: Read,
{
    fn read_inner(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read(buf)
    }
}

#[async_trait::async_trait]
impl<R> AsyncCalculatorInput for tokio::io::BufReader<R>
where
    R: tokio::io::AsyncRead + Unpin + Send,
{
    async fn read_inner(&mut self, buf: &mut BytesMut) -> io::Result<usize> {
        self.read_buf(buf).await
    }
}

trait CalculatorSelector {
    type FinishType: AsRef<[u8]>;
    fn update_inner(&mut self, data: &[u8]);
    fn finish_inner(self) -> Self::FinishType;
}

impl CalculatorSelector for Sha256 {
    type FinishType = Output<Sha256>;

    fn update_inner(&mut self, data: &[u8]) {
        self.update(data)
    }

    fn finish_inner(self) -> Self::FinishType {
        self.finalize()
    }
}

fn calc<I, S>(mut input: I, mut selector: S) -> io::Result<String>
where
    I: CalculatorInput,
    S: CalculatorSelector,
{
    let mut buf = [0u8; 1024];
    loop {
        let len = input.read_inner(&mut buf)?;
        if len == 0 {
            break;
        }
        selector.update_inner(&buf[0..len]);
    }
    let hash = selector.finish_inner();
    Ok(hex::encode(hash))
}

async fn async_calc<I, S>(mut input: I, mut selector: S) -> io::Result<String>
where
    I: AsyncCalculatorInput,
    S: CalculatorSelector,
{
    let mut buf = BytesMut::with_capacity(1024);
    loop {
        let len = input.read_inner(&mut buf).await?;
        if len == 0 {
            break;
        }
        selector.update_inner(&buf[0..len]);
    }
    let hash = selector.finish_inner();
    Ok(hex::encode(hash))
}

#[cfg(feature = "native_openssl")]
mod openssl_sha256 {
    use crate::CalculatorSelector;

    pub type OpenSslSha256 = openssl::sha::Sha256;

    impl CalculatorSelector for OpenSslSha256 {
        type FinishType = [u8; 32];

        fn update_inner(&mut self, data: &[u8]) {
            self.update(data)
        }

        fn finish_inner(self) -> Self::FinishType {
            self.finish()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "native_openssl")]
    #[test]
    fn test_openssl() {
        let input = Path::new("./foo.file");
        let f = fs::File::open(input).unwrap();
        let reader = BufReader::new(f);
        let sha = openssl::sha::Sha256::new();
        assert_eq!(
            "433855b7d2b96c23a6f60e70c655eb4305e8806b682a9596a200642f947259b1",
            calc(reader, sha).unwrap()
        );
    }

    #[test]
    fn test_sha256() {
        let input = Path::new("./foo.file");
        let f = fs::File::open(input).unwrap();
        let reader = BufReader::new(f);
        let sha = Sha256::new();
        assert_eq!(
            "433855b7d2b96c23a6f60e70c655eb4305e8806b682a9596a200642f947259b1",
            calc(reader, sha).unwrap()
        );
    }

    #[cfg(feature = "native_openssl")]
    #[tokio::test]
    async fn test_async_openssl() {
        let input = Path::new("./foo.file");
        let f = tokio::fs::File::open(input).await.unwrap();
        let reader = tokio::io::BufReader::new(f);
        let sha = openssl::sha::Sha256::new();
        assert_eq!(
            "433855b7d2b96c23a6f60e70c655eb4305e8806b682a9596a200642f947259b1",
            async_calc(reader, sha).await.unwrap()
        );
    }

    #[cfg(feature = "native_openssl")]
    #[tokio::test]
    async fn test_async() {
        let input = Path::new("./foo.file");
        let f = tokio::fs::File::open(input).await.unwrap();
        let reader = tokio::io::BufReader::new(f);
        let sha = Sha256::new();
        assert_eq!(
            "433855b7d2b96c23a6f60e70c655eb4305e8806b682a9596a200642f947259b1",
            async_calc(reader, sha).await.unwrap()
        );
    }

    #[cfg(feature = "native_openssl")]
    #[tokio::test]
    async fn test_try_async_openssl_digest() {
        let hash = try_async_openssl_digest("./foo.file").await.unwrap();
        assert_eq!(
            "433855b7d2b96c23a6f60e70c655eb4305e8806b682a9596a200642f947259b1",
            hash
        );
    }

    #[tokio::test]
    async fn test_try_async_digest() {
        let hash = try_async_digest("./foo.file").await.unwrap();
        assert_eq!(
            "433855b7d2b96c23a6f60e70c655eb4305e8806b682a9596a200642f947259b1",
            hash
        );
    }
}
