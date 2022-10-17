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

use sha2::Digest;
use std::fmt::Debug;
use std::fs;
use std::io;
use std::path::Path;

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
pub fn try_digest<D: TrySha256Digest>(input: D) -> Result<String, D::Error> {
    input.digest()
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

pub trait TrySha256Digest {
    type Error: Debug;
    fn digest(self) -> Result<String, Self::Error>;
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

impl TrySha256Digest for &Path {
    type Error = io::Error;
    fn digest(self) -> Result<String, Self::Error> {
        let bytes = fs::read(self)?;
        Ok(__digest__(&bytes))
    }
}

fn __digest__(data: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(data))
}
