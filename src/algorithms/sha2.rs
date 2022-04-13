use std::iter::ExactSizeIterator;
use std::iter::FromIterator;
use std::iter::IntoIterator;
use std::marker::PhantomData;

use crate::Encrypt;

pub struct Sha2<T>(PhantomData<T>)
where T: Default + sha2::Digest;

impl<T> Default for Sha2<T>
where T: Default + sha2::Digest,
{
    fn default() -> Self {
        Self (PhantomData)
    }
}

impl<T> Encrypt for Sha2<T>
where T: Default + sha2::Digest,
{
    fn encrypt<D, E>(&self, data_to_encrypt: D) -> E
    where
        D: IntoIterator<Item = u8>,
        D::IntoIter: ExactSizeIterator,
        E: FromIterator<u8>,
    {
        let vec: Vec<u8> = data_to_encrypt.into_iter().collect();
        let mut encr = T::default();
        encr.update(vec);
        return encr.finalize()[..].iter().map(|&b| b).collect();
    }
}

/// SHA-224 hasher implementing [`Encrypt`] trait from this crate.
/// 
/// [`Encrypt`]: crate::crypt::Encrypt
pub type Sha224 = Sha2<sha2::Sha224>;

/// SHA-256 hasher implementing [`Encrypt`] trait from this crate.
/// 
/// [`Encrypt`]: crate::crypt::Encrypt
pub type Sha256 = Sha2<sha2::Sha256>;

/// SHA-384 hasher implementing [`Encrypt`] trait from this crate.
/// 
/// [`Encrypt`]: crate::crypt::Encrypt
pub type Sha384 = Sha2<sha2::Sha384>;

/// SHA-512 hasher implementing [`Encrypt`] trait from this crate.
/// 
/// [`Encrypt`]: crate::crypt::Encrypt
pub type Sha512 = Sha2<sha2::Sha512>;

/// SHA-512/224 hasher implementing [`Encrypt`] trait from this crate.
/// 
/// [`Encrypt`]: crate::crypt::Encrypt
pub type Sha512_224 = Sha2<sha2::Sha512_224>;

/// SHA-512/256 hasher implementing [`Encrypt`] trait from this crate.
/// 
/// [`Encrypt`]: crate::crypt::Encrypt
pub type Sha512_256 = Sha2<sha2::Sha512_256>;