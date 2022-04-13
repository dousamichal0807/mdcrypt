use std::iter::FromIterator;
use std::iter::IntoIterator;

use crate::decrypt::Decrypt;
use crate::encrypt::Encrypt;
use crate::Key;

pub struct Vigener {
    key: Key
}

impl Vigener {

    /// Creates a new [`Vineger`](Vineger) instance from given key. The key is used
    /// then when encrypting and decrypting
    /// 
    /// # Parameters
    /// 
    /// - `key`: [`Key`](Key) instance to encrypt/decrypt with
    /// 
    /// # Returns
    /// 
    /// Returns a new instance with given key.
    pub fn new(key: Key) -> Self {
        Self { key }
    }

    /// This method is used to get a key associated with the [`Vineger`] instance.
    /// 
    /// # Returns
    /// 
    /// The key as an immutable borrow of [`Key`] instance that is used to encrypt
    /// and decrypt.
    /// 
    /// [`Vineger`]: Vineger
    /// [`Key`]: Key
    pub fn key(&self) -> &Key {
        &self.key
    }
}

impl Encrypt for Vigener {
    
    fn encrypt<D, E>(&self, data_to_encrypt: D) -> E
    where
        D:           IntoIterator<Item = u8>,
        D::IntoIter: ExactSizeIterator,
        E:           FromIterator<u8>
    {
        // Convert encrypted data into iterator
        data_to_encrypt.into_iter()
            // Zip with key iterator that repeats
            .zip(self.key.iter().cycle())
            // Add the byte to encrypt and the byte from the key. Overflow can
            // happen, but we do not mind about it:
            .map(|(byte, &mask)| byte.wrapping_add(mask))
            // Collect into instance of `D` 
            .collect()
    }
}

impl Decrypt for Vigener {

    fn decrypt<E, D>(&self, encrypted_data: E) -> D
    where
        E:           IntoIterator<Item = u8>,
        E::IntoIter: ExactSizeIterator,
        D:           FromIterator<u8>
    {
        // Convert encrypted data into iterator
        encrypted_data.into_iter()
            // Zip with key iterator that repeats
            .zip(self.key.iter().cycle())
            // Add the encrypted byte and the byte from the key. Overflow can happen, but we do not
            // mind about it.
            .map(|(encrypted_byte, &mask)| encrypted_byte.wrapping_sub(mask))
            // Collect into an instance of `D`
            .collect()
    }
}