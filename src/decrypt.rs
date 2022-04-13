use std::convert::Infallible;
use std::error::Error;
use std::iter::FromIterator;
use std::iter::IntoIterator;

/// Represents an algorithm that can decrypt encrypted data represented as an
/// iterable over bytes. [`try_decrypt`] method is used for the decryption. Note that
/// the decryption might not be successful.
/// 
/// [`try_decrypt`]: TryDecrypt::try_decrypt
pub trait TryDecrypt {

    /// The type when decryption will not be successful.
    type ErrorType: Error;

    /// This method is used for decryption. Encryption may or may not be successful.
    /// The implementor's documentation should state when decryption will result in
    /// [`Err`]. This method should not panic.
    ///
    /// # Parameters
    ///
    /// - `encrypted_data`: encrypted data as an iterable object iterating over
    ///     [`u8`] that should be decrypted
    /// 
    /// # Returns
    /// 
    /// - [`Ok`] if encryption was successful
    /// - [`Err`] if encryption was not successful
    /// 
    /// [`u8`]: u8
    /// [`Ok`]: Ok
    /// [`Err`]: Err
    fn try_decrypt<E, D>(
        &self,
        encrypted_data: E,
    ) -> Result<D, Self::ErrorType> where
        E:           IntoIterator<Item = u8>,
        E::IntoIter: ExactSizeIterator,
        D:           FromIterator<u8>;
}

/// Represents an algorithm that can decrypt encrypted data represented as an
/// iterable over bytes. [`decrypt`](Decrypt::decrypt) method is used for the
/// decryption.
/// 
/// Also implementing [`Decrypt`](Decrypt) there is no need to implement
/// [`TryDecrypt`](TryDecrypt) &ndash; there is a default blanket implemetation.
pub trait Decrypt {

    /// This method is used for decryption. It should never panic.
    ///
    /// # Parameters
    ///
    /// - `encrypted_data`: encrypted data as an iterable object iterating over
    ///     [`u8`](u8) that should be decrypted
    fn decrypt<E, D>(
        &self,
        encrypted_data: E
    ) -> D where
        E:           IntoIterator<Item = u8>,
        E::IntoIter: ExactSizeIterator,
        D:           FromIterator<u8>;
}

/// Blanket implementation of TryDecrypt when Decrypt is implemented
impl<T> TryDecrypt for T
where T: Decrypt {

    /// Error can never happen, so [`Infallible`] enum is used. Consult
    /// [`Infallible`]'s documentation for more information.
    /// 
    /// [`Infallible`]: std::convert::Infallible
    type ErrorType = Infallible;

    /// This method is used for decryption. Decryption should be always successful,
    /// e.g. this method should never panic.
    ///
    /// # Parameters
    ///
    /// - `encrypted_data`: encrypted data as an iterable object iterating over
    ///     [`u8`](u8) that should be decrypted
    fn try_decrypt<E, D>(
        &self,
        encrypted_data: E,
    ) -> Result<D, Infallible> where
        E:           IntoIterator<Item = u8>,
        E::IntoIter: ExactSizeIterator,
        D:           FromIterator<u8>
    {
        // Use [`Decrypt`]'s implementation:
        Ok(self.decrypt(encrypted_data))
    }
}