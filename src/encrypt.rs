use std::convert::Infallible;
use std::error::Error;
use std::iter::FromIterator;
use std::iter::IntoIterator;

/// Represents an algorithm that can encrypt data represented as an iterable object
/// over bytes. [`try_encrypt`] method is used for the encryption. Note that the
/// encryption might not be successful.
/// 
/// [`try_encrypt`]: TryEncrypt::try_encrypt
pub trait TryEncrypt {

    /// The type when encryption will not be successful.
    type ErrorType: Error;

    /// This method is used for encryption. Encryption may or may not be successful.
    /// The implementor's documentation should state when encryption will result in
    /// [`Err`]. This method should not panic.
    ///
    /// # Parameters
    ///
    /// - `data_to_encrypt`: data to encrypt as an iterable object iterating over
    ///     [`u8`]
    /// 
    /// # Returns
    /// 
    /// - [`Ok`] if encryption was successful
    /// - [`Err`] if encryption was not successful
    /// 
    /// [`u8`]: u8
    /// [`Ok`]: Ok
    /// [`Err`]: Err
    fn try_encrypt<D, E>(
        &self,
        data_to_encrypt: D,
    ) -> Result<E, Self::ErrorType> where
        D:           IntoIterator<Item = u8>,
        D::IntoIter: ExactSizeIterator,
        E:           FromIterator<u8>;
}

/// Represents an algorithm that can encrypt data to encrypt represented as an
/// iterable over bytes. [`encrypt`](Encrypt::encrypt) method is used for the
/// encryption.
/// 
/// Also implementing [`Encrypt`](Encrypt) there is no need to implement
/// [`TryEncrypt`](TryEncrypt) &ndash; there is a default blanket implemetation.
pub trait Encrypt {

    /// This method is used for encryption. It should never panic.
    ///
    /// # Parameters
    ///
    /// - `data_to_encrypt`: data to encrypt as an iterable object iterating over
    ///     [`u8`](u8)
    fn encrypt<D, E>(
        &self,
        data_to_encrypt: D
    ) -> E where
        D:           IntoIterator<Item = u8>,
        D::IntoIter: ExactSizeIterator,
        E:           FromIterator<u8>;
}

/// Blanket implementation of TryEncrypt when Encrypt is implemented
impl<T> TryEncrypt for T
where T: Encrypt {

    /// Error can never happen, so [`Infallible`] enum is used. Consult
    /// [`Infallible`]'s documentation for more information.
    /// 
    /// [`Infallible`]: std::convert::Infallible
    type ErrorType = Infallible;

    /// This method is used for encryption. Encryption should be always successful,
    /// e.g. this method should never panic.
    ///
    /// # Parameters
    ///
    /// - `data_to_encrypt`: data to encrypt as an iterable object iterating over
    ///     [`u8`](u8) that should be encrypted
    fn try_encrypt<E, D>(
        &self,
        data_to_encrypt: E,
    ) -> Result<D, Infallible> where
        E:           IntoIterator<Item = u8>,
        E::IntoIter: ExactSizeIterator,
        D:           FromIterator<u8>
    {
        // Use [`Encrypt`]'s implementation:
        Ok(self.encrypt(data_to_encrypt))
    }
}