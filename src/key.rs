use std::fmt;
use std::iter::FromIterator;
use std::iter::IntoIterator;
use std::num::NonZeroUsize;
use std::ops::Add;
use std::ops::BitAnd;
use std::ops::BitOr;
use std::ops::BitXor;
use std::ops::Index;
use std::ops::Not;
use std::slice;

use rand::Rng;

pub struct Key {
    data: Vec<u8>,
}

impl Key {
    /// Creates a [`Key`](Key) instance from [`Vec`](Vec) of [`u8`](u8)s.
    ///
    /// # Panics
    ///
    /// - if length of given vector is zero
    pub fn new(data: Vec<u8>) -> Self {
        // Key length must not be zero
        assert!(data.len() > 0, "Length of the key must be non-zero");

        // Create a new instance
        Self { data: data }
    }

    /// Generates [`Key`](Key) instance with specified length, consisting of random
    /// bytes.
    ///
    /// # Parameters
    ///
    /// - `key_len`: the length of the key
    /// - `rng`: random number generator
    pub fn random<R: Rng + ?Sized>(key_len: NonZeroUsize, rng: &mut R) -> Self {

        // Create a vector with given capacity and fill the vector with zeros:
        let mut data: Vec<u8> = Vec::with_capacity(key_len.into());
        data.fill(0);

        // Create a mutable slice
        let slice = &mut data[..];

        // Use random number generator (RNG) to fill our vector through the slice
        rng.fill_bytes(slice);

        // Create an instance
        Self { data }
    }

    /// Returns length of the key in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns length of the key in bits.
    pub fn len_bits(&self) -> usize {
        self.len() * 8
    }

    /// Returns an iterator that does not consume the [`Key`](Key) instance itself.
    pub fn iter(&self) -> slice::Iter<'_, u8> {
        (&self).into_iter()
    }
}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        // Lengths must be the same...
        self.len() == other.len() &&
        // ...and all bytes must be equal
        self.into_iter()
            // zip with the other key's iterator
            .zip(other.into_iter())
            // look for bytes that do not match
            .filter(|(a, b)| a != b)
            // we should find no bytes that do not match if the keys are the same
            .next().is_none()
    }
}

impl Eq for Key {}

impl FromIterator<u8> for Key {
    /// Constructs the key from an iterable object of [`u8`]s. If iterable object
    /// gives no element, this method will panic.
    fn from_iter<T: IntoIterator<Item = u8>>(iter: T) -> Self {

        // Collect everything into a `Vec`:
        let data: Vec<u8> = iter.into_iter().collect();

        // Create a new instance
        Self::new(data)
    }
}

impl IntoIterator for Key {
    type Item = u8;
    type IntoIter = std::vec::IntoIter<u8>;

    /// Returns an iterator over bytes of the key. This will consume the [`Key`](Key)
    /// instance.
    ///
    /// # Returns
    ///
    /// An iterator over [`u8`](u8); each [`u8`](u8) represents a single byte from
    /// the key.
    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}

impl<'a> IntoIterator for &'a Key {
    type Item = &'a u8;
    type IntoIter = slice::Iter<'a, u8>;

    /// Returns an iterator over bytes of the key. This will not consume the [`Key`]
    /// instance since we iterate over `&u8`
    ///
    /// # Returns
    ///
    /// An iterator over `&u8`; each [`u8`](u8) represents a single byte from the
    /// key.
    fn into_iter(self) -> Self::IntoIter {
        self.data.iter()
    }
}

impl Clone for Key {
    fn clone(&self) -> Self {

        // Clone our data
        let data_clone = self.data.clone();

        // Construct a new instance from cloned data
        Self { data: data_clone }
    }
}

impl<'a> Add for &'a Key {
    ///
    /// The output of addition (`+`) operator is a new [`Key`](Key) instance.
    ///
    type Output = Key;

    ///
    /// Using binary `+` operator you concatenate both keys into one key. Lengths of
    /// the [`Key`](Key) instances do not need to be same.
    ///
    fn add(self, other: Self) -> Self::Output {
        self.data
            .iter()
            .chain(other.data.iter())
            .map(|&v| v) // <== Dereference
            .collect()
    }
}

impl<I> Index<I> for Key
where
    I: slice::SliceIndex<[u8]>,
{
    ///
    /// The output of index (`[]`) operator is a byte at given position.
    ///
    type Output = I::Output;

    ///
    /// Returns the byte given by the index. If index is out of range, method will
    /// panic.
    ///
    fn index(&self, index: I) -> &I::Output {
        &self.data[index]
    }
}

// Bitwise operator implementation
//===================================================================================

impl<'a> Not for &'a Key {
    ///
    /// The output type of the unary `!` operator is a new [`Key`] instance.
    ///
    type Output = Key;

    ///
    /// Performs unary `!` operation, e.g. bitwise negation. Each bit gets flipped
    /// from `0` to `1` and the othwer way around.
    ///
    fn not(self) -> Self::Output {

        // Create an iterator that negates each byte of the key:
        let new_values = self.data.iter().map(|b| !b);

        // Create a new instance from the iterator
        Self::Output::from_iter(new_values)
    }
}

impl<'a> BitAnd for &'a Key {
    ///
    /// The output type of the binary `&` operator is a new [`Key`] instance.
    ///
    type Output = Key;

    ///
    /// Performs binary `&` operation, e.g. bitwise `AND`. Each bit from first
    /// [`Key`] instance is `AND`ed with bit from the second [`Key`] instance at the
    /// same index. Length of both keys must be the same, otherwise using this
    /// operator will panic.
    ///
    fn bitand(self, other: Self) -> Self::Output {
        // The length must be the same
        assert_eq!(
            self.len(),
            other.len(),
            "Key length must be the same for the `&` operation"
        );
        // Create an iterator of new values
        let new_values = self.data.iter().zip(other.data.iter()).map(|(a, b)| a & b);
        // Create a new value from the iterator
        Self::Output::from_iter(new_values)
    }
}

impl<'a> BitOr for &'a Key {
    ///
    /// The output type of the binary `|` operator is a new [`Key`] instance.
    ///
    type Output = Key;

    ///
    /// Performs binary `|` operation, e.g. bitwise `OR`. Each bit from first
    /// [`Key`] instance is `OR`ed with bit from the second [`Key`] instance at the
    /// same index. Length of both keys must be the same, otherwise using this
    /// operator will panic.
    ///
    fn bitor(self, other: Self) -> Self::Output {
        // The length must be the same
        assert_eq!(
            self.len(),
            other.len(),
            "Key length must be the same for the `|` operation"
        );
        // Create an iterator of new values
        let new_values = self.data.iter().zip(other.data.iter()).map(|(a, b)| a | b);
        // Create a new value from the iterator
        Self::Output::from_iter(new_values)
    }
}

impl<'a> BitXor for &'a Key {
    ///
    /// The output type of the binary `^` operator is a new [`Key`] instance.
    ///
    type Output = Key;

    ///
    /// Performs binary `^` operation, e.g. bitwise `XOR`. Each bit from first
    /// [`Key`] instance is `XOR`ed with bit from the second [`Key`] instance at the
    /// same index. Length of both keys must be the same, otherwise using this
    /// operator will panic.
    ///
    fn bitxor(self, other: Self) -> Self::Output {
        // The length must be the same
        assert_eq!(
            self.len(),
            other.len(),
            "Key length must be the same for the `^` operation"
        );
        // Create an iterator of new values
        let new_values = self.data.iter().zip(other.data.iter()).map(|(a, b)| a ^ b);
        // Create a new value from the iterator
        Self::Output::from_iter(new_values)
    }
}

// Formatting implementation
//===================================================================================

impl fmt::LowerHex for Key {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Format each byte as a hexadecimal number and append it to the `Formatter`:
        for byte in &self.data {
            formatter.write_fmt(format_args!("{:02x}", byte))?;
        }

        // Everything went fine:
        Ok(())
    }
}

impl fmt::UpperHex for Key {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Format each byte as a hexadecimal number and append it to the `Formatter`:
        for byte in &self.data {
            formatter.write_fmt(format_args!("{:02X}", byte))?;
        }

        // Everything went fine:
        Ok(())
    }
}

impl fmt::Binary for Key {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Format each byte as a hexadecimal number and append it to the `Formatter`:
        for byte in &self.data {
            formatter.write_fmt(format_args!("{:02b}", byte))?;
        }

        // Everything went fine:
        Ok(())
    }
}

impl fmt::Display for Key {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Use `LowerHex` trait implementation
        fmt::LowerHex::fmt(&self, formatter)
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Use `LowerHex` trait implementation
        fmt::LowerHex::fmt(&self, formatter)
    }
}

impl fmt::Pointer for Key {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // use `as` to convert to a `*const T`, which implements Pointer, which we can use
        let ptr = self as *const Self;
        fmt::Pointer::fmt(&ptr, formatter)
    }
}
