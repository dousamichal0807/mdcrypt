use std::io;
use std::iter::ExactSizeIterator;
use std::iter::FromIterator;
use std::iter::IntoIterator;
use std::iter::repeat;

use bit_vec::BitVec;

use crate::encrypt::TryEncrypt;

/// A struct that implements Hamming's error correction code (ECC), which puts data
/// into blocks. This code can detect up to 2 errors and correct 1 error in a single
/// block. If there are more than 2 errors in a single block, ECC might not detect
/// any mistake at all and will consider that block is correct. That!s why it is
/// important to choose value for block size that fits best for your needs. Larger
/// block means less ratio of redundancy over data, but is more vulnerable as there
/// will be higher probability of more than 2 mistakes per block.
/// 
/// # ECC Implementation
/// 
/// For composing data into blocks using Hamming Code, this struct implements
/// [`TryEncrypt`] trait. Composing data using this implementation can fail as
/// *n*=`size_field_bits` bits indicate the size of original data in bytes and the
/// input can be larger than 2<sup>*n*</sup> &ndash; 1. See
/// [`size_field_bits()`] method for more information.
/// 
/// For decomposing data into blocks using Hamming Code, this struct implements
/// [`TryDecrypt`] trait. Decomposing data can also fail, because there may be two
/// errors in a single block. Then Hamming's ECC knows that there is an error, but it
/// cannot determine where those errors are.
/// 
/// [`TryEncrypt`]: crate::crypt::TryEncrypt
/// [`TryDecrypt`]: crate::crypt::TryEncrypt
/// [`size_field_bits()`]: Hamming::size_field_bits
pub struct HammingECC {
    blk_log_size: u8,
    size_field_bits: u8,
}

impl HammingECC {

    /// Creates a new [`HammingECC`](HammingECC) instance
    /// 
    /// # Parameters
    /// 
    ///  -  `blk_log_size`: size of a block expressed by its base-2 logarithm, e.g. number 3 for
    ///     8 bits, number 4 for 16 bits, number 5 for 32 bits and so on.
    ///  -  `size_field_bits`: how many bits should be reserved for information about data length
    ///     in bytes
    ///
    /// # Return value
    ///
    ///  -  [`Option::Some`] if both parateters have valid value, e.g. when
    ///     `blk_log_size >= 3 && size_field_bits >= 2`,
    ///  -  [`Option::None`] otherwise
    pub fn new(
        blk_log_size: u8,
        size_field_bits: u8
    ) -> Option<Self> {
        // If all parateters are in specified range, we can create a new instance:
        match blk_log_size >= 3 && size_field_bits >= 2 {
            true  => Option::Some(Self { blk_log_size, size_field_bits }),
            false => Option::None
        }
    }
}

impl TryEncrypt for HammingECC {

    /// Error type to be returned when data size exceeds value
    /// `u16::MAX * 8`.
    type ErrorType = io::Error;

    /// 
    fn try_encrypt<D, E>(
        &self,
        data_to_encrypt: D
    ) -> Result<E, Self::ErrorType> where
        D:           IntoIterator<Item = u8>,
        D::IntoIter: ExactSizeIterator,
        E:           FromIterator<u8>{
        
        // Turning data into an iterator:
        let data_byte_iter = data_to_encrypt.into_iter();
        // Size of data in bytes:
        let data_byte_len = data_byte_iter.len();
        // If size of message in bytes exceeds maximum value of unsigned 16-bit
        // integer, we return an error:
        if data_byte_len >= (1 << self.size_field_bits) {
            // Return error
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Expected at most {} bytes to encrypt but {} bytes were given",
                    (1 << self.size_field_bits) - 1,
                    data_byte_len
                )
            ))
        }
        // Size of data in bits:
        let data_bit_len = data_byte_len * 8;
        // Total number of bits in the block:
        let blk_bits_total = 1usize << self.blk_log_size;
        // Number of error-correction bits in the block:
        let blk_bits_ecc = 1usize + self.blk_log_size as usize;
        // Number of bits in the block that carry data:
        let blk_bits_data = blk_bits_total - blk_bits_ecc;
        // Number of blocks needed calculated without need of floats and rounding up:
        // let blk_count = ceil((data_size_bits as f64) / (message_bits_per_block as f64))
        let blk_count = (data_bit_len + self.size_field_bits as usize + blk_bits_data - 1) / blk_bits_data;
        // Vector of blocks
        let mut blocks = repeat(BitVec::with_capacity(blk_bits_total))
            .take(blk_count)
            .collect::<Vec<BitVec>>();
        // Iterator over bits of size field:
        let sz_field_bit_iter = (0..self.size_field_bits).into_iter().rev()
            .map(|i| (data_byte_len & (1 << i)) != 0);
        // Iterator over bits from the data. Map each byte into 8 boolean values:
        let data_bit_iter = data_byte_iter.flat_map(|byte| {
            // Create an vector of booleans representing bits. Compute each bit. The
            // least significant bit must be on the last position and the most
            // significant bit on the first position in the vector. Using bit shift
            // operator we get these bits in reversed order than we want. To correct
            // this, we reverse the bits in the byte. For each bit in the reversed
            // byte compute the mask and assign into vector. In the end of processing
            // the byte, turn vector into iterator:
            let mut vec = Vec::with_capacity(8);
            let reversed_byte = byte.reverse_bits();
            for i in 0..8 {
                let mask = 1 << i;
                vec.push((reversed_byte & mask) != 0);
            }
            vec.into_iter()
        });
        // Iterator over full data to be encoded (including first bits indicating
        // length of message).
        let mut encode_bit_iter = sz_field_bit_iter.chain(data_bit_iter);
        // Do for each block
        for block in blocks.iter_mut() {
            // Iterator over bits for the block. Take next n=`blk_bits_data` bits.
            let mut blk_data_iter = encode_bit_iter.by_ref().take(blk_bits_data);
            // Put up a block:
            for bit_idx in 0..blk_bits_total {
                // Push:
                block.push(
                    // If bit index is 0 or a power of two, that will be a bit for
                    // error correction. Put false now.
                    if bit_idx.count_ones() <= 1 { false }
                    // Otherwise we can put a next bit. If we run out of bits in the
                    // last block, we push zeros (false):
                    else { blk_data_iter.next().unwrap_or(false) }
                );
            }
            // Now we set error correction codes. We will set bit at position 0 in
            // the end:
            for i in 0..self.blk_log_size {
                let mask = 1 << i;
                let ecc_bit = (0..blk_bits_total).into_iter()
                    .filter(|b| (b & mask) == mask)
                    .map(|b| block.get(b).unwrap())
                    .reduce(|parity, bit| parity ^ bit)
                    .unwrap();
                block.set(mask, ecc_bit);
            }
            // 
            block.set(0, block.iter().reduce(|parity, bit| parity ^ bit).unwrap())
        }

        // Create a bit vector that can hold all our data:
        let mut result = BitVec::with_capacity(16 + blk_bits_total * blk_count);
        // Now we zip blocks so the blocks take turns after each bit, e.g. previous
        // bit is from previous block and next bit is from next block. This prevents
        // the data to be corrupted by the hacker just by changing a number of
        // consecutive bits.
        for bit_idx in 0..blk_bits_total {
            for block in &blocks {
                result.push(block.get(bit_idx).unwrap());
            }
        }
        // Convert bitvector into iterator over u8 and `collect()` it:
        Ok(result.to_bytes().into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn into_ok() {
        let test_cases = vec![
            (
                HammingECC::new(4, 3),
                vec![0b10010110, 0b00110110],
                vec![0b10001000, 0b00100111, 0b10000111, 0b00101000]
            ), (
                HammingECC::new(4, 4),
                vec![0b01011010, 0b10000001],
                vec![0b01001000, 0b00011000, 0b01001000, 0b10110010]
            ), (
                HammingECC::new(3, 4),
                vec![0b01110010, 0b01101000],
                vec![0b10101000, 0b11101110, 0b00011110, 0b00101011, 0b11001000]
            ), (
                HammingECC::new(4, 3),
                vec![],
                vec![0b00000000, 0b00000000]
            ), (
                HammingECC::new(3, 5),
                vec![],
                vec![0b00000000, 0b00000000]
            )
        ];

        for (instance, input, expected_output) in test_cases {
            let hamming = instance.unwrap();
            let actual_output: Vec<u8> = hamming.try_encrypt(input).unwrap();
            assert_eq!(actual_output, expected_output)
        }
    }
}