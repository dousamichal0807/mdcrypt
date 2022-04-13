/// Module for any algorithm that transforms a sequence of bytes into another
/// sequence of bytes, so that the algorithm increases security of transmission
/// over network. This includes, but does not limit to, data encryption, error
/// correction code and other.
pub mod algorithms;

mod decrypt;        pub use decrypt::*;
mod encrypt;        pub use encrypt::*;
mod key;            pub use key::*;