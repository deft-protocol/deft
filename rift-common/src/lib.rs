mod chunk;
mod hash;

pub use chunk::*;
pub use hash::*;

pub const DEFAULT_CHUNK_SIZE: u32 = 262144; // 256 KB
