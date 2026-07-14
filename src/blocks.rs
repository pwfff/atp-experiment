//! File → block layout shared by sender and receiver.
//!
//! Each block is an independent RaptorQ object: both sides construct the
//! codec config with `ObjectTransmissionInformation::with_defaults(len,
//! symbol_size)`, so nothing about the code needs to travel on the wire
//! beyond the manifest's `block_size`/`symbol_size`/`file_size`.

use raptorq::ObjectTransmissionInformation;

/// Static description of how a file splits into blocks.
#[derive(Debug, Clone, Copy)]
pub struct Layout {
    pub file_size: u64,
    pub block_size: u32,
    pub symbol_size: u16,
    pub num_blocks: u32,
}

impl Layout {
    pub fn new(file_size: u64, block_size: u32, symbol_size: u16) -> Self {
        assert!(file_size > 0, "empty transfers are rejected earlier");
        assert!(block_size > 0 && symbol_size > 0);
        let num_blocks = file_size.div_ceil(block_size as u64);
        let num_blocks = u32::try_from(num_blocks).expect("block count fits u32");
        Layout { file_size, block_size, symbol_size, num_blocks }
    }

    /// Byte range of block `index` within the file.
    pub fn range(&self, index: u32) -> std::ops::Range<u64> {
        debug_assert!(index < self.num_blocks);
        let start = index as u64 * self.block_size as u64;
        let end = (start + self.block_size as u64).min(self.file_size);
        start..end
    }

    /// Length in bytes of block `index` (only the last block may be short).
    pub fn block_len(&self, index: u32) -> u64 {
        let r = self.range(index);
        r.end - r.start
    }

    /// Number of source symbols in block `index`.
    pub fn source_symbols(&self, index: u32) -> u32 {
        let len = self.block_len(index);
        len.div_ceil(self.symbol_size as u64) as u32
    }

    /// RaptorQ config for block `index`; identical on both ends.
    pub fn oti(&self, index: u32) -> ObjectTransmissionInformation {
        ObjectTransmissionInformation::with_defaults(self.block_len(index), self.symbol_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_math() {
        let l = Layout::new(2_500_000, 1 << 20, 1200);
        assert_eq!(l.num_blocks, 3);
        assert_eq!(l.block_len(0), 1 << 20);
        assert_eq!(l.block_len(2), 2_500_000 - 2 * (1 << 20));
        assert_eq!(l.range(1), (1 << 20)..(2 << 20));
        assert_eq!(l.source_symbols(0), (1u64 << 20).div_ceil(1200) as u32);
    }

    #[test]
    fn single_short_block() {
        let l = Layout::new(10, 1 << 20, 1200);
        assert_eq!(l.num_blocks, 1);
        assert_eq!(l.block_len(0), 10);
        assert_eq!(l.source_symbols(0), 1);
    }
}
