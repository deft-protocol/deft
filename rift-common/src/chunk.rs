use std::io::{Read, Seek, SeekFrom};
use crate::{sha256_hex, DEFAULT_CHUNK_SIZE};

#[derive(Debug, Clone)]
pub struct ChunkMetadata {
    pub index: u64,
    pub offset: u64,
    pub size: u32,
    pub hash: String,
}

#[derive(Debug, Clone)]
pub struct FileChunks {
    pub total_size: u64,
    pub chunk_size: u32,
    pub chunks: Vec<ChunkMetadata>,
    pub file_hash: String,
}

impl FileChunks {
    pub fn chunk_count(&self) -> u64 {
        self.chunks.len() as u64
    }
}

pub struct Chunker {
    chunk_size: u32,
}

impl Default for Chunker {
    fn default() -> Self {
        Self::new(DEFAULT_CHUNK_SIZE)
    }
}

impl Chunker {
    pub fn new(chunk_size: u32) -> Self {
        Self { chunk_size }
    }

    pub fn compute_chunks<R: Read + Seek>(&self, reader: &mut R) -> std::io::Result<FileChunks> {
        let start = reader.stream_position()?;
        reader.seek(SeekFrom::End(0))?;
        let total_size = reader.stream_position()?;
        reader.seek(SeekFrom::Start(start))?;

        let mut chunks = Vec::new();
        let mut file_hasher = sha2::Sha256::new();
        let mut buffer = vec![0u8; self.chunk_size as usize];
        let mut offset = 0u64;
        let mut index = 0u64;

        use sha2::Digest;

        loop {
            let bytes_read = read_exact_or_eof(reader, &mut buffer)?;
            if bytes_read == 0 {
                break;
            }

            let chunk_data = &buffer[..bytes_read];
            file_hasher.update(chunk_data);

            let chunk_hash = sha256_hex(chunk_data);
            chunks.push(ChunkMetadata {
                index,
                offset,
                size: bytes_read as u32,
                hash: chunk_hash,
            });

            offset += bytes_read as u64;
            index += 1;
        }

        let file_hash = hex_encode(&file_hasher.finalize());

        Ok(FileChunks {
            total_size,
            chunk_size: self.chunk_size,
            chunks,
            file_hash,
        })
    }

    pub fn read_chunk<R: Read + Seek>(
        &self,
        reader: &mut R,
        chunk_index: u64,
    ) -> std::io::Result<Vec<u8>> {
        let offset = chunk_index * self.chunk_size as u64;
        reader.seek(SeekFrom::Start(offset))?;

        let mut buffer = vec![0u8; self.chunk_size as usize];
        let bytes_read = read_exact_or_eof(reader, &mut buffer)?;
        buffer.truncate(bytes_read);

        Ok(buffer)
    }
}

fn read_exact_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total_read = 0;
    while total_read < buf.len() {
        match reader.read(&mut buf[total_read..]) {
            Ok(0) => break,
            Ok(n) => total_read += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total_read)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_chunker_small_file() {
        let data = b"Hello, RIFT Protocol!";
        let mut cursor = Cursor::new(data.as_slice());

        let chunker = Chunker::new(1024);
        let result = chunker.compute_chunks(&mut cursor).unwrap();

        assert_eq!(result.total_size, data.len() as u64);
        assert_eq!(result.chunks.len(), 1);
        assert_eq!(result.chunks[0].size, data.len() as u32);
    }

    #[test]
    fn test_chunker_multiple_chunks() {
        let data = vec![0u8; 1000];
        let mut cursor = Cursor::new(data.as_slice());

        let chunker = Chunker::new(256);
        let result = chunker.compute_chunks(&mut cursor).unwrap();

        assert_eq!(result.total_size, 1000);
        assert_eq!(result.chunks.len(), 4);
        assert_eq!(result.chunks[0].size, 256);
        assert_eq!(result.chunks[1].size, 256);
        assert_eq!(result.chunks[2].size, 256);
        assert_eq!(result.chunks[3].size, 232);
    }

    #[test]
    fn test_read_chunk() {
        let data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let mut cursor = Cursor::new(data.as_slice());

        let chunker = Chunker::new(256);

        let chunk0 = chunker.read_chunk(&mut cursor, 0).unwrap();
        assert_eq!(chunk0.len(), 256);
        assert_eq!(chunk0[0], 0);

        let chunk1 = chunker.read_chunk(&mut cursor, 1).unwrap();
        assert_eq!(chunk1.len(), 256);
        assert_eq!(chunk1[0], 0); // 256 % 256

        let chunk3 = chunker.read_chunk(&mut cursor, 3).unwrap();
        assert_eq!(chunk3.len(), 232);
    }
}
