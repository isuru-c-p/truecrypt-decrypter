use std::io::Cursor;
use std::io::Error;
use std::io::prelude::*;
use binrw::BinRead;

#[derive(Debug)]
pub struct TrueCryptContainer
{
    file: std::fs::File,
    header: TrueCryptHeader,
}

#[derive(Debug, BinRead)]
#[br(big)]
#[allow(dead_code)]
pub struct TrueCryptHeader
{
    version: u16,
    required_program_version: u16,
    key_area_crc: u32,
    creation_time: u64,
    modification_time: u64,
    hidden_volume_size: u64,
    volume_size: u64,
    enc_area_start: u64,
    enc_area_length: u64,
    flags: u32,
    sector_size: u32,
    reserved: [u8; 120],
    header_crc: u32,
    key_area: [u8; 256]
}

fn generate_header_key(password: &[u8], salt: &[u8; 64]) -> Result<[u8; 64], Error> {
    let mut key = [0u8; 64];
    openssl::pkcs5::pbkdf2_hmac(
        password,
        salt,
        2000,
        openssl::hash::MessageDigest::ripemd160(),
        &mut key
    )?;
    Ok(key)
}

const TRUECRYPT_MAGIC : [u8; 4] = [84, 82, 85, 69];
const DEFAULT_SECTOR_SIZE : u32 = 512;
const MIN_SECTOR_SIZE : u32 = 512;
const MAX_SECTOR_SIZE : u32 = 4096;
const ENCRYPTION_DATA_UNIT_SIZE : u32 = 512;

impl TrueCryptContainer
{
    pub fn open(path: &str, password: &str) -> Result<TrueCryptContainer, Error>  {
        let mut file = std::fs::OpenOptions::new().read(true).write(false).open(path)?; 

        // Read encrypted header
        let mut enc_header = [0u8; 512];
        file.seek(std::io::SeekFrom::Start(0))?;
        file.read(&mut enc_header)?;

        // Read clear salt
        let mut salt = [0u8; 64];
        salt.copy_from_slice(&enc_header[0..64]);

        // Generate header key using password and salt
        let header_key = generate_header_key(&password.as_bytes(), &salt)?;

        // Decrypt header
        let cipher = openssl::symm::Cipher::aes_256_xts();
        let iv = [0u8; 16];
        let decrypted_header = openssl::symm::decrypt(
            cipher,
            &header_key,
            Some(&iv),
            &enc_header[64..]
        )?;

        // Check for correct decryption
        if &decrypted_header[0..4] != TRUECRYPT_MAGIC {
            return Err(
                std::io::Error::new(std::io::ErrorKind::PermissionDenied,
                "Incorrect password")
            );
        }

        let mut header = TrueCryptHeader::read(&mut Cursor::new(&decrypted_header[4..])).unwrap();

        // Version specific handling

        if header.version < 5 {
            // Fixed sector size
            header.sector_size = DEFAULT_SECTOR_SIZE;
        }

        // Validation
        if header.sector_size < MIN_SECTOR_SIZE || header.sector_size > MAX_SECTOR_SIZE || (header.sector_size % ENCRYPTION_DATA_UNIT_SIZE) != 0 {
            return Err(
                std::io::Error::new(std::io::ErrorKind::InvalidData,
                "Incorrect sector size in header")
            );
        }

        // Seek to volume start
        file.seek(std::io::SeekFrom::Start(header.enc_area_start))?;

        Ok(TrueCryptContainer {
            file: file,
            header: header,
        })
    }

    pub fn decrypt(&mut self, output : &mut dyn std::io::Write) -> Result<usize, Error> {

        // Need to perform decryption aligned to sector size
        let sector_size = self.header.sector_size as usize;
        self.file.seek(std::io::SeekFrom::Start(self.header.enc_area_start))?;

        let mut enc_buffer = Vec::<u8>::with_capacity(sector_size);
        enc_buffer.resize(sector_size, 0u8);
        let cipher = openssl::symm::Cipher::aes_256_xts();
        let volume_key : &[u8; 64] = (&self.header.key_area[0..64]).try_into().unwrap();
        let mut iv : u128 = 256;

        let mut bytes_written : usize = 0;
        let enc_area_length = self.header.enc_area_length as usize;
        while bytes_written < enc_area_length {
            let bytes_read = self.file.read(&mut enc_buffer)?;
            if bytes_read == 0 {
                break;
            }
            let iv_buf = iv.to_le_bytes();
            let decrypted_buffer = openssl::symm::decrypt(
                cipher,
                volume_key,
                Some(&iv_buf),
                &enc_buffer
            )?;

            // Write decrypted data to output
            output.write(&decrypted_buffer[0..bytes_read])?;
            bytes_written += bytes_read;
            iv += 1;
        }

        return Ok(bytes_written);
    }
}
