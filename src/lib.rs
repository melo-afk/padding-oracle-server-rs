// well. There are new aes & cbc release candidates that would fix
// the deprecated warning but I didnt get them to work :(
#![allow(deprecated)]
use aes::cipher::{
    BlockDecryptMut, BlockEncryptMut, KeyIvInit,
    block_padding::{Padding, Pkcs7},
    consts::U16,
    generic_array::GenericArray,
};
use anyhow::Context;
use base64::{Engine as _, engine::general_purpose};
use log::{debug, info};
use std::{
    io::{Read, Write},
    net::TcpStream,
};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

pub fn encode_b64(to_encode: &Vec<u8>) -> String {
    general_purpose::STANDARD.encode(to_encode)
}

fn to_blocks(data: Vec<u8>) -> Vec<GenericArray<u8, U16>> {
    assert!(
        data.len().is_multiple_of(16),
        "data length must be a multiple of 16"
    );

    data.chunks(16)
        .map(GenericArray::clone_from_slice)
        .collect()
}

fn join_blocks(blocks: &[GenericArray<u8, U16>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(blocks.len() * 16);
    for block in blocks {
        out.extend_from_slice(block);
    }
    out
}

/// be a good padding oracle and return whether padding is valid or not
fn oracle(iv_bytes: &[u8], block_bytes: &[u8], key: &GenericArray<u8, U16>) -> bool {
    let mut block: GenericArray<u8, U16> = GenericArray::clone_from_slice(block_bytes);
    let iv: GenericArray<u8, U16> = GenericArray::clone_from_slice(iv_bytes);

    Aes128CbcDec::new(key, &iv).decrypt_block_mut(&mut block);
    if Pkcs7::unpad(&block).is_ok() {
        debug!("valid Q: {}", hex::encode(iv_bytes));
        return true;
    }
    false
}

pub fn encrypt(plaintext: Vec<u8>, key_s: &[u8; 16], iv_s: &[u8; 16], ambig: bool) -> Vec<u8> {
    let key: GenericArray<u8, U16> = GenericArray::clone_from_slice(key_s);
    let iv: GenericArray<u8, U16> = if ambig {
        GenericArray::clone_from_slice(&[0u8; 16])
    } else {
        GenericArray::clone_from_slice(iv_s)
    };

    let pt_len = plaintext.len();

    let padded_size = pt_len.div_ceil(16) * 16;
    let mut empty = padded_size - pt_len;
    let mut buf = vec![0u8; padded_size];
    buf[..pt_len].copy_from_slice(&plaintext);

    let mut blocks = to_blocks(buf);

    if empty == 0 || empty == 1 && ambig {
        // add block with only padding (and maybe ambiguous padding)
        let mut empty_block = GenericArray::clone_from_slice(&[0u8; 16]);
        if ambig {
            empty_block[14] = 0x02;
            empty = 15;
        }
        Pkcs7::pad(&mut empty_block, empty);
        blocks.push(empty_block);
    } else {
        // add also some padding
        let mut last_block = blocks.pop().unwrap();
        if ambig {
            last_block[14] = 0x02;
            empty = 1;
        }
        Pkcs7::pad(&mut last_block, 16 - empty);
        blocks.push(last_block);
    }
    let plain = join_blocks(&blocks);
    println!("--- Used IV--- ");
    println!("b64: {}", encode_b64(&iv.to_vec()));
    println!("hex: {}", hex::encode(iv));
    println!("\n--- Padded Plaintext --- ");
    println!("UTF8: {:?}", String::from_utf8_lossy(&plain));
    println!("b64 : {}", encode_b64(&plain));
    println!("hex : {}", hex::encode(plain));

    Aes128CbcEnc::new(&key, &iv).encrypt_blocks_mut(&mut blocks);

    let ciphertext = join_blocks(&blocks);
    println!("\n--- Ciphertext --- ");
    println!("b64: {}", encode_b64(&ciphertext));
    println!("hex: {}\n", hex::encode(&ciphertext));
    ciphertext.to_vec()
}

pub fn handle_connection(mut stream: TcpStream, key_: &[u8; 16]) -> anyhow::Result<()> {
    let key: GenericArray<u8, U16> = GenericArray::clone_from_slice(key_);
    stream.set_nodelay(true)?;

    let mut keyid = [0; 2];
    stream
        .read_exact(&mut keyid)
        .context("Could not read keyid from stream")?;
    info!(
        "Received the keyid {:#x} and ignoring it",
        u16::from_le_bytes(keyid)
    );

    let mut ciphertext = [0u8; 16];
    stream
        .read_exact(&mut ciphertext)
        .context("Could not read ciphertext from stream")?;
    info!("Received the ciphertext");

    loop {
        let mut lenb = [0; 2];
        stream
            .read_exact(&mut lenb)
            .context("Could not read len from stream")?;
        let len = u16::from_le_bytes(lenb);
        if len == 0 {
            info!("Closed connection");
            return Ok(());
        }
        info!("Received len {}", len);
        let mut blocks: Vec<u8> = vec![0; len as usize * 16];
        stream
            .read_exact(&mut blocks)
            .context("Could not read all blocks from stream")?;
        info!("Received {} bytes", blocks.len());

        debug!("Using the oracle for {} blocks", blocks.len().div_ceil(16));
        let mut buf = Vec::with_capacity(len as usize);
        for block in blocks.chunks(16) {
            if oracle(block, &ciphertext, &key) {
                buf.extend(0x01u8.to_le_bytes());
            } else {
                buf.extend(0x00u8.to_le_bytes());
            }
        }
        stream
            .write_all(&buf)
            .context("Could not write response to stream")?;
        stream.flush().context("Could not flush the stream")?;
        debug!("Sent {} responses", buf.len());
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Ok;

    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    /// (single block) (ending with 0x0201)
    fn test_encrypt_ambig_short() -> anyhow::Result<()> {
        assert_eq!(
            encrypt(
                "foo".as_bytes().to_vec(),
                "AAAAAAAAAAAAAAAA".as_bytes().try_into()?,
                "AAAAAAAAAAAAAAAA".as_bytes().try_into()?,
                true
            ),
            hex::decode("fdf1300041242cd95922eb1e3bbd09c4")?
        );
        assert_eq!(
            encrypt(
                "foo".as_bytes().to_vec(),
                "AAAAAAAAAAAAAAAA".as_bytes().try_into()?,
                "IVIVIVIVIVIVIVIV".as_bytes().try_into()?,
                false
            ),
            hex::decode("1c213765dd74f0a23ea260473f583933")?
        );
        Ok(())
    }

    #[test]
    /// (single block)
    fn test_encrypt_short() -> anyhow::Result<()> {
        assert_eq!(
            encrypt(
                "foo".as_bytes().to_vec(),
                "AAAAAAAAAAAAAAAA".as_bytes().try_into()?,
                "IVIVIVIVIVIVIVIV".as_bytes().try_into()?,
                false
            ),
            hex::decode("1c213765dd74f0a23ea260473f583933")?
        );
        Ok(())
    }

    #[test]
    /// (multiple blocks) plaintext is 16 bytes -> another block is needed (ending with 0x0201)
    fn test_encrypt_ambig_mid() -> anyhow::Result<()> {
        assert_eq!(
            encrypt(
                "foobarfoobarfoob".as_bytes().to_vec(),
                "AAAAAAAAAAAAAAAA".as_bytes().try_into()?,
                "IVIVIVIVIVIVIVIV".as_bytes().try_into()?,
                true
            ),
            hex::decode("36d9b28a855f5e7018adcf0ffe304b4ff803ee963c7284addafffe8f8e7e2959")?
        );
        Ok(())
    }

    #[test]
    /// (multiple blocks)  plaintext is 16 bytes -> another block is required with padding only
    fn test_encrypt_mid() -> anyhow::Result<()> {
        assert_eq!(
            encrypt(
                "foobarfoobarfoob".as_bytes().to_vec(),
                "AAAAAAAAAAAAAAAA".as_bytes().try_into()?,
                "IVIVIVIVIVIVIVIV".as_bytes().try_into()?,
                false
            ),
            hex::decode("75fd6b55417b39fff95e3728c7edf41fce87b8fb37c82a0ec465d2b31ae351e4")?
        );
        Ok(())
    }

    #[test]
    /// (multiple blocks) plaintext is 36 bytes (ending with 0x0201)
    fn test_encrypt_ambig_long() -> anyhow::Result<()> {
        assert_eq!(
            encrypt(
                "foobarfoobarfoobarfoobarfoobarfoobar".as_bytes().to_vec(),
                "AAAAAAAAAAAAAAAA".as_bytes().try_into()?,
                "IVIVIVIVIVIVIVIV".as_bytes().try_into()?,
                true
            ),
            hex::decode(
                "36d9b28a855f5e7018adcf0ffe304b4f50dfbdec0ac6bb7aec2657dc2976c6e5e69896cf00e5303b248b80c0a6892cfc"
            )?
        );
        Ok(())
    }

    #[test]
    /// (multiple blocks)  plaintext is 36 bytes
    fn test_encrypt_long() -> anyhow::Result<()> {
        assert_eq!(
            encrypt(
                "foobarfoobarfoobarfoobarfoobarfoobar".as_bytes().to_vec(),
                "AAAAAAAAAAAAAAAA".as_bytes().try_into()?,
                "IVIVIVIVIVIVIVIV".as_bytes().try_into()?,
                false
            ),
            hex::decode(
                "75fd6b55417b39fff95e3728c7edf41fb220e23d54e0bec6e41c2fc23a5031770289e2de460a62c1c570264fa3619866"
            )?
        );
        Ok(())
    }

    #[test]
    fn test_oracle() -> anyhow::Result<()> {
        assert_eq!(
            oracle(
                &hex::decode("a979c930e6acaddb50a4cbdf0532163a")?,
                &hex::decode("25ee1fe2afc486940eb7bbb2e3ecf688")?,
                "AAAAAAAAAAAAAAAA".as_bytes().try_into()?,
            ),
            true
        );
        assert_eq!(
            oracle(
                &hex::decode("a879c930e6acaddb50a4cbdf0532163a")?,
                &hex::decode("25ee1fe2afc486940eb7bbb2e3ecf688")?,
                "AAAAAAAAAAAAAAAA".as_bytes().try_into()?,
            ),
            false
        );
        Ok(())
    }
}
