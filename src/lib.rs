// well. There are new aes & cbc release candidates that would fix
// the deprecated warning but I didnt get them to work :(
#![allow(deprecated)]
use aes::cipher::{
    BlockDecryptMut, BlockEncryptMut, KeyIvInit,
    block_padding::{Padding, Pkcs7},
    consts::U16,
    generic_array::GenericArray,
};
use anyhow::{Context, bail};
use base64::{Engine as _, engine::general_purpose};
use log::{debug, info};
use rand::seq::IndexedRandom;
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

pub fn encode_b64(to_encode: &Vec<u8>) -> String {
    general_purpose::STANDARD.encode(to_encode)
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
struct RootTest {
    title: String,
    description: String,
    testcases: HashMap<String, TestCase>,
    expectedResults: HashMap<String, ExpectedResult>,
}

#[derive(Serialize, Deserialize, Debug)]
struct TestCase {
    action: String,
    arguments: TestCaseArgs,
}

#[derive(Serialize, Deserialize, Debug)]
struct TestCaseArgs {
    hostname: String,
    port: u16,
    key_id: u16,
    iv: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct ExpectedResult {
    plaintext: String,
}

pub fn generate_test_cases(
    hostname: &String,
    port: u16,
    path_testcases: String,
    path_keymap: String,
) -> anyhow::Result<()> {
    let plaintexts = [
        "We're no strangers",
        "to love",
        "You know the rules and so do I",
        "A full commitment's what I'm thinkin' of",
        "You wouldn't get this from any other guy",
        "Never gonna give you up, never gonna let you down",
        "Never gonna run around and desert you",
        "Never gonna make you cry, never gonna say goodbye",
    ];
    let mut testcases: HashMap<String, TestCase> = HashMap::new();
    let mut results: HashMap<String, ExpectedResult> = HashMap::new();
    let mut keymap: HashMap<u16, [u8; 16]> = HashMap::new();

    for i in 0..10 {
        let p = match plaintexts.choose(&mut rand::rng()) {
            Some(v) => *v,
            None => continue,
        };
        let mut key = [0u8; 16];
        rand::rng().fill_bytes(&mut key);

        let key_id = rand::rng().random_range(..u16::MAX);

        let mut iv = [0u8; 16];
        rand::rng().fill_bytes(&mut iv);

        let ambig = i % 2 == 0;

        let (plain, cipher, iv) = encrypt(p.into(), &key, &iv, ambig);
        keymap.insert(key_id, key);

        testcases.insert(
            format!("case{}", i),
            TestCase {
                action: "padding_oracle".to_string(),
                arguments: TestCaseArgs {
                    hostname: hostname.to_string(),
                    port,
                    key_id,
                    iv,
                    ciphertext: cipher,
                },
            },
        );
        results.insert(format!("case{}", i), ExpectedResult { plaintext: plain });
    }
    let root = RootTest {
        title: "Some padding oracle cases".to_string(),
        description: "padding oracle".to_string(),
        testcases,
        expectedResults: results,
    };
    let testcases_file =
        fs::File::create(path_testcases).context("Could not create testcase file")?;
    let keys_file: fs::File =
        fs::File::create(path_keymap).context("Could not create keymap file")?;
    serde_json::to_writer_pretty(testcases_file, &root)?;
    serde_json::to_writer_pretty(keys_file, &keymap)?;
    Ok(())
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

pub fn encrypt(
    plaintext: Vec<u8>,
    key_s: &[u8; 16],
    iv_s: &[u8; 16],
    ambig: bool,
) -> (String, String, String) {
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
    if ambig {
        println!("Note: due to creating ambigous padding, the plaintext is a bit scrambled");
        let mut first_block = blocks.remove(0);
        first_block[14] = 0x02;
        first_block[15] = 0x01;
        blocks.insert(0, first_block);
        empty = 1;
    }

    if empty == 0 {
        // add block with only padding
        let mut empty_block = GenericArray::clone_from_slice(&[0u8; 16]);
        Pkcs7::pad(&mut empty_block, empty);
        blocks.push(empty_block);
    } else {
        let mut last_block = blocks.pop().unwrap();
        Pkcs7::pad(&mut last_block, 16 - empty);
        blocks.push(last_block);
    }
    let plain = join_blocks(&blocks);
    println!("--- Used IV--- ");
    let b64_iv = encode_b64(&iv.to_vec());
    println!("b64: {}", b64_iv);
    println!("hex: {}", hex::encode(iv));
    println!("\n--- Padded Plaintext --- ");
    println!("UTF8: {:?}", String::from_utf8_lossy(&plain));
    let b64_plaintext = encode_b64(&plain);
    println!("b64 : {}", b64_plaintext);
    println!("hex : {}", hex::encode(plain));

    Aes128CbcEnc::new(&key, &iv).encrypt_blocks_mut(&mut blocks);

    let ciphertext = join_blocks(&blocks);
    println!("\n--- Ciphertext --- ");
    let b64_ciphertext = encode_b64(&ciphertext);
    println!("b64: {}", b64_ciphertext);
    println!("hex: {}\n", hex::encode(&ciphertext));
    (b64_plaintext, b64_ciphertext, b64_iv)
}

#[derive(Error, Debug)]
pub enum ConnectionError {
    #[error("Requested keyid {keyid} is not in the map")]
    KeyNotInMapError { keyid: u16 },
}

pub async fn handle_connection(
    mut stream: TcpStream,
    keymap: HashMap<u16, [u8; 16]>,
    serve: bool,
) -> anyhow::Result<()> {
    stream.set_nodelay(true)?;

    let mut keyid = [0; 2];
    stream
        .read_exact(&mut keyid)
        .await
        .context("Could not read keyid from stream")?;
    info!("Received the keyid {:#x}", u16::from_le_bytes(keyid));

    // when it's not in serve mode, the key is stored at index 0
    if !serve {
        keyid = [0; 2];
    }

    let key_ = match keymap.get(&u16::from_le_bytes(keyid)) {
        Some(v) => v,
        None => bail!(ConnectionError::KeyNotInMapError {
            keyid: u16::from_le_bytes(keyid)
        }),
    };

    let key: GenericArray<u8, U16> = GenericArray::clone_from_slice(key_);

    let mut ciphertext = [0u8; 16];
    stream
        .read_exact(&mut ciphertext)
        .await
        .context("Could not read ciphertext from stream")?;
    info!("Received the ciphertext");

    loop {
        let mut lenb = [0; 2];
        stream
            .read_exact(&mut lenb)
            .await
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
            .await
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
            .await
            .context("Could not write response to stream")?;
        stream.flush().await.context("Could not flush the stream")?;
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
            )
            .1,
            "/fEwAEEkLNlZIuseO70JxA=="
        );
        assert_eq!(
            encrypt(
                "foo".as_bytes().to_vec(),
                "AAAAAAAAAAAAAAAA".as_bytes().try_into()?,
                "IVIVIVIVIVIVIVIV".as_bytes().try_into()?,
                false
            )
            .1,
            "HCE3Zd108KI+omBHP1g5Mw=="
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
            )
            .1,
            "HCE3Zd108KI+omBHP1g5Mw=="
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
            )
            .1,
            "elYsFKIxPdNJoo7qVgEwqQ=="
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
            )
            .1,
            "df1rVUF7Of/5Xjcox+30H86HuPs3yCoOxGXSsxrjUeQ="
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
            )
            .1,
            "elYsFKIxPdNJoo7qVgEwqXSDbZ1ZXisIvcbHmCMnIen/dUVEiPcur0R9aG8MMRGb",
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
            )
            .1,
            "df1rVUF7Of/5Xjcox+30H7Ig4j1U4L7G5BwvwjpQMXcCieLeRgpiwcVwJk+jYZhm",
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
