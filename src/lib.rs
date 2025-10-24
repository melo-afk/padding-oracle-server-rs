// well. There are new aes & cbc release candidates that would fix
// the deprecated warning but I didnt get them to work :(
#![allow(deprecated)]
use aes::cipher::{
    BlockDecryptMut, BlockEncryptMut, KeyIvInit,
    block_padding::{Padding, Pkcs7},
    consts::{U16, U32},
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
fn oracle(block_bytes: &[u8], iv: GenericArray<u8, U16>, key: GenericArray<u8, U16>) -> bool {
    let mut block: GenericArray<u8, U32> = GenericArray::clone_from_slice(block_bytes);
    Aes128CbcDec::new(&key, &iv)
        .decrypt_padded_mut::<Pkcs7>(&mut block)
        .is_ok()
}

pub fn encrypt(plaintext: Vec<u8>, key: &[u8; 16], iv: &[u8; 16], ambig: bool) {
    let key_a = GenericArray::clone_from_slice(key);
    let iv_a = GenericArray::clone_from_slice(iv);

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
        // add some padding
        let mut last_block = blocks.pop().unwrap();
        if ambig {
            last_block[16 - empty] = 0x02;
            empty -= 1;
        }
        Pkcs7::pad(&mut last_block, 16 - empty);
        blocks.push(last_block);
    }
    let plain = join_blocks(&blocks);
    println!("Padded Plaintext: {:?}", String::from_utf8_lossy(&plain));
    println!("Padded Plaintext  (b64): {}", encode_b64(&plain));

    Aes128CbcEnc::new(&key_a, &iv_a).encrypt_blocks_mut(&mut blocks);

    let ciphertext = join_blocks(&blocks);
    println!("Ciphertext (b64): {}", encode_b64(&ciphertext));
    println!("Ciphertext (hex): {}", hex::encode(ciphertext));
}

pub fn handle_connection(
    mut stream: TcpStream,
    key_: &[u8; 16],
    iv_: &[u8; 16],
) -> anyhow::Result<()> {
    let key: GenericArray<u8, U16> = GenericArray::clone_from_slice(key_);
    let iv: GenericArray<u8, U16> = GenericArray::clone_from_slice(iv_);
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

        let mut blocks: Vec<u8> = vec![0; len as usize * 16];
        stream
            .read_exact(&mut blocks)
            .context("Could not read all blocks from stream")?;
        info!(
            "Received len {}, amount of blocks: {}",
            len,
            blocks.len().div_ceil(len as usize)
        );

        debug!("Using the oracle for {} blocks", blocks.len().div_ceil(16));
        let mut buf = Vec::with_capacity(len as usize);
        for block in blocks.chunks(16) {
            let mut combined = Vec::with_capacity(32);
            combined.extend_from_slice(block);
            combined.extend_from_slice(&ciphertext);
            assert!(combined.len() == 32);
            if oracle(&combined, iv, key) {
                buf.extend(0x01u8.to_le_bytes());
            } else {
                buf.extend(0x00u8.to_le_bytes());
            }
        }

        stream
            .write_all(&buf)
            .context("Could not write response to stream")?;
        debug!("Sent {} responses", buf.len());
    }
}
