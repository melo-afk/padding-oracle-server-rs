// well. There are new aes & cbc release candidates that would fix
// the deprecated warning but I didnt get them to work :(
#![allow(deprecated)]
use aes::cipher::{
    BlockDecryptMut, BlockEncryptMut, KeyIvInit,
    block_padding::Pkcs7,
    consts::{U16, U32},
    generic_array::GenericArray,
};
use base64::{Engine as _, engine::general_purpose};
use log::{debug, info};
use std::{
    io::{Read, Write},
    net::TcpStream,
};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

pub fn decode_b64(to_decode: String) -> Vec<u8> {
    general_purpose::STANDARD
        .decode(to_decode)
        .expect("Could not decode base64")
}

pub fn encode_b64(to_encode: &Vec<u8>) -> String {
    general_purpose::STANDARD.encode(to_encode)
}

/// be a good padding oracle and return whether padding is valid or not
fn oracle(block_bytes: &[u8], iv: GenericArray<u8, U16>, key: GenericArray<u8, U16>) -> bool {
    let mut block: GenericArray<u8, U32> = GenericArray::clone_from_slice(block_bytes);
    Aes128CbcDec::new(&key, &iv)
        .decrypt_padded_mut::<Pkcs7>(&mut block)
        .is_ok()
}

/// encrypt the plaintext and print it
pub fn encrypt(plaintext: Vec<u8>, key: &[u8; 16], iv: &[u8; 16]) -> Vec<u8> {
    let key_a = GenericArray::clone_from_slice(key);
    let iv_a = GenericArray::clone_from_slice(iv);

    let pt_len = plaintext.len();
    let mut buf = vec![0u8; pt_len.div_ceil(16) * 16];
    buf[..pt_len].copy_from_slice(&plaintext);
    println!("Padded Plaintext: {:?}", String::from_utf8_lossy(&buf));
    println!("Padded Plaintext  (b64): {}", encode_b64(&buf));
    let ct = Aes128CbcEnc::new(&key_a, &iv_a)
        .encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len)
        .expect("could not encrypt");
    println!("Ciphertext (b64): {}", encode_b64(&ct.to_vec()));
    println!("Ciphertext (hex): {}", hex::encode(ct));
    ct.to_vec()
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
    stream.read_exact(&mut keyid).expect("Could not read keyid");
    info!(
        "Received the keyid {:#x} and ignoring it",
        u16::from_le_bytes(keyid)
    );

    let mut ciphertext = [0u8; 16];
    stream
        .read_exact(&mut ciphertext)
        .expect("Could not read ciphertext");
    info!("Received the ciphertext");

    loop {
        let mut lenb = [0; 2];
        stream.read_exact(&mut lenb).expect("Could not read len");
        let len = u16::from_le_bytes(lenb);
        if len == 0 {
            info!("Closed connection");
            return Ok(());
        }

        let mut blocks: Vec<u8> = vec![0; len as usize * 16];
        stream
            .read_exact(&mut blocks)
            .expect("Could not read all blocks");
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
            if oracle(&combined, iv, key) {
                buf.extend(0x01u8.to_le_bytes());
            } else {
                buf.extend(0x00u8.to_le_bytes());
            }
        }

        stream.write_all(&buf).expect("could not write all");
        debug!("Sent {} responses", buf.len());
    }
}
