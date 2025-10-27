use clap::Parser;
use log::{error, info, warn};
use padding_oracle_server::{encrypt, generate_test_cases, handle_connection};
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::process::exit;
use tokio::net::TcpListener;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(short, long, action = clap::ArgAction::Count)]
    /// Increase verbosity (-v, -vv, -vvv)
    verbose: u8,

    #[arg(long, default_value = "0.0.0.0")]
    /// Hostname to bind to
    hostname: String,

    #[arg(short, long, default_value_t = 12345, value_parser = clap::value_parser!(u16))]
    /// Port to bind to
    port: u16,

    #[arg(long, default_value = "Ich bin ein plaintext")]
    /// Plaintext to encrypt
    plaintext: String,

    #[arg(long, default_value = "AAAAAAAAAAAAAAAA")]
    /// Key to use
    key: String,

    #[arg(long, default_value = "IVIVIVIVIVIVIVIV")]
    /// IV to use
    iv: String,

    #[arg(short, long, default_value_t = false)]
    /// Wheter to use ambiguous padding => ...0x02, 0x01
    ambiguous: bool,

    #[arg(short, long, default_value_t = false)]
    /// Generates testcases, a keymap and exits
    generate_tests: bool,

    #[arg(short, long, default_value_t = false)]
    /// Run as a server with different keys & keyids
    serve: bool,

    #[arg(
        short,
        long,
        required_if_eq("generate_tests", "true"),
        required_if_eq("serve", "true")
    )]
    /// In / Output of the keymap file [required with: -g, -s]
    key_map: Option<String>,

    #[arg(short, long, required_if_eq("generate_tests", "true"))]
    /// Output of test case file [required with: -g]
    test_cases: Option<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Map v counts to log levels
    let log_level = match args.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    if env::var("RUST_LOG").is_err() {
        unsafe {
            env::set_var("RUST_LOG", log_level);
        }
    }
    env_logger::init();

    let key: [u8; 16] = match args.key.as_bytes().try_into() {
        Ok(v) => v,
        Err(_) => {
            error!("Could not cast the key into a 16byte slice");
            exit(1);
        }
    };

    let iv: [u8; 16] = match args.iv.as_bytes().try_into() {
        Ok(v) => v,
        Err(_) => {
            error!("Could not cast the IV into a 16byte slice");
            exit(1);
        }
    };

    println!("Note: if you want more verbose output, start the oracle with -v, -vv or -vvv");

    if args.generate_tests {
        match generate_test_cases(
            &args.hostname,
            args.port,
            args.test_cases.unwrap(),
            args.key_map.unwrap(),
        ) {
            Ok(()) => exit(0),
            Err(e) => {
                warn!("Could not generate test cases: {}", e);
                exit(1);
            }
        }
    }

    let keymap: HashMap<u16, [u8; 16]> = if args.serve {
        let file = match File::open(args.key_map.unwrap()) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Could not open the keymap file: {}", e);
                exit(1);
            }
        };
        serde_json::from_reader(file).unwrap()
    } else {
        let mut nmap: HashMap<u16, [u8; 16]> = HashMap::new();
        nmap.insert(0, key);
        nmap
    };

    if !args.serve {
        println!("Note: the KeyId is ignored in this mode");
        encrypt(
            args.plaintext.as_bytes().to_vec(),
            &key,
            &iv,
            args.ambiguous,
        );
    }

    let listener = match TcpListener::bind((args.hostname.clone(), args.port)).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "Could not bind to {}:{} due to {}",
                args.hostname, args.port, e
            );
            exit(1)
        }
    };
    println!("Ready, listening on {}:{}", args.hostname, args.port);
    loop {
        let (stream, addr) = match listener.accept().await {
            Ok((s, a)) => (s, a),
            Err(e) => {
                warn!("Error while accepting connection connection: {}", e);
                continue;
            }
        };
        info!("Initiated connection with {}", addr);
        let kmap = keymap.clone();
        tokio::spawn(async move {
            match handle_connection(stream, kmap, args.serve).await {
                Ok(()) => (),
                Err(e) => warn!("Error while handling connection with {}: {}", addr, e),
            };
        });
    }
}
