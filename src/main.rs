use clap::Parser;
use log::{info, warn};
use padding_oracle_server::{encrypt, handle_connection};
use std::net::TcpListener;
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(short, long, action = clap::ArgAction::Count)]
    /// Increase verbosity (-v, -vv, -vvv)
    verbose: u8,

    #[arg(long, default_value = "localhost")]
    /// Hostname to bind to
    hostname: String,

    #[arg(short, long, default_value_t = 12345, value_parser = clap::value_parser!(u16))]
    /// Port to bind to
    port: u16,

    #[arg(long, default_value = "Ich bin ein kleiner plaintext")]
    /// Hostname to bind to
    plaintext: String,

    #[arg(short, long, default_value = "AAAAAAAAAAAAAAAA")]
    /// Hostname to bind to
    key: String,

    #[arg(short, long, default_value = "IVIVIVIVIVIVIVIV")]
    /// Hostname to bind to
    iv: String,
}

fn main() {
    let args = Args::parse();

    // Map v counts to log levels
    let log_level = match args.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    // Initialize logger
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();

    assert!(args.key.len() == 16);
    assert!(args.iv.len() == 16);

    let key: [u8; 16] = args.key.as_bytes().try_into().unwrap();
    let iv: [u8; 16] = args.iv.as_bytes().try_into().unwrap();

    encrypt(args.plaintext.as_bytes().to_vec(), &key, &iv);
    println!("Note: if you want more verbose output, start the oracle with -v, -vv or -vvv");

    let listener = TcpListener::bind((args.hostname.clone(), args.port)).expect("could not bind");
    println!("Ready, listening on {}:{}", args.hostname, args.port);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                info!("Initiated connection");
                match handle_connection(stream, &key, &iv) {
                    Ok(()) => (),
                    Err(e) => warn!("Error while handling connection {}", e),
                };
            }
            Err(_) => warn!("Connection failed"),
        }
    }
}
