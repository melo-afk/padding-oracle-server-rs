# ✨ Blazingly fast padding oracle server ✨

## Building it
Clone the repo and do:
```
cargo build --release
```


## Using it

```
Usage: padding-oracle-server [OPTIONS]

Options:
  -v, --verbose...             Increase verbosity (-v, -vv, -vvv)
      --hostname <HOSTNAME>    Hostname to bind to [default: localhost]
  -p, --port <PORT>            Port to bind to [default: 12345]
      --plaintext <PLAINTEXT>  Plaintext to encrypt [default: "Ich bin ein kla"]
  -k, --key <KEY>              Key to use [default: AAAAAAAAAAAAAAAA]
  -i, --iv <IV>                IV to use [default: IVIVIVIVIVIVIVIV]
  -a, --ambiguous              Wheter to use ambiguous padding => ...0x02, 0x01
  -h, --help                   Print help
  -V, --version                Print version
```