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
      --plaintext <PLAINTEXT>  Hostname to bind to [default: "Ich bin ein kleiner plaintext"]
  -k, --key <KEY>              Hostname to bind to [default: AAAAAAAAAAAAAAAA]
  -i, --iv <IV>                Hostname to bind to [default: IVIVIVIVIVIVIVIV]
  -h, --help                   Print help
  -V, --version                Print version
```