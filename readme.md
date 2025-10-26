# ✨ Blazingly fast padding oracle server ✨

## Building it
Clone the repo and do:
```
cargo build --release
```


## Using it

There are two ways for using it.

### Local use (single key mode)
When starting the server, it prints the padded plaintext, the IV and the ciphertext in different formats.
The server accepts any keyid (still must be 2 bytes long) and always uses the key supplied by the cli args (defaults to AAAAAAAAAAAAAAAA).


### Public use / serving different keys
First you need to generate a json with testcases and the keymap (with `-g -k mykeys.json -g mytests.json`). Afterwards, the server can be startetd with `-s -k mykeys.json`. Here, the keyid's of the testcase must be used. If someone sends a wrong keyid that does not exist, the server terminates that connection. 



```
Usage: padding-oracle-server [OPTIONS]

Options:
  -v, --verbose...               Increase verbosity (-v, -vv, -vvv)
      --hostname <HOSTNAME>      Hostname to bind to [default: 0.0.0.0]
  -p, --port <PORT>              Port to bind to [default: 12345]
      --plaintext <PLAINTEXT>    Plaintext to encrypt [default: "Ich bin ein plaintext"]
      --key <KEY>                Key to use [default: AAAAAAAAAAAAAAAA]
      --iv <IV>                  IV to use [default: IVIVIVIVIVIVIVIV]
  -a, --ambiguous                Wheter to use ambiguous padding => ...0x02, 0x01
  -g, --generate-tests           Generates testcases, a keymap and exits
  -s, --serve                    Run as a server with different keys & keyids
  -k, --key-map <KEY_MAP>        In / Output of the keymap file [required with: -g, -s]
  -t, --test-cases <TEST_CASES>  Output of test case file [required with: -g]
  -h, --help                     Print help
  -V, --version                  Print version
```