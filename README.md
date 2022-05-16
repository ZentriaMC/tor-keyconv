# tor-keyconv

Convert Tor Onion v3 service key into usable form by ControlPort API (`ADD_ONION`) or [lnd][lnd]

Especially useful for converting vanity address generated by [mkp224o][mkp224o].

## Usage

```shell
$ tor-keyconv -key ./key/hs_ed25519_secret_key > ./convkey
$ cat convkey
ED25519-V3:...
```

### Help, lnd does not launch!

Ensure that the keyfile does not have newline character. Use `od -a ./convkey` to check (`nl` = newline)
and `head -c -1 convkey > convkey_nonl` to fix.

## License

MIT

[lnd]: https://github.com/lightningnetwork/lnd
[mkp224o]: https://github.com/cathugger/mkp224o
