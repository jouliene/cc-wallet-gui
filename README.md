# CC Wallet

A desktop wallet for TVM (TON Virtual Machine) networks, built against a
[Tycho](https://github.com/broxus/tycho) node from Broxus.

It manages EVER Wallet accounts and sends both the native gas coin and
**Currency Collection** extra-currency tokens — moving CC is what the wallet was
originally built for, and where the name comes from.

Rust + [Slint](https://slint.dev), delivered as **one portable Linux x86-64
executable**. No installer, launcher, service, or configuration file.

## Build

Requires the toolchain pinned in `rust-toolchain.toml` (rustup reads it
automatically).

```sh
cargo run                  # run the GUI
cargo build --release      # optimised build for this host
./build-portable.sh        # portable executable with a pinned glibc floor
```

`build-portable.sh` produces the distributable artifact. It pins a glibc floor
(2.35 by default, `GLIBC_FLOOR=2.31 ./build-portable.sh` to lower it) and then
verifies the result actually honours it. That needs
[cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild); without it the
script still builds, but the binary requires the build host's glibc.

The executable links only `libc`, `libm`, `libgcc_s`/`libpthread`: fonts and
icons are embedded, rendering uses Slint's software renderer rather than OpenGL,
and TLS is rustls rather than OpenSSL.

## Wallet files

A wallet is a single encrypted `.ccwallet` file: an Argon2id keyslot over
XChaCha20-Poly1305 sealed sections, with a public authenticated header carrying
the wallet's display name so the picker can list wallets before unlocking. All
public framing is bound into every section's associated data, so tampering with
a name, the manifest, or the save counter is caught on unlock.

The wallet folder is the **directory the executable is started from**, read once
at startup. There is no fallback to the executable directory, `$HOME`, or XDG
paths, and no in-app folder picker:

```sh
cd -- /absolute/path/to/wallet-directory && /absolute/path/to/cc-wallet-gui
```

## Layout

| Crate | Responsibility |
| --- | --- |
| `cc-wallet-domain` | Pure domain types: amounts, assets, addresses, send journal, risk model, persisted envelopes and digests |
| `cc-wallet-vault` | The encrypted single-file container format |
| `cc-wallet-storage` | Wallet files on disk: atomic durable writes, crash recovery, data directory, single-instance lock |
| `cc-wallet-tycho` | Node layer: JRPC transport, SSE account subscription, keys and signing, contract encoding, fee emulation |
| `cc-wallet-chain` | Boundary between the controller and the node layer: balances, sends, fee estimation, activity history |
| `cc-wallet-app` | UI-independent application controller and state machine |
| `cc-wallet-ui-slint` | Slint UI and the bridge to the controller; builds the `cc-wallet-gui` binary |

## Status

Linux x86-64 only. Windows and macOS are unsupported: the storage durability,
locking, permission, clipboard, and process-dump contracts are implemented and
tested against Linux, and a cross-compile would not establish them elsewhere.
