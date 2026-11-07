# buntrail-helper

Remote services library and helper executable.

## Features

Framed service dispatch, protected Unix supervisor, leases and retained terminals.

## Usage

Add to your Cargo.toml after the initial registry release:

```toml
[dependencies]
buntrail-helper = "0.1.0"
```

```rust
assert_eq!(buntrail_helper::MAX_FRAME_BYTES, 8 * 1024 * 1024);
```

Rust 1.99.1 (edition 2024). Unix integration checks need Git, Python 3, zsh, and ripgrep 15.1.0. Install rg beside your executable for bundled discovery, or use the explicit search constructor. SSH, Docker and Podman are required only for their respective routes. SSH askpass and remote bootstrap require matching helper resources supplied by the embedding application.

```sh
cargo fetch
scripts/check.sh
```

## Technologies and support

Rust, Cargo. Typed filesystem/remote/terminal implementations are primarily Unix-only. Windows currently uses command services and ConPTY; Unix supervisors are unavailable there. Native Windows acceptance and full interactive remote authentication/bootstrap acceptance remain unverified. This is a development release, not a promise of desktop parity.

## Helper entrypoints and protocols

Unix framed entrypoints are `buntrail-helper probe`,
`serve --socket /absolute/private/state/socket`, and
`bridge --socket /absolute/private/state/socket`. The bridge attaches to or starts
the protected owner and relays framed bytes on stdio. See the
[framed protocol reference](protocol/v1/README.md) for limits, authenticated
contexts, capabilities, transfers, operation inspection and lease behavior.
Stdout is binary transport; diagnostics belong on stderr. A connection owner must
verify the target identity before admitting file mutations. Never replay uncertain
mutations or terminal input after transport failure.

### Direct JSON sessions

The executable also currently provides a separate direct JSON session with
`--stdio`; Windows uses this session. These modes still exist while migration to
the shared framed runtime is incomplete. They do not speak the framed protocol.

Direct frames are a four-byte big-endian length (1–8,388,608), followed by UTF-8
JSON. First send `{"protocol":1}`. The success envelope contains `protocol`,
`instance`, `transport`, `terminal_encoding` and `max_frame_bytes`. Then send
service objects with `command`; see the services crate's
[command reference](https://github.com/buntrail/buntrail-services/blob/main/README.md#blocking-command-interface).
Replies are `{"ok":true,"value":...}` or
`{"ok":false,"error":{"code":"...","message":"..."}}`.

Malformed JSON/missing handshakes return errors. Invalid lengths and truncated
frames terminate the session. Oversized replies return `response_too_large`;
file requests/replies must fit the frame after JSON escaping. Terminal reads
include lossless `bytes` and lossy `output`; input accepts validated `bytes` or
`text`. Direct sessions require the matching helper already installed; typed
bootstrap and authentication are separate capabilities.

### Direct Unix supervisor

With no arguments, Unix bridges to the direct-session supervisor under
`$XDG_RUNTIME_DIR/id.bungamungil.buntrail.app` or
`$HOME/.cache/id.bungamungil.buntrail.app`. The user-owned directory must have mode
0700; the socket has mode 0600. `--socket PATH` selects its socket;
`--supervisor PATH` runs its owner. No public port or permanent service is installed.

The direct supervisor shares service state between windows and retains it for
30 minutes after the last disconnect, then ends terminals and removes its socket.
Compare handshake `instance` before reusing terminal IDs. `--stdio` has no retained
supervisor state. Windows named-pipe supervision and framed hosting are not yet
implemented. Native Windows execution is unverified and outside this session's
checks.


API documentation is built with `cargo doc --no-deps`. Public dependency types
remain in their originating Buntrail crates; depend on those crates directly
when constructing those types. No API stability beyond the declared 0.x version
is promised. See [release instructions](docs/releasing.md).

## Collaborators and contributing

Maintained by Bunga Mungil for the [Buntrail organization](https://github.com/buntrail).
Contributions are welcome through issues and small pull requests in
https://github.com/buntrail/buntrail-helper. Read [CONTRIBUTING.md](CONTRIBUTING.md)
and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Contact: bungamungil@icloud.com.
Report vulnerabilities privately using [SECURITY.md](SECURITY.md).

## License

First-party code is [MIT licensed](LICENSE), Copyright (c) 2026 Bunga Mungil.
Third-party dependencies retain their own licenses. See
[third-party notices](THIRD_PARTY_NOTICES.md).
