# cipher-break

Classical cipher analysis in Rust, with a Haskell reference.

```sh
cargo install --path .
cb data/ciphertext.txt
```

GPU: `cargo install --path . --features gpu`.

Check: `mise install && mise run check`.

Automation: `cargo xtask help`.
The Rust [xtask](xtask/src/main.rs) handles cloud jobs, source audits, recovery checks, client setup, implementation agreement and benchmarks.
See [automation](docs/automation.md) and the [P1030680 research record](docs/p1030680.md).

[MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE).
