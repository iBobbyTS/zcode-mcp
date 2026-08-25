# Exact Cargo Dependency License Inventory

This report inventories every resolved third-party package in the exact
workspace `Cargo.lock`. It reports package metadata as declared; it is not a
legal compatibility conclusion.

## Reproducibility record

- Source lockfile: `Cargo.lock`
- Cargo.lock SHA-256: `ec2471b508ef12cee914fbd1554e3cef2d4be9a9127d9253db887d3797149a7e`
- Resolved third-party packages: `189`
- Canonical inventory SHA-256:
  `a9067c2f48aed8560f62c5a5a3d2a3a2d7e255a8021efdc7bf514a32df17541f`
- Hash strategy: SHA-256 of the compact, key-sorted JSON array produced by the
  first `jq -cS` command below. Array rows are sorted by
  `name`, `version`, then `source`. The complete report-file SHA-256 is
  recorded by the linking reference document so this file does not contain a
  self-referential hash.
- Tool versions:
  - `cargo 1.97.1 (c980f4866 2026-06-30) (Homebrew)`
  - `jq-1.7.1-apple`
  - `shasum 6.02`

The `License declared` column is verbatim Cargo package metadata.
`License display` changes only legacy `/` separators to `OR` for
readability. The [Rust Style Guide](https://doc.rust-lang.org/stable/style-guide/cargo.html)
recognizes `/` as a widespread legacy convention for `OR`; current
[Cargo manifest guidance](https://doc.rust-lang.org/cargo/reference/manifest.html#the-license-and-license-file-fields)
uses SPDX `OR`, so this report marks slash syntax as deprecated. No dependency
metadata is rewritten.

Run from the repository root to reproduce the canonical hash and the complete
inventory table:

```sh
set -eu
metadata_file="$(mktemp)"
generated_table="$(mktemp)"
tracked_table="$(mktemp)"
trap 'rm -f "$metadata_file" "$generated_table" "$tracked_table"' EXIT

cargo metadata --locked --format-version 1 > "$metadata_file"
test "$(shasum -a 256 Cargo.lock | awk '{print $1}')" = \
  "ec2471b508ef12cee914fbd1554e3cef2d4be9a9127d9253db887d3797149a7e"
test "$(jq '[.packages[] | select(.source != null)] | length' \
  "$metadata_file")" = "189"
test "$(jq '[.packages[] | select(.source != null) |
  select(.license == null or .license == "" or
    (.license | ascii_downcase | test("unknown|unlicensed")))] | length' \
  "$metadata_file")" = "0"

inventory_sha="$(
  jq -cS '[.packages[] | select(.source != null) |
    {license_declared:.license,
     license_display:(.license | gsub("/"; " OR ")),
     name,
     source,
     syntax:(if (.license | contains("/"))
       then "legacy slash (deprecated)" else "SPDX" end),
     version}] | sort_by(.name,.version,.source)' "$metadata_file" |
  shasum -a 256 | awk '{print $1}'
)"
test "$inventory_sha" = \
  "a9067c2f48aed8560f62c5a5a3d2a3a2d7e255a8021efdc7bf514a32df17541f"

{
  printf '%s\n' \
    '| Package | Version | Source | License declared | License display | Syntax |' \
    '|---|---:|---|---|---|---|'
  jq -r '[.packages[] | select(.source != null) |
    {name,
     version,
     source,
     license_declared:.license,
     license_display:(.license | gsub("/"; " OR ")),
     syntax:(if (.license | contains("/"))
       then "legacy slash (deprecated)" else "SPDX" end)}] |
    sort_by(.name,.version,.source)[] |
    "| `\(.name)` | `\(.version)` | `\(.source)` | `\(.license_declared)` | `\(.license_display)` | \(.syntax) |"' \
    "$metadata_file"
} > "$generated_table"

sed -n '/^| Package | Version | Source | License declared | License display | Syntax |$/,$p' \
  docs/dependency-licenses.md > "$tracked_table"
cmp "$generated_table" "$tracked_table"
```

## Inventory

| Package | Version | Source | License declared | License display | Syntax |
|---|---:|---|---|---|---|
| `ahash` | `0.8.12` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `aho-corasick` | `1.1.5` | `registry+https://github.com/rust-lang/crates.io-index` | `Unlicense OR MIT` | `Unlicense OR MIT` | SPDX |
| `allocator-api2` | `0.2.21` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `android_system_properties` | `0.1.6` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `autocfg` | `1.5.1` | `registry+https://github.com/rust-lang/crates.io-index` | `Apache-2.0 OR MIT` | `Apache-2.0 OR MIT` | SPDX |
| `base64` | `0.23.1` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `bit-set` | `0.8.0` | `registry+https://github.com/rust-lang/crates.io-index` | `Apache-2.0 OR MIT` | `Apache-2.0 OR MIT` | SPDX |
| `bit-vec` | `0.8.0` | `registry+https://github.com/rust-lang/crates.io-index` | `Apache-2.0 OR MIT` | `Apache-2.0 OR MIT` | SPDX |
| `bitflags` | `2.13.1` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `block-buffer` | `0.10.4` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `borrow-or-share` | `0.2.4` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT-0` | `MIT-0` | SPDX |
| `bumpalo` | `3.20.3` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `bytecount` | `0.6.9` | `registry+https://github.com/rust-lang/crates.io-index` | `Apache-2.0/MIT` | `Apache-2.0 OR MIT` | legacy slash (deprecated) |
| `bytes` | `1.12.1` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `cc` | `1.4.4` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `cfg-if` | `1.0.4` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `cfg_aliases` | `0.2.2` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `chrono` | `0.4.45` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `core-foundation-sys` | `0.8.7` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `cpufeatures` | `0.2.17` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `crypto-common` | `0.1.7` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `darling` | `0.24.1` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `darling_core` | `0.24.1` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `darling_macro` | `0.24.1` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `data-encoding` | `2.11.1` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `digest` | `0.10.7` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `displaydoc` | `0.2.7` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `dyn-clone` | `1.0.20` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `email_address` | `0.2.9` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `equivalent` | `1.0.2` | `registry+https://github.com/rust-lang/crates.io-index` | `Apache-2.0 OR MIT` | `Apache-2.0 OR MIT` | SPDX |
| `errno` | `0.3.14` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `fallible-iterator` | `0.3.0` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT/Apache-2.0` | `MIT OR Apache-2.0` | legacy slash (deprecated) |
| `fallible-streaming-iterator` | `0.1.9` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT/Apache-2.0` | `MIT OR Apache-2.0` | legacy slash (deprecated) |
| `fancy-regex` | `0.19.0` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `fastrand` | `2.5.0` | `registry+https://github.com/rust-lang/crates.io-index` | `Apache-2.0 OR MIT` | `Apache-2.0 OR MIT` | SPDX |
| `find-msvc-tools` | `0.1.11` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `fluent-uri` | `0.4.1` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `foldhash` | `0.2.0` | `registry+https://github.com/rust-lang/crates.io-index` | `Zlib` | `Zlib` | SPDX |
| `fraction` | `0.16.0` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `futures` | `0.3.34` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `futures-channel` | `0.3.34` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `futures-core` | `0.3.34` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `futures-executor` | `0.3.34` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `futures-io` | `0.3.34` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `futures-macro` | `0.3.34` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `futures-sink` | `0.3.34` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `futures-task` | `0.3.34` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `futures-util` | `0.3.34` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `generic-array` | `0.14.7` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `getrandom` | `0.3.4` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `getrandom` | `0.4.3` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `hashbrown` | `0.14.5` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `hashbrown` | `0.17.1` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `hashlink` | `0.9.1` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `heck` | `0.5.0` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `iana-time-zone` | `0.1.65` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `iana-time-zone-haiku` | `0.1.2` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `icu_collections` | `2.3.0` | `registry+https://github.com/rust-lang/crates.io-index` | `Unicode-3.0` | `Unicode-3.0` | SPDX |
| `icu_locale_core` | `2.3.0` | `registry+https://github.com/rust-lang/crates.io-index` | `Unicode-3.0` | `Unicode-3.0` | SPDX |
| `icu_normalizer` | `2.3.0` | `registry+https://github.com/rust-lang/crates.io-index` | `Unicode-3.0` | `Unicode-3.0` | SPDX |
| `icu_normalizer_data` | `2.3.0` | `registry+https://github.com/rust-lang/crates.io-index` | `Unicode-3.0` | `Unicode-3.0` | SPDX |
| `icu_properties` | `2.3.0` | `registry+https://github.com/rust-lang/crates.io-index` | `Unicode-3.0` | `Unicode-3.0` | SPDX |
| `icu_properties_data` | `2.3.0` | `registry+https://github.com/rust-lang/crates.io-index` | `Unicode-3.0` | `Unicode-3.0` | SPDX |
| `icu_provider` | `2.3.1` | `registry+https://github.com/rust-lang/crates.io-index` | `Unicode-3.0` | `Unicode-3.0` | SPDX |
| `ident_case` | `1.0.1` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT/Apache-2.0` | `MIT OR Apache-2.0` | legacy slash (deprecated) |
| `idna` | `1.1.0` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `idna_adapter` | `1.2.2` | `registry+https://github.com/rust-lang/crates.io-index` | `Apache-2.0 OR MIT` | `Apache-2.0 OR MIT` | SPDX |
| `indexmap` | `2.14.0` | `registry+https://github.com/rust-lang/crates.io-index` | `Apache-2.0 OR MIT` | `Apache-2.0 OR MIT` | SPDX |
| `itoa` | `1.0.18` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `js-sys` | `0.3.104` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `jsonschema` | `0.51.0` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `jsonschema-regex` | `0.51.0` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `jsonschema-value` | `0.51.0` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `libc` | `0.2.189` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `libsqlite3-sys` | `0.30.1` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `linux-raw-sys` | `0.12.1` | `registry+https://github.com/rust-lang/crates.io-index` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | SPDX |
| `litemap` | `0.8.3` | `registry+https://github.com/rust-lang/crates.io-index` | `Unicode-3.0` | `Unicode-3.0` | SPDX |
| `lock_api` | `0.4.14` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `log` | `0.4.34` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `memchr` | `2.8.3` | `registry+https://github.com/rust-lang/crates.io-index` | `Unlicense OR MIT` | `Unlicense OR MIT` | SPDX |
| `micromap` | `0.3.0` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `mio` | `1.2.2` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `nix` | `0.31.3` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `num` | `0.4.3` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `num-bigint` | `0.4.8` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `num-cmp` | `0.1.0` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT/Apache-2.0` | `MIT OR Apache-2.0` | legacy slash (deprecated) |
| `num-complex` | `0.4.6` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `num-integer` | `0.1.47` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `num-iter` | `0.1.46` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `num-rational` | `0.4.2` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `num-traits` | `0.2.19` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `once_cell` | `1.21.4` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `outref` | `0.5.2` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `parking_lot` | `0.12.5` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `parking_lot_core` | `0.9.12` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `pastey` | `0.2.3` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `percent-encoding` | `2.3.2` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `pin-project-lite` | `0.2.17` | `registry+https://github.com/rust-lang/crates.io-index` | `Apache-2.0 OR MIT` | `Apache-2.0 OR MIT` | SPDX |
| `pkg-config` | `0.3.34` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `potential_utf` | `0.1.6` | `registry+https://github.com/rust-lang/crates.io-index` | `Unicode-3.0` | `Unicode-3.0` | SPDX |
| `proc-macro2` | `1.0.107` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `process-wrap` | `9.1.0` | `registry+https://github.com/rust-lang/crates.io-index` | `Apache-2.0 OR MIT` | `Apache-2.0 OR MIT` | SPDX |
| `quote` | `1.0.47` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `r-efi` | `5.3.0` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0 OR LGPL-2.1-or-later` | `MIT OR Apache-2.0 OR LGPL-2.1-or-later` | SPDX |
| `r-efi` | `6.0.0` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0 OR LGPL-2.1-or-later` | `MIT OR Apache-2.0 OR LGPL-2.1-or-later` | SPDX |
| `redox_syscall` | `0.5.18` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `ref-cast` | `1.0.27` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `ref-cast-impl` | `1.0.27` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `referencing` | `0.51.0` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `regex` | `1.13.1` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `regex-automata` | `0.4.18` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `regex-syntax` | `0.8.11` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `rmcp` | `3.1.4` | `registry+https://github.com/rust-lang/crates.io-index` | `Apache-2.0` | `Apache-2.0` | SPDX |
| `rmcp-macros` | `3.1.4` | `registry+https://github.com/rust-lang/crates.io-index` | `Apache-2.0` | `Apache-2.0` | SPDX |
| `rusqlite` | `0.32.1` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `rustix` | `1.1.4` | `registry+https://github.com/rust-lang/crates.io-index` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | SPDX |
| `rustversion` | `1.0.23` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `schemars` | `1.2.2` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `schemars_derive` | `1.2.2` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `scopeguard` | `1.2.0` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `serde` | `1.0.229` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `serde_core` | `1.0.229` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `serde_derive` | `1.0.229` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `serde_derive_internals` | `0.30.0` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `serde_json` | `1.0.151` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `sha2` | `0.10.9` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `shlex` | `2.0.1` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `signal-hook` | `0.3.18` | `registry+https://github.com/rust-lang/crates.io-index` | `Apache-2.0/MIT` | `Apache-2.0 OR MIT` | legacy slash (deprecated) |
| `signal-hook-registry` | `1.4.8` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `slab` | `0.4.12` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `smallvec` | `1.15.2` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `socket2` | `0.6.5` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `stable_deref_trait` | `1.2.1` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `strsim` | `0.11.1` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `strum` | `0.28.0` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `strum_macros` | `0.28.0` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `syn` | `2.0.119` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `syn` | `3.0.3` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `synstructure` | `0.13.2` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `tempfile` | `3.27.0` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `thiserror` | `2.0.20` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `thiserror-impl` | `2.0.20` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `tinystr` | `0.8.4` | `registry+https://github.com/rust-lang/crates.io-index` | `Unicode-3.0` | `Unicode-3.0` | SPDX |
| `tokio` | `1.53.1` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `tokio-macros` | `2.7.2` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `tokio-stream` | `0.1.19` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `tokio-util` | `0.7.19` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `tracing` | `0.1.44` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `tracing-attributes` | `0.1.31` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `tracing-core` | `0.1.36` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `typenum` | `1.20.1` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `unicode-general-category` | `1.1.0` | `registry+https://github.com/rust-lang/crates.io-index` | `Apache-2.0` | `Apache-2.0` | SPDX |
| `unicode-ident` | `1.0.24` | `registry+https://github.com/rust-lang/crates.io-index` | `(MIT OR Apache-2.0) AND Unicode-3.0` | `(MIT OR Apache-2.0) AND Unicode-3.0` | SPDX |
| `utf8_iter` | `1.0.4` | `registry+https://github.com/rust-lang/crates.io-index` | `Apache-2.0 OR MIT` | `Apache-2.0 OR MIT` | SPDX |
| `uuid` | `1.25.0` | `registry+https://github.com/rust-lang/crates.io-index` | `Apache-2.0 OR MIT` | `Apache-2.0 OR MIT` | SPDX |
| `uuid-simd` | `0.8.0` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `vcpkg` | `0.2.15` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT/Apache-2.0` | `MIT OR Apache-2.0` | legacy slash (deprecated) |
| `version_check` | `0.9.5` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT/Apache-2.0` | `MIT OR Apache-2.0` | legacy slash (deprecated) |
| `vsimd` | `0.8.0` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
| `wasi` | `0.11.1+wasi-snapshot-preview1` | `registry+https://github.com/rust-lang/crates.io-index` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | SPDX |
| `wasip2` | `1.0.4+wasi-0.2.12` | `registry+https://github.com/rust-lang/crates.io-index` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | SPDX |
| `wasm-bindgen` | `0.2.127` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `wasm-bindgen-macro` | `0.2.127` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `wasm-bindgen-macro-support` | `0.2.127` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `wasm-bindgen-shared` | `0.2.127` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `windows` | `0.62.2` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `windows-collections` | `0.3.2` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `windows-core` | `0.62.2` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `windows-future` | `0.3.2` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `windows-implement` | `0.60.2` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `windows-interface` | `0.59.3` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `windows-link` | `0.2.1` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `windows-numerics` | `0.3.1` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `windows-result` | `0.4.1` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `windows-strings` | `0.5.1` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `windows-sys` | `0.61.2` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `windows-threading` | `0.2.1` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT OR Apache-2.0` | `MIT OR Apache-2.0` | SPDX |
| `wit-bindgen` | `0.57.1` | `registry+https://github.com/rust-lang/crates.io-index` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | SPDX |
| `writeable` | `0.6.4` | `registry+https://github.com/rust-lang/crates.io-index` | `Unicode-3.0` | `Unicode-3.0` | SPDX |
| `yoke` | `0.8.3` | `registry+https://github.com/rust-lang/crates.io-index` | `Unicode-3.0` | `Unicode-3.0` | SPDX |
| `yoke-derive` | `0.8.2` | `registry+https://github.com/rust-lang/crates.io-index` | `Unicode-3.0` | `Unicode-3.0` | SPDX |
| `zerocopy` | `0.8.56` | `registry+https://github.com/rust-lang/crates.io-index` | `BSD-2-Clause OR Apache-2.0 OR MIT` | `BSD-2-Clause OR Apache-2.0 OR MIT` | SPDX |
| `zerocopy-derive` | `0.8.56` | `registry+https://github.com/rust-lang/crates.io-index` | `BSD-2-Clause OR Apache-2.0 OR MIT` | `BSD-2-Clause OR Apache-2.0 OR MIT` | SPDX |
| `zerofrom` | `0.1.8` | `registry+https://github.com/rust-lang/crates.io-index` | `Unicode-3.0` | `Unicode-3.0` | SPDX |
| `zerofrom-derive` | `0.1.7` | `registry+https://github.com/rust-lang/crates.io-index` | `Unicode-3.0` | `Unicode-3.0` | SPDX |
| `zerotrie` | `0.2.5` | `registry+https://github.com/rust-lang/crates.io-index` | `Unicode-3.0` | `Unicode-3.0` | SPDX |
| `zerovec` | `0.11.8` | `registry+https://github.com/rust-lang/crates.io-index` | `Unicode-3.0` | `Unicode-3.0` | SPDX |
| `zerovec-derive` | `0.11.6` | `registry+https://github.com/rust-lang/crates.io-index` | `Unicode-3.0` | `Unicode-3.0` | SPDX |
| `zmij` | `1.0.23` | `registry+https://github.com/rust-lang/crates.io-index` | `MIT` | `MIT` | SPDX |
