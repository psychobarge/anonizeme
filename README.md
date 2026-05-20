# Anon-ize-me

Lightweight macOS app (Tauri v2) for anonymizing text and `.env` files.

## Features

- Drag-and-drop or file picker for `.txt` / `.env` files
- Local anonymization (no data sent over the network)
- Detection: JWT, secrets, URLs, emails, UUIDs, IPs, phone numbers, hostnames, paths
- Consistent placeholders (same value reuses `<EMAIL_1>`, etc.)
- Copy-to-clipboard button

## Prerequisites

- [Node.js](https://nodejs.org/) 18+
- [Rust](https://www.rust-lang.org/tools/install)
- Xcode Command Line Tools (macOS)

```bash
rustup target add aarch64-apple-darwin x86_64-apple-darwin
```

## Development

```bash
npm install
npm run tauri dev
```

## Building a DMG

**Native architecture** (Apple Silicon or Intel, depending on your machine):

```bash
npm run build:mac
```

The `.dmg` is generated in `src-tauri/target/release/bundle/dmg/`.

**Universal binary** (Intel + Apple Silicon) — requires `rustup`:

```bash
rustup target add aarch64-apple-darwin x86_64-apple-darwin
npm run build:dmg
```

The universal `.dmg` is generated in `src-tauri/target/universal-apple-darwin/release/bundle/dmg/`.

## IPC contract

Single Tauri command:

```rust
anonymize_text(content: String, file_type: Option<String>) -> Result<String, String>
```

The frontend reads the file via the File API and sends the text content to Rust.

## Rust tests

```bash
cd src-tauri && cargo test
```

## CI / Releases

| Workflow | Trigger | Action |
|----------|---------|--------|
| [Test](.github/workflows/test.yml) | push / PR on `develop` | `npm run build` + `cargo test` |
| [Release](.github/workflows/release.yml) | push on `main` | DMG universel + GitHub Release `v{version}` |

Before merging to `main`, bump the version (`package.json`, `Cargo.toml`, `tauri.conf.json`) so each release gets a new tag. Re-pushing the same version updates the existing release assets.
