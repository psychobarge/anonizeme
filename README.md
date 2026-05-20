# Anon-ize-me

Application macOS légère (Tauri v2) pour anonymiser des fichiers texte et `.env`.

## Fonctionnalités

- Glisser-déposer ou sélection de fichier `.txt` / `.env`
- Anonymisation locale (aucune donnée envoyée sur le réseau)
- Détection : JWT, secrets, URLs, emails, UUIDs, IPs, téléphones, hostnames, chemins
- Placeholders cohérents (`<EMAIL_1>` réutilisé pour la même valeur)
- Bouton copier vers le presse-papier

## Prérequis

- [Node.js](https://nodejs.org/) 18+
- [Rust](https://www.rust-lang.org/tools/install)
- Xcode Command Line Tools (macOS)

```bash
rustup target add aarch64-apple-darwin x86_64-apple-darwin
```

## Développement

```bash
npm install
npm run tauri dev
```

## Build DMG

**Architecture native** (Apple Silicon ou Intel selon la machine) :

```bash
npm run build:mac
```

Le `.dmg` est généré dans `src-tauri/target/release/bundle/dmg/`.

**Binaire universel** (Intel + Apple Silicon) — nécessite `rustup` :

```bash
rustup target add aarch64-apple-darwin x86_64-apple-darwin
npm run build:dmg
```

Le `.dmg` universel est généré dans `src-tauri/target/universal-apple-darwin/release/bundle/dmg/`.

## Contrat IPC

Une seule commande Tauri :

```rust
anonymize_text(content: String, file_type: Option<String>) -> Result<String, String>
```

Le frontend lit le fichier via la File API et envoie le contenu texte à Rust.

## Tests Rust

```bash
cd src-tauri && cargo test
```
