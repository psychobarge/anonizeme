---
name: bump-app-version
description: >-
  OBLIGATOIRE après toute modification de code applicatif dans Anon-ize-me.
  Incrémente la version semver (package.json, Cargo.toml, tauri.conf.json) en
  fin de tâche, avant commit/PR. Toujours lire et exécuter cette skill — ne pas
  attendre que l'utilisateur le demande. Déclenché aussi par la règle projet
  .cursor/rules/bump-app-version.mdc (alwaysApply).
---

# Montée de version (Anon-ize-me)

## Obligation agent (à chaque session)

**Tu dois exécuter cette skill** dès que tu as modifié du code applicatif, **sans attendre** une demande explicite de l'utilisateur.

| Moment | Action |
|--------|--------|
| Fin de tâche d'implémentation | Lire cette skill → choisir patch/minor/major → exécuter le script → vérifier les 3 fichiers |
| Avant commit ou PR | Version déjà bumpée et incluse dans les changements |
| Question / review seule | Ne pas bump si aucun fichier applicatif n'a été modifié |

La règle `.cursor/rules/bump-app-version.mdc` (`alwaysApply: true`) rappelle cette obligation dans chaque conversation Cursor sur ce projet.

**Checklist de fin de tâche** (ne pas marquer la tâche terminée tant que ce n'est pas fait) :

- [ ] Au moins un fichier hors `dist/`, `node_modules/`, `src-tauri/target/` a été modifié ?
- [ ] Si oui : version bumpée dans `package.json`, `src-tauri/Cargo.toml`, `src-tauri/tauri.conf.json`
- [ ] Si non (docs seules, version seule, etc.) : pas de bump

## Quand incrémenter

À la **fin** de toute tâche où l'agent modifie le code applicatif (hors demande explicite de ne pas toucher la version) :

| Type de changement | Bump |
|--------------------|------|
| `fix`, correctif, régression | `patch` |
| `refactor`, `style`, `perf`, `test`, `docs`, `chore` (comportement inchangé ou mineur) | `patch` |
| `feat`, nouvelle capacité utilisateur | `minor` |
| rupture de compatibilité, suppression d'API publique | `major` |

Ne pas incrémenter si la session ne modifie **que** la version, le README sans code, ou des fichiers générés (`dist/`, `src-tauri/target/`, `node_modules/`).

## Fichiers à garder synchronisés

Les trois sources doivent toujours afficher la **même** version :

1. `package.json` → champ `version`
2. `src-tauri/Cargo.toml` → `version = "…"`
3. `src-tauri/tauri.conf.json` → `"version"`

L'UI lit la version via `getVersion()` (Tauri) depuis `tauri.conf.json` — ne pas dupliquer la version dans `src/main.ts`.

## Procédure

1. Lire la version actuelle : `node -p "require('./package.json').version"`.
2. Choisir `patch`, `minor` ou `major` selon le tableau ci-dessus.
3. Exécuter depuis la racine du dépôt :

```bash
chmod +x .cursor/skills/bump-app-version/scripts/bump-version.sh
.cursor/skills/bump-app-version/scripts/bump-version.sh patch   # ou minor / major
```

4. Vérifier l'alignement :

```bash
node -p "require('./package.json').version"
grep '^version' src-tauri/Cargo.toml
node -p "require('./src-tauri/tauri.conf.json').version"
```

5. Inclure les trois fichiers dans le même commit que les changements fonctionnels (ou commit dédié `chore: bump version to x.y.z` si l'utilisateur le demande).

## Sans script

Si le script échoue, mettre à jour manuellement les trois fichiers avec la même valeur semver `MAJOR.MINOR.PATCH`.

## Exemples

- Correction du filtre email → `bump-version.sh patch` (ex. `0.1.0` → `0.1.1`).
- Ajustement UI (hauteur drop-zone) → `bump-version.sh patch`.
- Ajout du support d'un nouveau format de fichier → `bump-version.sh minor` (ex. `0.1.1` → `0.2.0`).
- Suppression d'une commande Tauri exposée au frontend → `bump-version.sh major`.
