pub mod anonymizer;

use std::path::Path;

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadTextFileResult {
    name: String,
    content: String,
}

#[tauri::command]
fn anonymize_text(content: String, file_type: Option<String>) -> Result<String, String> {
    let normalized = file_type.as_deref().map(str::trim).filter(|t| !t.is_empty());
    anonymizer::anonymize(&content, normalized)
}

#[tauri::command]
fn read_text_file(path: String) -> Result<ReadTextFileResult, String> {
    let file_path = Path::new(path.trim());
    if !file_path.is_file() {
        return Err("Le chemin ne correspond pas à un fichier.".into());
    }

    let name = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("Nom de fichier invalide.")?
        .to_string();

    let content = std::fs::read_to_string(file_path)
        .map_err(|e| format!("Impossible de lire le fichier : {e}"))?;

    Ok(ReadTextFileResult { name, content })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![anonymize_text, read_text_file])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
