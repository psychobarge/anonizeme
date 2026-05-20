mod patterns;
mod replacer;

use patterns::{
    SENSITIVE_KEY_SEGMENTS, RE_AWS_ACCESS_KEY, RE_AWS_SECRET, RE_BASE64_LONG, RE_BASIC_AUTH,
    RE_BEARER, RE_CLOUDFLARE, RE_CONNECTION_STRING, RE_DIGITALOCEAN, RE_DISCORD, RE_DOPPLER,
    RE_DSN_ODBC, RE_EMAIL, RE_FRENCH_SSN, RE_GENERIC_SECRET, RE_GITHUB_TOKEN, RE_GITLAB_TOKEN,
    RE_GOOGLE_CLOUD, RE_HASHICORP_VAULT, RE_HEX_LONG, RE_HYPHENATED_API_KEY, RE_IBAN, RE_IPV4,
    RE_IPV6, RE_JWT, RE_MAC_ADDRESS, RE_MAILGUN, RE_NEW_RELIC, RE_NPM, RE_OPENAI, RE_PAYPAL,
    RE_PEM_BLOCK, RE_PLACEHOLDER, RE_SENDGRID, RE_SENTRY_DSN, RE_SHOPIFY, RE_SLACK, RE_SQUARE,
    RE_STRIPE, RE_SUPABASE, RE_TWILIO, RE_URL, RE_UUID, RE_VERCEL, RE_WINDOWS_PATH,
};
use replacer::{
    apply_credit_card_pattern, apply_hostname_pattern, apply_pattern, apply_phone_pattern,
    apply_unix_path_pattern, is_placeholder, ReplacerState,
};

pub fn anonymize(content: &str, file_type: Option<&str>) -> Result<String, String> {
    if content.trim().is_empty() {
        return Err("Content is empty".to_string());
    }

    if matches!(file_type, Some("env")) || should_use_env_mode(content, file_type) {
        Ok(anonymize_env(content))
    } else {
        Ok(anonymize_plain(content))
    }
}

fn should_use_env_mode(content: &str, file_type: Option<&str>) -> bool {
    if matches!(file_type, Some("txt") | None) {
        return looks_like_env_file(content);
    }
    false
}

fn looks_like_env_file(content: &str) -> bool {
    let mut env_lines = 0u32;
    let mut total = 0u32;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('#') {
            let after = trimmed.trim_start_matches('#').trim_start();
            if let Some((key, _)) = split_key_value(after) {
                if is_env_key_name(key) {
                    env_lines += 1;
                }
            }
            continue;
        }
        total += 1;
        if let Some((key, _)) = split_key_value(trimmed) {
            if is_env_key_name(key) {
                env_lines += 1;
            }
        }
    }
    total > 0 && env_lines * 2 >= total
}

fn anonymize_plain(content: &str) -> String {
    let mut state = ReplacerState::new();
    anonymize_plain_with_state(content, &mut state)
}

fn anonymize_plain_with_state(content: &str, state: &mut ReplacerState) -> String {
    let mut text = content.to_string();

    // Auth tokens
    text = apply_pattern(&text, &RE_JWT, "JWT", state);
    text = apply_pattern(&text, &RE_BEARER, "SECRET", state);
    text = apply_pattern(&text, &RE_BASIC_AUTH, "SECRET", state);

    // Cloud / infra keys
    text = apply_pattern(&text, &RE_AWS_ACCESS_KEY, "AWS_KEY", state);
    text = apply_pattern(&text, &RE_AWS_SECRET, "AWS_SECRET", state);
    text = apply_pattern(&text, &RE_GITHUB_TOKEN, "SECRET", state);
    text = apply_pattern(&text, &RE_GITLAB_TOKEN, "SECRET", state);

    // Provider-specific tokens
    text = apply_pattern(&text, &RE_STRIPE, "SECRET", state);
    text = apply_pattern(&text, &RE_SQUARE, "SECRET", state);
    text = apply_pattern(&text, &RE_PAYPAL, "SECRET", state);
    text = apply_pattern(&text, &RE_SLACK, "SECRET", state);
    text = apply_pattern(&text, &RE_SENDGRID, "SECRET", state);
    text = apply_pattern(&text, &RE_TWILIO, "SECRET", state);
    text = apply_pattern(&text, &RE_MAILGUN, "SECRET", state);
    text = apply_pattern(&text, &RE_DISCORD, "SECRET", state);
    text = apply_pattern(&text, &RE_GOOGLE_CLOUD, "SECRET", state);
    text = apply_pattern(&text, &RE_DIGITALOCEAN, "SECRET", state);
    text = apply_pattern(&text, &RE_HASHICORP_VAULT, "SECRET", state);
    text = apply_pattern(&text, &RE_SUPABASE, "SECRET", state);
    text = apply_pattern(&text, &RE_VERCEL, "SECRET", state);
    text = apply_pattern(&text, &RE_DOPPLER, "SECRET", state);
    text = apply_pattern(&text, &RE_CLOUDFLARE, "SECRET", state);
    text = apply_pattern(&text, &RE_NPM, "SECRET", state);
    text = apply_pattern(&text, &RE_OPENAI, "SECRET", state);
    text = apply_pattern(&text, &RE_SHOPIFY, "SECRET", state);
    text = apply_pattern(&text, &RE_NEW_RELIC, "SECRET", state);
    text = apply_pattern(&text, &RE_SENTRY_DSN, "SECRET", state);
    text = apply_pattern(&text, &RE_HYPHENATED_API_KEY, "SECRET", state);

    // PEM blocks (multiline)
    text = apply_pattern(&text, &RE_PEM_BLOCK, "SECRET", state);

    // Generic key=value secrets
    text = apply_pattern(&text, &RE_GENERIC_SECRET, "SECRET", state);

    // URLs and connection strings
    text = apply_pattern(&text, &RE_URL, "URL", state);
    text = apply_pattern(&text, &RE_CONNECTION_STRING, "SECRET", state);
    text = apply_pattern(&text, &RE_DSN_ODBC, "SECRET", state);

    // PII
    text = apply_pattern(&text, &RE_EMAIL, "EMAIL", state);
    text = apply_pattern(&text, &RE_UUID, "UUID", state);
    text = apply_pattern(&text, &RE_IPV4, "IP", state);
    text = apply_pattern(&text, &RE_IPV6, "IP", state);
    // IBAN / cards / SSN before PHONE to avoid partial phone matches on digit sequences
    text = apply_pattern(&text, &RE_IBAN, "IBAN", state);
    text = apply_credit_card_pattern(&text, state);
    text = apply_pattern(&text, &RE_FRENCH_SSN, "SSN", state);
    text = apply_phone_pattern(&text, state);
    text = apply_pattern(&text, &RE_MAC_ADDRESS, "MAC", state);

    // Probabilistic / heuristic patterns (after specific ones)
    text = apply_pattern(&text, &RE_HEX_LONG, "SECRET", state);
    text = apply_pattern(&text, &RE_BASE64_LONG, "SECRET", state);

    // Hostnames and paths
    text = apply_hostname_pattern(&text, state);
    text = apply_unix_path_pattern(&text, state);
    text = apply_pattern(&text, &RE_WINDOWS_PATH, "PATH", state);

    text
}

fn anonymize_env(content: &str) -> String {
    let mut state = ReplacerState::new();
    let mut output = content
        .lines()
        .map(|line| anonymize_env_line(line, &mut state))
        .collect::<Vec<_>>()
        .join("\n");

    if content.ends_with('\n') {
        output.push('\n');
    }

    output
}

fn anonymize_env_line(line: &str, state: &mut ReplacerState) -> String {
    let trimmed = line.trim_start();

    if trimmed.is_empty() {
        return line.to_string();
    }

    if trimmed.starts_with('#') {
        return anonymize_commented_env_line(line, trimmed, state);
    }

    let (body, inline_comment) = split_inline_comment(line);
    let (export_prefix, key_value) = split_export_prefix(body);

    let Some((key, raw_value)) = split_key_value(key_value) else {
        return anonymize_plain_with_state(line, state);
    };

    if raw_value.is_empty() {
        return format!("{export_prefix}{key}={inline_comment}");
    }

    let (quote, value_body) = strip_quotes(raw_value);
    let anonymized_value = anonymize_env_value(value_body, key, state);
    let wrapped = wrap_with_quotes(&anonymized_value, quote);

    format!("{export_prefix}{key}={wrapped}{inline_comment}")
}

fn anonymize_commented_env_line(line: &str, trimmed: &str, state: &mut ReplacerState) -> String {
    let after_hash = trimmed.trim_start_matches('#').trim_start();
    if after_hash.is_empty() {
        return line.to_string();
    }

    let Some((key, _)) = split_key_value(after_hash) else {
        return line.to_string();
    };

    if !is_env_key_name(key) {
        return line.to_string();
    }

    let hash_pos = line.find('#').unwrap_or(0);
    let after_hash_raw = &line[hash_pos + 1..];
    let leading_ws = after_hash_raw.len() - after_hash_raw.trim_start().len();
    let prefix = &line[..hash_pos + 1 + leading_ws];
    let kv = after_hash_raw.trim_start();

    format!("{prefix}{}", anonymize_env_kv(kv, state))
}

fn anonymize_env_kv(kv: &str, state: &mut ReplacerState) -> String {
    let Some((key, raw_value)) = split_key_value(kv) else {
        return anonymize_plain_with_state(kv, state);
    };

    if raw_value.is_empty() {
        return format!("{key}=");
    }

    let (quote, value_body) = strip_quotes(raw_value);
    let anonymized_value = anonymize_env_value(value_body, key, state);
    let wrapped = wrap_with_quotes(&anonymized_value, quote);
    format!("{key}={wrapped}")
}

fn is_env_key_name(key: &str) -> bool {
    !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit())
}

fn is_sensitive_key(key: &str) -> bool {
    key.to_uppercase()
        .split('_')
        .any(|seg| SENSITIVE_KEY_SEGMENTS.contains(&seg))
}

fn split_inline_comment(line: &str) -> (&str, &str) {
    let mut in_single = false;
    let mut in_double = false;
    let bytes = line.as_bytes();

    for (idx, &byte) in bytes.iter().enumerate() {
        match byte {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b'#' if !in_single && !in_double => {
                let (body, comment) = line.split_at(idx);
                return (body, comment);
            }
            _ => {}
        }
    }

    (line, "")
}

fn split_export_prefix(line: &str) -> (&str, &str) {
    let trimmed = line.trim_start();
    if trimmed.starts_with("export ") {
        let leading_ws = line.len() - trimmed.len();
        let export_end = leading_ws + "export ".len();
        (&line[..export_end], &line[export_end..])
    } else {
        ("", line)
    }
}

fn split_key_value(line: &str) -> Option<(&str, &str)> {
    let eq_idx = line.find('=')?;
    let key = line[..eq_idx].trim_end();
    let value = line[eq_idx + 1..].trim_start();
    if key.is_empty() {
        return None;
    }
    Some((key, value))
}

fn strip_quotes(value: &str) -> (Option<char>, &str) {
    if value.len() >= 2 {
        let first = value.chars().next().unwrap();
        let last = value.chars().last().unwrap();
        if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
            let inner = &value[1..value.len() - 1];
            return (Some(first), inner);
        }
    }
    (None, value)
}

fn wrap_with_quotes(value: &str, quote: Option<char>) -> String {
    match quote {
        Some(q) => format!("{q}{value}{q}"),
        None => value.to_string(),
    }
}

fn anonymize_env_value(value: &str, key: &str, state: &mut ReplacerState) -> String {
    if is_placeholder(value) || value == "<REDACTED>" {
        return value.to_string();
    }

    let anonymized = anonymize_plain_with_state(value, state);

    if is_sensitive_key(key) {
        if is_value_fully_anonymized(&anonymized) {
            return anonymized;
        }
        return "<REDACTED>".to_string();
    }

    if anonymized != value {
        return anonymized;
    }

    if looks_sensitive(value) {
        "<REDACTED>".to_string()
    } else {
        value.to_string()
    }
}

fn is_value_fully_anonymized(s: &str) -> bool {
    if s == "<REDACTED>" {
        return true;
    }

    let mut remaining = s.to_string();
    for mat in RE_PLACEHOLDER.find_iter(s) {
        remaining = remaining.replace(mat.as_str(), "");
    }
    let remaining = remaining.trim_matches(|c: char| c.is_whitespace() || c == '"' || c == '\'');

    if remaining.is_empty() {
        return true;
    }

    !looks_sensitive(remaining)
}

fn shannon_entropy(s: &str) -> f64 {
    let len = s.len() as f64;
    if len == 0.0 {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in s.as_bytes() {
        freq[b as usize] += 1;
    }
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn looks_sensitive(value: &str) -> bool {
    if value.len() < 4 {
        return false;
    }

    // Pure hex >= 16 chars: almost certainly a secret
    if value.len() >= 16 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }

    // High entropy: likely a secret
    let entropy = shannon_entropy(value);
    let threshold = if value.len() >= 20 { 3.0 } else { 3.5 };
    if entropy >= threshold && value.len() >= 8 {
        return true;
    }

    let has_letter = value.chars().any(|c| c.is_alphabetic());
    let has_digit = value.chars().any(|c| c.is_numeric());
    let has_symbol = value.chars().any(|c| !c.is_alphanumeric() && !c.is_whitespace());

    if value.len() >= 6 && has_letter && has_digit && has_symbol {
        return true;
    }

    value.len() >= 6 && has_letter && has_digit
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn placeholder_detection() {
        assert!(is_placeholder("<EMAIL_1>"));
        assert!(is_placeholder("<REDACTED>"));
        assert!(!is_placeholder("user@test.com"));
    }

    #[test]
    fn sensitive_key_detection() {
        assert!(is_sensitive_key("APP_SECRET"));
        assert!(is_sensitive_key("STRIPE_SECRET_KEY"));
        assert!(is_sensitive_key("JWT_PASSPHRASE"));
        assert!(is_sensitive_key("INFOBIP_WEBHOOK_TOKEN"));
        assert!(!is_sensitive_key("APP_ENV"));
        assert!(!is_sensitive_key("STRIPE_ENABLED"));
    }

    #[test]
    fn entropy_distinguishes_secrets_from_words() {
        assert!(!looks_sensitive("production"));
        assert!(!looks_sensitive("apache"));
        assert!(looks_sensitive("EGCfECiH90Ss0RK6Bax8i7AM7F9jh9"));
        assert!(looks_sensitive("77b9ae11e3bbc8fb4b1b80161fdf0f"));
    }

    #[test]
    fn env_preserves_comments_and_keys() {
        let input = "# comment\nAPI_KEY=secret123\nEMPTY=\n";
        let out = anonymize(input, Some("env")).unwrap();
        assert!(out.contains("# comment"));
        assert!(out.contains("API_KEY="));
        assert!(out.contains("EMPTY="));
        assert!(!out.contains("secret123"));
    }

    #[test]
    fn env_commented_key_value_is_redacted() {
        let input = "# I_SEND_PRO_ACCESS_TOKEN=7jDaEGJWU82tHgneU3k7EJy67rpKJD\n";
        let out = anonymize(input, Some("env")).unwrap();
        assert!(out.contains("I_SEND_PRO_ACCESS_TOKEN="));
        assert!(!out.contains("7jDaEGJWU82tHgneU3k7EJy67rpKJD"));
    }
}
