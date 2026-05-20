use regex::Regex;
use std::collections::HashMap;

use super::patterns::{self, FILE_EXTENSIONS};

pub struct ReplacerState {
    value_to_placeholder: HashMap<String, String>,
    category_counters: HashMap<String, u32>,
}

impl ReplacerState {
    pub fn new() -> Self {
        Self {
            value_to_placeholder: HashMap::new(),
            category_counters: HashMap::new(),
        }
    }

    pub fn placeholder_for(&mut self, value: &str, category: &str) -> String {
        if is_placeholder(value) {
            return value.to_string();
        }

        let key = format!("{category}:{value}");
        if let Some(existing) = self.value_to_placeholder.get(&key) {
            return existing.clone();
        }

        let counter = self.category_counters.entry(category.to_string()).or_insert(0);
        *counter += 1;
        let placeholder = format!("<{category}_{counter}>");
        self.value_to_placeholder
            .insert(key, placeholder.clone());
        placeholder
    }
}

pub fn is_placeholder(value: &str) -> bool {
    patterns::RE_PLACEHOLDER.is_match(value) || value == "<REDACTED>"
}

pub fn apply_pattern(text: &str, re: &Regex, category: &str, state: &mut ReplacerState) -> String {
    let mut result = String::with_capacity(text.len());
    let mut last = 0usize;

    for mat in re.find_iter(text) {
        let matched = mat.as_str();
        if is_placeholder(matched) {
            continue;
        }

        result.push_str(&text[last..mat.start()]);
        result.push_str(&state.placeholder_for(matched, category));
        last = mat.end();
    }

    result.push_str(&text[last..]);
    result
}

pub fn should_skip_hostname(host: &str) -> bool {
    let lower = host.to_lowercase();
    if FILE_EXTENSIONS.iter().any(|ext| lower.ends_with(ext)) {
        return true;
    }

    // Skip dotted numeric sequences (e.g. 1.2.3) mistaken for hostnames
    host.split('.')
        .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
}

fn is_path_boundary(text: &str, start: usize) -> bool {
    if start == 0 {
        return true;
    }
    let prev = text.as_bytes()[start - 1];
    !prev.is_ascii_alphanumeric()
}

pub fn apply_unix_path_pattern(text: &str, state: &mut ReplacerState) -> String {
    let re = &patterns::RE_UNIX_PATH;
    let mut result = String::with_capacity(text.len());
    let mut last = 0usize;

    for mat in re.find_iter(text) {
        let matched = mat.as_str();
        if !is_path_boundary(text, mat.start()) || is_placeholder(matched) {
            continue;
        }

        result.push_str(&text[last..mat.start()]);
        result.push_str(&state.placeholder_for(matched, "PATH"));
        last = mat.end();
    }

    result.push_str(&text[last..]);
    result
}

pub fn apply_hostname_pattern(text: &str, state: &mut ReplacerState) -> String {
    let re = &patterns::RE_HOSTNAME;
    let mut result = String::with_capacity(text.len());
    let mut last = 0usize;

    for mat in re.find_iter(text) {
        let matched = mat.as_str();
        if is_placeholder(matched) || should_skip_hostname(matched) {
            continue;
        }

        result.push_str(&text[last..mat.start()]);
        result.push_str(&state.placeholder_for(matched, "HOST"));
        last = mat.end();
    }

    result.push_str(&text[last..]);
    result
}

fn looks_like_credit_card(num: &str) -> bool {
    patterns::RE_CREDIT_CARD.is_match(num)
}

pub fn apply_phone_pattern(text: &str, state: &mut ReplacerState) -> String {
    let re = &patterns::RE_PHONE;
    let mut result = String::with_capacity(text.len());
    let mut last = 0usize;

    for mat in re.find_iter(text) {
        let matched = mat.as_str();
        if is_placeholder(matched)
            || looks_like_credit_card(matched)
            || patterns::RE_IBAN.is_match(matched)
        {
            continue;
        }

        result.push_str(&text[last..mat.start()]);
        result.push_str(&state.placeholder_for(matched, "PHONE"));
        last = mat.end();
    }

    result.push_str(&text[last..]);
    result
}

fn luhn_valid(card: &str) -> bool {
    let digits: Vec<u32> = card
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                d
            }
        })
        .sum();
    sum % 10 == 0
}

pub fn apply_credit_card_pattern(text: &str, state: &mut ReplacerState) -> String {
    let re = &patterns::RE_CREDIT_CARD;
    let mut result = String::with_capacity(text.len());
    let mut last = 0usize;

    for mat in re.find_iter(text) {
        let matched = mat.as_str();
        if is_placeholder(matched) || !luhn_valid(matched) {
            continue;
        }

        result.push_str(&text[last..mat.start()]);
        result.push_str(&state.placeholder_for(matched, "CREDIT_CARD"));
        last = mat.end();
    }

    result.push_str(&text[last..]);
    result
}
