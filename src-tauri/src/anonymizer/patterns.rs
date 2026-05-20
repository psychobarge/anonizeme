use once_cell::sync::Lazy;
use regex::Regex;

pub static RE_JWT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b").unwrap()
});

pub static RE_BEARER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)Bearer\s+[A-Za-z0-9._~+/=-]{10,}").unwrap()
});

pub static RE_BASIC_AUTH: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)Basic\s+[A-Za-z0-9+/]{4,}={0,2}").unwrap()
});

pub static RE_AWS_ACCESS_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap()
});

pub static RE_AWS_SECRET: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)\b(?:aws[_-]?secret[_-]?access[_-]?key|secret[_-]?key)\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}['"]?\b"#,
    )
    .unwrap()
});

pub static RE_GITHUB_TOKEN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bgh[ps]_[A-Za-z0-9_]{36,255}\b").unwrap()
});

pub static RE_GITLAB_TOKEN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bglpat-[A-Za-z0-9_-]{20,}\b").unwrap()
});

// --- Provider-specific tokens (category SECRET) ---

pub static RE_STRIPE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[spr]k_(?:live|test)_[A-Za-z0-9]{10,}\b").unwrap()
});

pub static RE_SQUARE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bsq0[a-z]{3}-[0-9A-Za-z_-]{22,}\b").unwrap()
});

pub static RE_PAYPAL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\baccess_token\$production\$[A-Za-z0-9]{16,}\b").unwrap()
});

pub static RE_SLACK: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bxox[bpsa]-[A-Za-z0-9._-]{10,}\b").unwrap()
});

pub static RE_SENDGRID: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bSG\.[A-Za-z0-9_-]{20,}\b").unwrap()
});

pub static RE_TWILIO: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:SK|AC)[0-9a-fA-F]{32}\b").unwrap()
});

pub static RE_MAILGUN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bkey-[0-9a-zA-Z]{32}\b").unwrap()
});

pub static RE_DISCORD: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}\b").unwrap()
});

pub static RE_GOOGLE_CLOUD: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bAIza[0-9A-Za-z_-]{35}\b").unwrap()
});

pub static RE_DIGITALOCEAN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bdop_v1_[a-f0-9]{64}\b").unwrap()
});

pub static RE_HASHICORP_VAULT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bhvs\.[A-Za-z0-9_-]{24,}\b").unwrap()
});

pub static RE_SUPABASE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bsbp_[a-f0-9]{40}\b").unwrap()
});

pub static RE_VERCEL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bvercel_[A-Za-z0-9_-]{24,}\b").unwrap()
});

pub static RE_DOPPLER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bdp\.st\.[A-Za-z0-9_-]{40,}\b").unwrap()
});

pub static RE_CLOUDFLARE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bv1\.0-[a-f0-9]{24}-[a-f0-9]{64,}\b").unwrap()
});

pub static RE_NPM: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bnpm_[A-Za-z0-9]{10,}\b").unwrap()
});

pub static RE_OPENAI: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bsk-[A-Za-z0-9]{20,}\b").unwrap()
});

pub static RE_SHOPIFY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32,}\b").unwrap()
});

pub static RE_NEW_RELIC: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bNRAK-[A-Z0-9]{27}\b").unwrap()
});

pub static RE_SENTRY_DSN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"https://[a-f0-9]{16,}@[^\s"'<>]+\.sentry\.io[^\s"'<>]*"#).unwrap()
});

pub static RE_PEM_BLOCK: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?s)-----BEGIN\s(?:RSA\s|EC\s|DSA\s|ENCRYPTED\s)?(?:PRIVATE\sKEY|CERTIFICATE|PUBLIC\sKEY)-----.*?-----END\s(?:RSA\s|EC\s|DSA\s|ENCRYPTED\s)?(?:PRIVATE\sKEY|CERTIFICATE|PUBLIC\sKEY)-----",
    )
    .unwrap()
});

pub static RE_GENERIC_SECRET: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)\b(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|password|passwd|passphrase|secret[_-]?key|webhook[_-]?(?:token|secret)|encryption[_-]?key|signing[_-]?key|master[_-]?key|database[_-]?password|db[_-]?pass(?:word)?|smtp[_-]?pass(?:word)?|redis[_-]?pass(?:word)?)\s*[=:]\s*['"]?[A-Za-z0-9._~+/=%&!@#$^*-]{4,}['"]?\b"#,
    )
    .unwrap()
});

pub static RE_URL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:https?|postgres|postgresql|mysql|mongodb|redis|mariadb|amqp|doctrine|smtp|smtps|ftp|ftps|ldap|ldaps|ssh|s3)://[^\s"'<>]+"#,
    )
    .unwrap()
});

/// Infobip-style and similar hyphenated API keys (e.g. d1e17...-c6745a-...)
pub static RE_HYPHENATED_API_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[a-f0-9]{8,}(?:-[a-f0-9]{4,}){2,}\b").unwrap()
});

pub static RE_CONNECTION_STRING: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:Server|Data\sSource|Host)\s*=\s*[^;]+;[^;]*(?:Password|Pwd)\s*=\s*[^;]+"#,
    )
    .unwrap()
});

pub static RE_DSN_ODBC: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:DSN|DRIVER)=[^;]+(?:;[^;=]+=?[^;]*)*").unwrap()
});

pub static RE_EMAIL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap()
});

pub static RE_UUID: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
    )
    .unwrap()
});

pub static RE_IPV4: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    )
    .unwrap()
});

pub static RE_IPV6: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b",
    )
    .unwrap()
});

pub static RE_PHONE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?x)
        \b
        (?:
          \+\d{1,3}[\s.-]?
        )?
        (?:
          \(?\d{2,4}\)?[\s.-]?
        )?
        \d{2,4}[\s.-]?\d{2,4}[\s.-]?\d{2,4}
        \b
        ",
    )
    .unwrap()
});

pub static RE_IBAN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[A-Z]{2}\d{2}\s?(?:\d{4}\s?){2,7}\d{1,4}\b").unwrap()
});

pub static RE_CREDIT_CARD: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
    )
    .unwrap()
});

pub static RE_FRENCH_SSN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[12]\s?\d{2}\s?(?:0[1-9]|1[0-2])\s?\d{2}\s?\d{3}\s?\d{3}\s?\d{2}\b").unwrap()
});

pub static RE_MAC_ADDRESS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b").unwrap()
});

pub static RE_HEX_LONG: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[0-9a-fA-F]{16,}\b").unwrap()
});

pub static RE_BASE64_LONG: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[A-Za-z0-9+/]{40,}={0,2}\b").unwrap()
});

pub static RE_HOSTNAME: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?){2,}\b",
    )
    .unwrap()
});

pub static RE_UNIX_PATH: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(/(?:[\w.\-~]+/)+[\w.\-~]+)"#).unwrap()
});

pub static RE_WINDOWS_PATH: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[A-Za-z]:\\(?:[^\\/\s]+\\)*[^\\/\s]+\b").unwrap()
});

pub static RE_PLACEHOLDER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"<[A-Z][A-Z0-9_]*_\d+>|<REDACTED>").unwrap()
});

pub const FILE_EXTENSIONS: &[&str] = &[
    ".js", ".ts", ".tsx", ".jsx", ".css", ".json", ".html", ".xml", ".yaml", ".yml", ".md",
    ".txt", ".env", ".rs", ".go", ".py", ".java", ".kt", ".swift", ".png", ".jpg", ".svg",
    ".ico", ".woff", ".woff2", ".map", ".lock", ".toml",
];

pub const SENSITIVE_KEY_SEGMENTS: &[&str] = &[
    "SECRET", "KEY", "TOKEN", "PASSWORD", "PASSWD", "PASSPHRASE", "CREDENTIAL", "DSN", "HASH",
    "SALT", "PRIVATE",
];
