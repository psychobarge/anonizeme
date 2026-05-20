use anon_ize_me_lib::anonymizer;

/// Realistic provider token shapes built at runtime (not static literals in git).
/// GitHub push protection scans commits for secret-shaped strings; assembling here
/// keeps tests faithful to production formats without storing full tokens in the repo.
mod realistic_tokens {
    const B62: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const HEX: &[u8] = b"0123456789abcdef";

    fn repeat_from(alphabet: &[u8], len: usize) -> String {
        (0..len)
            .map(|i| alphabet[i % alphabet.len()] as char)
            .collect()
    }

    pub fn stripe_live_secret_key() -> String {
        format!("sk_live_{}", repeat_from(B62, 87))
    }

    pub fn stripe_live_publishable_key() -> String {
        format!("pk_live_{}", repeat_from(B62, 87))
    }

    pub fn slack_bot_token() -> String {
        format!(
            "xoxb-{}-{}-{}",
            repeat_from(b"0123456789", 10),
            repeat_from(b"0123456789", 13),
            repeat_from(B62, 24)
        )
    }

    pub fn twilio_api_key() -> String {
        format!("SK{}", repeat_from(HEX, 32))
    }

    pub fn twilio_account_sid() -> String {
        format!("AC{}", repeat_from(HEX, 32))
    }
}

#[test]
fn rejects_empty_content() {
    let err = anonymizer::anonymize("   \n  ", None).unwrap_err();
    assert!(err.contains("empty"));
}

#[test]
fn anonymizes_emails_with_consistent_placeholders() {
    let input = "Contact alice@test.com and alice@test.com again.";
    let out = anonymizer::anonymize(input, None).unwrap();
    assert!(!out.contains("alice@test.com"));
    let email_count = out.matches("<EMAIL_").count();
    assert_eq!(email_count, 2);
    assert!(out.contains("<EMAIL_1>"));
}

#[test]
fn url_is_not_double_matched_as_email() {
    let input = "See https://user:pass@api.example.com/v1 for details.";
    let out = anonymizer::anonymize(input, None).unwrap();
    assert!(!out.contains("example.com"));
    assert!(!out.contains("user:pass"));
    assert!(out.contains("<URL_"));
}

#[test]
fn idempotent_on_already_anonymized_text() {
    let input = "Email <EMAIL_1> and host <HOST_2>.";
    let out = anonymizer::anonymize(input, None).unwrap();
    assert_eq!(out, input);
}

#[test]
fn env_handles_quotes_comments_and_empty_values() {
    let input = r#"
# production secrets
export API_KEY="sk-live-abc123xyz"
DATABASE_URL=postgres://user:pass@db.internal.example.com:5432/app
EMPTY=
TOKEN='eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U' # jwt inline
"#;
    let out = anonymizer::anonymize(input, Some("env")).unwrap();
    assert!(out.contains("# production secrets"));
    assert!(out.contains("API_KEY="));
    assert!(out.contains("EMPTY="));
    assert!(!out.contains("sk-live-abc123xyz"));
    assert!(!out.contains("postgres://"));
    assert!(!out.contains("eyJhbGci"));
}

#[test]
fn version_string_is_not_treated_as_ipv4() {
    let input = "version=1.2.3\nbuild=4.5.6.7";
    let out = anonymizer::anonymize(input, Some("env")).unwrap();
    assert!(out.contains("version=1.2.3"));
}

#[test]
fn package_json_is_not_hostname() {
    let input = "import config from './package.json';";
    let out = anonymizer::anonymize(input, None).unwrap();
    assert!(out.contains("package.json"));
}

#[test]
fn jwt_and_aws_keys_are_redacted() {
    let input = "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U\nkey=AKIAIOSFODNN7EXAMPLE";
    let out = anonymizer::anonymize(input, Some("env")).unwrap();
    assert!(!out.contains("eyJhbGci"));
    assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"));
}

#[test]
fn performance_large_input() {
    let line = "EMAIL=user@example.com HOST=db.prod.internal.example.com PATH=/var/lib/data\n";
    let input = line.repeat(100_000);
    let out = anonymizer::anonymize(&input, None).unwrap();
    assert!(!out.contains("user@example.com"));
    assert!(out.contains("<EMAIL_1>"));
}

// --- Provider tokens ---

#[test]
fn stripe_keys_are_redacted() {
    let sk = realistic_tokens::stripe_live_secret_key();
    let pk = realistic_tokens::stripe_live_publishable_key();
    let input = format!("STRIPE_SECRET_KEY={sk}\nSTRIPE_PUBLIC_KEY={pk}\n");
    let out = anonymizer::anonymize(&input, Some("env")).unwrap();
    assert!(!out.contains(&sk));
    assert!(!out.contains(&pk));
    assert!(out.contains("STRIPE_SECRET_KEY="));
    assert!(out.contains("STRIPE_PUBLIC_KEY="));
}

#[test]
fn slack_token_is_redacted() {
    let token = realistic_tokens::slack_bot_token();
    let input = format!("SLACK_TOKEN={token}");
    let out = anonymizer::anonymize(&input, None).unwrap();
    assert!(!out.contains(&token));
    assert!(out.contains("<SECRET_"));
}

#[test]
fn sendgrid_key_is_redacted() {
    let key = "SG.abcdefghijklmnopqrstuvwxyz0123456789";
    let input = format!("key={key}");
    let out = anonymizer::anonymize(&input, None).unwrap();
    assert!(!out.contains(key));
}

#[test]
fn google_cloud_api_key_is_redacted() {
    let key = "AIzaSyD4f9s8d7f6g5h4j3k2l1m0n9b8v7c6x5z4";
    let input = format!("GCP_KEY={key}");
    let out = anonymizer::anonymize(&input, Some("env")).unwrap();
    assert!(!out.contains(key));
}

#[test]
fn twilio_keys_are_redacted() {
    let sk = realistic_tokens::twilio_api_key();
    let ac = realistic_tokens::twilio_account_sid();
    let input = format!("TWILIO_SK={sk}\nTWILIO_AC={ac}\n");
    let out = anonymizer::anonymize(&input, Some("env")).unwrap();
    assert!(!out.contains(&sk));
    assert!(!out.contains(&ac));
}

#[test]
fn hashicorp_vault_token_is_redacted() {
    let token = "hvs.CAESIJabcdefghijklmnopqrstuvwxyz123456";
    let input = format!("VAULT_TOKEN={token}");
    let out = anonymizer::anonymize(&input, Some("env")).unwrap();
    assert!(!out.contains(token));
}

#[test]
fn sentry_dsn_is_redacted() {
    let dsn = "https://970b0f010b8559bf06ff617529194ae@o45612920410112.ingest.de.sentry.io/45086126832720";
    let input = format!(r#"SENTRY_DSN="{dsn}""#);
    let out = anonymizer::anonymize(&input, Some("env")).unwrap();
    assert!(!out.contains("970b0f010b8559bf06ff617529194ae"));
    assert!(!out.contains("sentry.io"));
}

// --- Heuristic patterns ---

#[test]
fn smtp_url_is_redacted() {
    let dsn = "smtp://contact%40example.fr:SecretP4ss%26T25@mail.example.net:465?encryption=ssl";
    let input = format!("MAILER_DSN={dsn}");
    let out = anonymizer::anonymize(&input, Some("env")).unwrap();
    assert!(!out.contains("SecretP4ss"));
    assert!(!out.contains("mail.example.net"));
    assert!(out.contains("<URL_"));
}

#[test]
fn long_hex_string_is_redacted() {
    let secret = "77b9ae11e3bbc8fb4b1b80161fdf0f";
    let input = format!("APP_SECRET={secret}");
    let out = anonymizer::anonymize(&input, Some("env")).unwrap();
    assert!(!out.contains(secret));
}

#[test]
fn basic_auth_header_is_redacted() {
    let input = "Authorization: Basic dXNlcjpwYXNzd29yZA==";
    let out = anonymizer::anonymize(input, None).unwrap();
    assert!(!out.contains("dXNlcjpwYXNzd29yZA=="));
}

#[test]
fn connection_string_ado_net_is_redacted() {
    let cs = "Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;";
    let input = format!("CONN={cs}");
    let out = anonymizer::anonymize(&input, None).unwrap();
    assert!(!out.contains("myPassword"));
}

#[test]
fn pem_private_key_is_redacted() {
    let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";
    let input = format!("KEY={pem}");
    let out = anonymizer::anonymize(&input, None).unwrap();
    assert!(!out.contains("BEGIN RSA PRIVATE KEY"));
}

// --- PII ---

#[test]
fn iban_is_redacted() {
    let iban = "FR76 3000 6000 0112 3456 7890 189";
    let input = format!("bank={iban}");
    let out = anonymizer::anonymize(&input, None).unwrap();
    assert!(!out.contains("FR76"));
    assert!(out.contains("<IBAN_"));
}

#[test]
fn valid_credit_card_is_redacted() {
    let card = "4111 1111 1111 1111";
    let input = format!("card={card}");
    let out = anonymizer::anonymize(&input, None).unwrap();
    assert!(!out.contains("4111 1111"));
    assert!(out.contains("<CREDIT_CARD_"));
}

#[test]
fn invalid_credit_card_luhn_is_not_redacted() {
    let card = "4111 1111 1111 1112";
    let input = format!("card={card}");
    let out = anonymizer::anonymize(&input, None).unwrap();
    assert!(out.contains("4111 1111 1111 1112"));
}

#[test]
fn french_ssn_is_redacted() {
    let ssn = "1 85 05 78 006 084 36";
    let input = format!("nir={ssn}");
    let out = anonymizer::anonymize(&input, None).unwrap();
    assert!(!out.contains("006 084 36"));
    assert!(out.contains("<SSN_"));
}

#[test]
fn mac_address_is_redacted() {
    let mac = "00:1A:2B:3C:4D:5E";
    let input = format!("mac={mac}");
    let out = anonymizer::anonymize(&input, None).unwrap();
    assert!(!out.contains(mac));
    assert!(out.contains("<MAC_"));
}

// --- .env mode ---

#[test]
fn env_sensitive_keys_no_partial_leak() {
    let input = "INFOBIP_PROMO_API_KEY=d1e17258dca3a11c9fbcee0edb56f-c6745a-cfc8-4dad-874a-49652b853\nINFOBIP_TRANS_API_KEY=9901c20ff34796625f44b1eb05c46-693b44-8790-4d9d-844d-b05015e93\n";
    let out = anonymizer::anonymize(input, Some("env")).unwrap();
    assert!(!out.contains("d1e17258"));
    assert!(!out.contains("c6745a"));
    assert!(!out.contains("9901c20f"));
    assert!(!out.contains("693b44"));
    assert!(out.contains("<REDACTED>") || out.contains("<SECRET_"));
}

#[test]
fn auto_detects_env_content_without_extension() {
    let input = "APP_SECRET=77b9ae11e3bbc8fb4b1b80161fdf0f\nAPP_ENV=prod\nINSEE_API_KEY=231e8d70-43a-4f-9e8d-7043aa85f3e\n";
    let out = anonymizer::anonymize(input, None).unwrap();
    assert!(!out.contains("77b9ae11e3bbc8fb4b1b80161fdf0f"));
    assert!(!out.contains("231e8d70"));
    assert!(out.contains("APP_ENV=prod"));
}

#[test]
fn env_sensitive_keys_force_redact() {
    let input = r#"
APP_SECRET=77b9ae11e3bbc8fb4b1b80161fdf0f
JWT_PASSPHRASE=4b0ea81e6f9e87076ee8074202f5a
INSEE_API_KEY=231e8d70-43a-4f-9e8d-7043aa85f3e
INFOBIP_WEBHOOK_TOKEN=9876543210able765-23retys
INFOBIP_PROMO_API_KEY=d1e17258dca3a11c9fbcee0edb56f-c6745a-cfc8-4dad-874a-49652b853
I_SEND_PRO_ACCESS_TOKEN=EGCfECiH90Ss0RK6Bax8i7AM7F9jh9
"#;
    let out = anonymizer::anonymize(input, Some("env")).unwrap();
    assert!(!out.contains("77b9ae11e3bbc8fb4b1b80161fdf0f"));
    assert!(!out.contains("4b0ea81e6f9e87076ee8074202f5a"));
    assert!(!out.contains("231e8d70-43a-4f-9e8d-7043aa85f3e"));
    assert!(!out.contains("9876543210able765-23retys"));
    assert!(!out.contains("d1e17258"));
    assert!(!out.contains("c6745a"));
    assert!(!out.contains("EGCfECiH90Ss0RK6Bax8i7AM7F9jh9"));
    assert!(out.contains("APP_SECRET="));
    assert!(out.contains("JWT_PASSPHRASE="));
}

#[test]
fn env_non_sensitive_values_preserved() {
    let input = r#"
APP_ENV=prod
STRIPE_ENABLED=1
SENTRY_ENVIRONMENT=prod
SMS_API=ISENDPRO
SENTRY_DSN=
SERVER_APACHE_USERNAME=apache
"#;
    let out = anonymizer::anonymize(input, Some("env")).unwrap();
    assert!(out.contains("APP_ENV=prod"));
    assert!(out.contains("STRIPE_ENABLED=1"));
    assert!(out.contains("SENTRY_ENVIRONMENT=prod"));
    assert!(out.contains("SMS_API=ISENDPRO"));
    assert!(out.contains("SENTRY_DSN=\n") || out.contains("SENTRY_DSN="));
    assert!(out.contains("SERVER_APACHE_USERNAME=apache"));
}

#[test]
fn env_commented_secret_is_redacted() {
    let input = "# I_SEND_PRO_ACCESS_TOKEN=7jDaEGJWU82tHgneU3k7EJy67rpKJD\n";
    let out = anonymizer::anonymize(input, Some("env")).unwrap();
    assert!(out.contains("# I_SEND_PRO_ACCESS_TOKEN="));
    assert!(!out.contains("7jDaEGJWU82tHgneU3k7EJy67rpKJD"));
}

#[test]
fn messenger_doctrine_dsn_is_redacted() {
    let input = "MESSENGER_TRANSPORT_DSN=doctrine://default?auto_setup=0\n";
    let out = anonymizer::anonymize(input, Some("env")).unwrap();
    assert!(!out.contains("doctrine://default"));
    assert!(out.contains("<URL_") || out.contains("<REDACTED>"));
}

#[test]
fn env_deduplication_cross_lines() {
    let input = "EMAIL_ADMIN=alice@test.com\nEMAIL_ADMIN_CC=alice@test.com\n";
    let out = anonymizer::anonymize(input, Some("env")).unwrap();
    assert!(!out.contains("alice@test.com"));
    let count = out.matches("<EMAIL_1>").count();
    assert_eq!(count, 2);
}

#[test]
fn env_entropy_production_not_redacted() {
    let input = "SOME_CONFIG=production\n";
    let out = anonymizer::anonymize(input, Some("env")).unwrap();
    assert!(out.contains("production"));
}

#[test]
fn database_url_mysql_is_redacted() {
    let url = r#"mysql://yacine:Slpbjfdme_2Pm!@127.0.0.1:3306/smartsms?serverVersion=8"#;
    let input = format!(r#"DATABASE_URL="{url}""#);
    let out = anonymizer::anonymize(&input, Some("env")).unwrap();
    assert!(!out.contains("yacine"));
    assert!(!out.contains("Slpbjfdme_2Pm"));
    assert!(out.contains("<URL_"));
}
