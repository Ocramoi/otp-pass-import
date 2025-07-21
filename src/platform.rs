use std::{path::PathBuf, process::Command};

use dotenv::dotenv;
use once_cell::sync::Lazy;
use shellexpand::path::tilde;

const DPASS_STORE_PATH: &str = "~/.password-store";
const DPASS_STORE_PATH_ENV: &str = "PASSWORD_STORE_DIR";

pub static P: Lazy<Platform> = Lazy::new(|| Platform::default());

pub struct Platform {
    pass_store_path: String,
}

impl Default for Platform {
    fn default() -> Self {
        Platform::new()
    }
}

impl Platform {
    fn new() -> Self {
        dotenv().ok();

        if cfg!(target_os = "windows") {
            eprintln!("Windows is not supported yet.");
            std::process::exit(1);
        }

        if Command::new("pass")
            .arg("help")
            .output()
            .is_err()
        {
            eprintln!("`pass` command not found. Please install `pass` to use this tool.");
            std::process::exit(1);
        }

        if Command::new("pass")
            .arg("otp")
            .arg("help")
            .output()
            .is_err()
        {
            eprintln!("`pass otp` command not found. Please install the `otp` pass extension to use this tool.");
            std::process::exit(1);
        }

        let pass_store_path = std::env::var(DPASS_STORE_PATH_ENV)
            .unwrap_or_else(|_| DPASS_STORE_PATH.to_string());

        Platform { pass_store_path }
    }

    pub fn default_store_path(&self) -> PathBuf {
        tilde(&self.pass_store_path).into_owned()
    }

    pub fn check_otp_uri(&self, uri: &str) -> bool {
        if uri.is_empty() { return false; }

        Command::new("pass")
            .arg("otp")
            .arg("validate")
            .arg(url_escape::encode_fragment(uri).into_owned())
            .output()
            .is_ok()
    }
}
