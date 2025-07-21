use clap::Parser;
use dotenv::dotenv;
use otp::OTPs;
use pass::Pass;

pub mod platform;
pub mod otp;
pub mod pass;

#[derive(Parser)]
#[command(version, author, about, long_about)]
/// A command-line interface for importing OTP pass entries. Based on `extract-otp-secrets` (https://github.com/scito/extract_otp_secrets) and `pass` (http://www.passwordstore.org/).
struct CliInterface {
    /// Path to the generated OTP list file.
    #[arg(value_hint = clap::ValueHint::FilePath)]
    path: std::path::PathBuf,

    /// Path to the pass store.
    /// If not specified, the default pass-store directory will be assumed [$PASSWORD_STORE_DIR, ~/.password-store]
    #[arg(short='s', long, value_name = "PATH", value_hint = clap::ValueHint::DirPath)]
    pass_store_path: Option<std::path::PathBuf>,

    /// Whether to update the pass store afterwards.
    #[arg(short, long)]
    update_pass_store: bool,

    /// List entries and quit.
    #[arg(long, short)]
    list: bool,
}

fn main() {
    use otp::New;

    // Load environment variables from .env file
    if dotenv().is_err() {
        eprintln!("Warning: Could not load env variables.");
        std::process::exit(1);
    }

    let cli = CliInterface::parse();
    let mut pass = match Pass::new(cli.pass_store_path.as_ref()) {
        Ok(pass) => pass,
        Err(e) => {
            eprintln!("Error initializing store object: {}", e);
            std::process::exit(1);
        }
    };

    let file_path = cli.path;
    let Ok(otps) = OTPs::new(&file_path) else {
        eprintln!("Error reading OTPs from file: {}", file_path.display());
        std::process::exit(1);
    };

    if cli.list {
        otps.list();
        return;
    }

    match otps.save(&mut pass) {
        Ok(_) => {
            println!("Successfully saved OTPs to pass store.");
        }
        Err(e) => {
            eprintln!("Error saving OTPs to pass store: {}", e);
            std::process::exit(1);
        }
    }
}
