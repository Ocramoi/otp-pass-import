use std::path::PathBuf;
use std::io::{Error, ErrorKind};
use std::process::Command;
use termion::{color, style};
use crate::platform::P;
use crate::otp::{OTPs, OTP};

pub struct Pass {
    base_path: PathBuf,
    entries: Vec<String>,
}

impl Default for Pass {
    fn default() -> Self {
        Pass {
            base_path: PathBuf::from(P.default_store_path()),
            entries: Vec::new(),
        }
    }

}

impl Pass {
    pub fn new(base_path: Option<&PathBuf>) -> Result<Pass, Error> {
        let path_str: &PathBuf = match base_path {
            Some(path) => path,
            _ => &P.default_store_path(),
        };

        if !path_str.exists() {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("Pass store path '{}' does not exist.", P.default_store_path().display()),
            ));
        }

        Ok(Pass {
            base_path: path_str.clone(),
            entries: match _get_entries_from_pass_store(path_str) {
                Ok(entries) => entries,
                Err(e) => {
                    eprintln!("Error reading pass-store: {}", e);
                    std::process::exit(1);
                }
            },
            ..Default::default()
        })
    }

    pub fn change_pass_store_path(&mut self, new_path: &PathBuf) -> Result<&Self, Error> {
        if !new_path.exists() {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("New pass store path '{}' does not exist.", new_path.display()),
            ));
        }

        self.base_path = new_path.clone();
        self.entries = _get_entries_from_pass_store(new_path)?;
        Ok(self)
    }

    pub fn update_pass_store(&mut self) -> Result<(), Error> {
        Ok(())
    }

    pub fn add_entries(&mut self, entries: &OTPs) -> Result<(), Error> {
        for entry in entries.get_data() {
            if let Err(e) = self.add_entry(entry) {
                eprintln!(
                    "{}{}Error adding entry '{}': {}",
                    color::Fg(color::Red),
                    style::Bold,
                    entry.name,
                    e,
                );
            } else {
                println!(
                    "{}{}{} {}{}",
                    color::Fg(color::Green),
                    style::Bold,
                    "Added",
                    color::Fg(color::Reset),
                    entry.name
                );
            }
        }
        Ok(())
    }

    pub fn add_entry(&mut self, entry: &OTP) -> Result<(), Error> {
        use std::io::Write;
        let mut _cmd = Command::new("pass");

        if let Some(issuer) = entry.issuer.clone() {
            _cmd
                .arg("--issuer")
                .arg(issuer.clone());
        }

        let cmd_stdin = _cmd
            .arg("otp")
            .arg("insert")
            .arg("--force")
            .arg("--account")
            .arg(entry.name.clone())
            .spawn()
            .unwrap()
            .stdin;

        if let Some(mut stdin) = cmd_stdin {
            match stdin.write_all(entry.url.to_string().as_bytes()) {
                Ok(_) => Ok(()),
                Err(e) => Err(Error::new(ErrorKind::Other, format!("Failed to write to pass stdin: {}", e)))
            }
        } else {
            Err(Error::new(
                ErrorKind::Other,
                "Failed to get stdin for pass command.",
            ))
        }
    }

    pub fn get_entries(&self) -> &Vec<String> {
        &self.entries
    }

    pub fn get_base_path(&self) -> Result<&str, Error> {
        match &self.base_path.to_str() {
            Some(path) => Ok(path),
            _ => {
                Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("Invalid pass store path: {}", self.base_path.display())),
                )
            }
        }
    }
}

fn _get_entries_from_pass_store(pass_store_path: &PathBuf) -> std::io::Result<Vec<String>> {
    if pass_store_path.exists() && pass_store_path.is_dir() {
        Ok({
            _register_files(pass_store_path)
                .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, format!("Error reading pass store: {}", e)))?
        })
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Pass store path '{}' does not exist or is not a directory.", pass_store_path.display()),
        ))
    }
}

fn _register_files(dir: &PathBuf) -> std::io::Result<Vec<String>> {
    use std::fs;

    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        match entry {
            Ok(entry) => {
                let file_type = entry.file_type()?;
                if file_type.is_file() {
                    files.push(entry.file_name().to_string_lossy().into_owned());
                } else if file_type.is_dir() {
                    files.extend(_register_files(&entry.path())?);
                }
            },
            Err(e) => {
                eprintln!("Error reading entry: {}", e);
                return Err(e);
            }
        }
    }
    Ok(files)
}
