use core::fmt;
use std::{io::{Error, ErrorKind}, path::PathBuf};
use crate::{pass::Pass, platform::P};
use termion::{color, style};

#[derive(serde::Deserialize, Clone)]
pub struct OTP {
    id: Option<i32>,
    pub name: String,
    pub secret: String,
    pub issuer: Option<String>,
    pub url: String,
}

pub struct OTPs {
    data: Vec<OTP>,
}

impl fmt::Display for OTP {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl OTP {
    pub fn new(name: String, secret: String, issuer: Option<String>, url: String) -> Self {
        OTP { id: Some(-1), name: name, secret, issuer, url }
    }

    pub fn is_valid(&self) -> Result<(), Error> {
        if self.secret.is_empty() {
            Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "Secret cannot be empty.",
            ))
        } else if self.url.is_empty() {
            Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "URL cannot be empty.",
            ))
        } else if self.name.is_empty() {
            Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "Name cannot be empty.",
            ))
        } else if !P.check_otp_uri(&self.url) {
            Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "Invalid OTP URI format.",
            ))
        } else {
            Ok(())
        }
    }

    pub fn to_string(&self) -> String {
        format!(
            "[{id}] {bold}{cyan}'{name}'{ubold}: ({issuer}) {underline}{uri}{nunderline}{sclear}{cclear}",
            id = self.id.unwrap_or(-1),
            bold = style::Bold,
            cyan = color::Fg(color::Cyan),
            ubold = style::Reset,
            sclear = style::Reset,
            cclear = color::Fg(color::Reset),
            name = self.name,
            issuer = match &self.issuer {
                Some(issuer) => issuer,
                None => "nil",
            },
            uri = self.url,
            underline = style::Underline,
            nunderline = style::NoUnderline,
        )
    }

    pub fn save_to_pass(&self, pass: &mut Pass) -> Result<String, Error> {
        if self.is_valid().is_err() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "{}{}Cannot save an invalid OTP entry.",
                    color::Fg(color::Red),
                    style::Bold,
                ),
            ));
        }

        match pass.add_entry(self) {
            Ok(_) => Ok(format!(
                "{}/{}",
                pass.get_base_path()?,
                self.name
            ).to_string()),
            Err(e) => Err(Error::new(ErrorKind::InvalidData, format!("Error adding OTP:\t{e}"))),
        }
    }

}

pub trait New<T> {
    type E;
    fn new(data: T) -> Result<Self, Self::E>
    where
        Self: Sized;
}

impl New<&Vec<OTP>> for OTPs {
    type E = Error;
    fn new(data: &Vec<OTP>) -> Result<Self, Error> {
        Ok(OTPs { data: data.to_vec() })
    }
}

impl New<&String> for OTPs {
    type E = Error;
    fn new(data: &String) -> Result<Self, Error> {
        let mut o = OTPs { data: Vec::new() };
        if let Ok(_) = o.read_file(&std::path::PathBuf::from(data)) {
            Ok(o)
        } else {
            Err(Error::new(
                ErrorKind::InvalidData,
                format!("Error reading OTPs from file: {}", data),
            ))
        }
    }
}

impl New<&PathBuf> for OTPs {
    type E = Error;
    fn new(path: &PathBuf) -> Result<Self, Error> {
        let mut o = OTPs { data: Vec::new() };
        if let Ok(_) = o.read_file(path) {
            Ok(o)
        } else {
            Err(Error::new(
                ErrorKind::InvalidData,
                format!("Error reading OTPs from file: {}", path.display()),
            ))
        }
    }
}

impl OTPs {
    pub fn add(&mut self, otp: OTP) {
        self.data.push(otp);
    }

    pub fn is_empty(&self) -> bool {
        self.data.len() == 0
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn get_data(&self) -> &Vec<OTP> {
        &self.data
    }

    pub fn read_file(&mut self, path: &std::path::PathBuf) -> Result<&OTPs, Error> {
        use std::fs::File;
        use std::io::BufReader;

        self.data.clear();

        let file = File::open(path)?;
        let reader = BufReader::new(file);
        for (idx, raw_entry) in csv::ReaderBuilder::new()
            .has_headers(true)
            .from_reader(reader)
            .deserialize()
            .into_iter()
            .enumerate()
        {
            let mut curr: OTP = match raw_entry {
                Ok(entry) => entry,
                Err(e) => {
                    eprintln!("Warning: Error parsing entry at position {} in file: {} (ignoring). \n\tError: {}", idx + 1, path.display(), e);
                    continue;
                }
            };
            curr.id = Some(idx as i32 + 1);

            if curr.is_valid().is_err() {
                eprintln!(
                    "Warning: Found an entry with invalid values in the file: {} at position {} (ignoring).\n\tError: {} \n\tEntry: {}",
                    path.display(),
                    idx + 1,
                    curr.is_valid().unwrap_err(),
                    curr
                );
                continue;
            }
            self.data.push(curr);
        }
        if self.data.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Error: No valid OTP entries found in the file: {}", path.display()),
            ));
        }

        Ok(self)
    }

    pub fn save(&self, pass: &mut Pass) -> Result<(), Error> {
        if self.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Empty OTPs list.",
            ));
        }

        match pass.add_entries(&self) {
            Ok(_) => Ok(()),
            Err(e) => Err(Error::new(
                ErrorKind::InvalidData,
                format!("Error saving OTPs to pass store: {}", e),
            )),
        }
    }

    pub fn list(&self) {
        if self.is_empty() {
            println!("No OTP entries found.");
            return;
        }

        for otp in &self.data {
            println!("{}", otp.to_string());
        }
    }
}
