use std::{fs::Metadata, path::PathBuf, time::SystemTime};

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::errors::{ParsingError, Result};

#[derive(Debug, Serialize)]
pub struct DirEntry {
    pub name: String,
    pub kind: EntryType,
    pub ext: Option<String>,
    pub modified: DateTime<Utc>,
    pub created: DateTime<Utc>,
    pub size: u64,
    pub path: PathBuf,
}
impl DirEntry {
    pub fn from_metadata(meta: Metadata, name: &str, path: PathBuf) -> Result<Self> {
        let ext = name.rsplit_once('.').map(|(_, e)| e.to_string());
        let kind = EntryType::from(meta.file_type());
        let name = if kind == EntryType::Dir && !name.ends_with('/') {
            format!("{}/", name)
        } else {
            name.to_string()
        };
        Ok(Self {
            name,
            kind,
            ext,
            modified: dt(meta.modified()?)?,
            created: dt(meta.created()?)?,
            size: meta.len(),
            path,
        })
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub enum EntryType {
    File,
    Dir,
}
impl From<std::fs::FileType> for EntryType {
    fn from(val: std::fs::FileType) -> Self {
        if val.is_dir() {
            Self::Dir
        } else {
            debug_assert!(val.is_symlink() || val.is_file());
            Self::File
        }
    }
}

fn dt(t: SystemTime) -> Result<DateTime<Utc>> {
    let secs = t.duration_since(SystemTime::UNIX_EPOCH)?.as_secs();
    let dt = DateTime::<Utc>::from_timestamp(secs as i64, 0);
    match dt {
        Some(dt) => Ok(dt),
        None => {
            Err(ParsingError::DateTime("date conversion failed".to_owned()).into())
        }
    }
}
