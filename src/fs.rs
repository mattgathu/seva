use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::{fs::Metadata, time::SystemTime};

#[derive(Debug, Serialize)]
pub struct DirEntry {
    pub name: String,
    pub file_type: EntryType,
    pub ext: Option<String>,
    pub modified: DateTime<Utc>,
    pub created: DateTime<Utc>,
    pub size: u64,
}
impl DirEntry {
    pub fn dt(t: SystemTime) -> Result<DateTime<Utc>> {
        let secs = t.duration_since(SystemTime::UNIX_EPOCH)?.as_secs();
        let dt = DateTime::<Utc>::from_timestamp(secs as i64, 0);
        match dt {
            Some(dt) => Ok(dt),
            None => Err(anyhow::format_err!("date conversion failed")),
        }
    }
    pub fn from_metadata(meta: Metadata, name: &str) -> Result<Self> {
        let ext = name.rsplit_once('.').map(|(_, e)| e.to_string());
        let file_type = EntryType::from(meta.file_type());
        let name = if file_type == EntryType::Dir && !name.ends_with('/') {
            format!("{}/", name)
        } else {
            name.to_string()
        };
        Ok(Self {
            name,
            file_type,
            ext,
            modified: Self::dt(meta.modified()?)?,
            created: Self::dt(meta.created()?)?,
            size: meta.len(),
        })
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub enum EntryType {
    File,
    Link,
    Dir,
    Other,
}
impl From<std::fs::FileType> for EntryType {
    fn from(value: std::fs::FileType) -> Self {
        if value.is_dir() {
            Self::Dir
        } else if value.is_file() {
            Self::File
        } else if value.is_symlink() {
            Self::Link
        } else {
            Self::Other
        }
    }
}
