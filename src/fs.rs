use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use seva_macros::MimeType;
use std::fs::Metadata;
use std::time::SystemTime;

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
        Ok(Self {
            name: name.to_string(),
            file_type: EntryType::from(meta.file_type()),
            ext: None,
            modified: Self::dt(meta.modified()?)?,
            created: Self::dt(meta.created()?)?,
            size: meta.len(),
        })
    }
}

#[derive(Debug, Serialize)]
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

#[derive(MimeType)]
pub enum MimeTypes {
    ///AAC audio
    #[mime_type(audio/aac)]
    Aac,
    ///AbiWord document
    #[mime_type(application/x-abiword)]
    Abw,
    ///Archive document (multiple files embedded)
    #[mime_type(application/x-freearc)]
    Arc,
    ///AVIF image
    #[mime_type(image/avif)]
    Avif,
    ///AVI: Audio Video Interleave
    #[mime_type(video/x-msvideo)]
    Avi,
    ///Amazon Kindle eBook format
    #[mime_type(application/vnd.amazon.ebook)]
    Azw,
    ///Any kind of binary data
    #[mime_type(application/octet-stream)]
    Bin,
    ///Windows OS/2 Bitmap Graphics
    #[mime_type(image/bmp)]
    Bmp,
    ///BZip archive
    #[mime_type(application/x-bzip)]
    Bz,
    ///BZip2 archive
    #[mime_type(application/x-bzip2)]
    Bz2,
    ///CD audio
    #[mime_type(application/x-cdf)]
    Cda,
    ///C-Shell script
    #[mime_type(application/x-csh)]
    Csh,
    ///Cascading Style Sheets (CSS)
    #[mime_type(text/css)]
    Css,
    ///Comma-separated values (CSV)
    #[mime_type(text/csv)]
    Csv,
    ///Microsoft Word
    #[mime_type(application/msword)]
    Doc,
    ///Microsoft Word (OpenXML)
    #[mime_type(application/vnd.openxmlformats-officedocument.wordprocessingml.document)]
    Docx,
    ///MS Embedded OpenType fonts
    #[mime_type(application/vnd.ms-fontobject)]
    Eot,
    ///Electronic publication (EPUB)
    #[mime_type(application/epub+zip)]
    Epub,
    ///GZip Compressed Archive
    #[mime_type(application/gzip)]
    Gz,
    ///Graphics Interchange Format (GIF)
    #[mime_type(image/gif)]
    Gif,
    ///HyperText Markup Language (HTML)
    #[mime_type(text/html)]
    Htm,
    ///HyperText Markup Language (HTML)
    #[mime_type(#[mime_type(text/html)])]
    Html,
    ///Icon format
    #[mime_type(image/vnd.microsoft.icon)]
    Ico,
    ///iCalendar format
    #[mime_type(text/calendar)]
    Ics,
    ///Java Archive (JAR)
    #[mime_type(application/java-archive)]
    Jar,
    ///JPEG images
    #[mime_type(image/jpeg)]
    Jpeg,
    ///JPEG images
    #[mime_type(#[mime_type(image/jpeg)])]
    Jpg,
    ///JavaScript
    #[mime_type(text/javascript)]
    Js,
    ///JSON format
    #[mime_type(application/json)]
    Json,
    ///JSON-LD format
    #[mime_type(application/ld+json)]
    Jsonld,
    ///Musical Instrument Digital Interface (MIDI)
    #[mime_type(audio/midi,)]
    Mid,
    ///Musical Instrument Digital Interface (MIDI)
    #[mime_type(#[mime_type(audio/midi,)])]
    Midi,
    ///JavaScript module
    #[mime_type(text/javascript)]
    Mjs,
    ///MP3 audio
    #[mime_type(audio/mpeg)]
    Mp3,
    ///MP4 video
    #[mime_type(video/mp4)]
    Mp4,
    ///MPEG Video
    #[mime_type(video/mpeg)]
    Mpeg,
    ///Apple Installer Package
    #[mime_type(application/vnd.apple.installer+xml)]
    Mpkg,
    ///OpenDocument presentation document
    #[mime_type(application/vnd.oasis.opendocument.presentation)]
    Odp,
    ///OpenDocument spreadsheet document
    #[mime_type(application/vnd.oasis.opendocument.spreadsheet)]
    Ods,
    ///OpenDocument text document
    #[mime_type(application/vnd.oasis.opendocument.text)]
    Odt,
    ///OGG audio
    #[mime_type(audio/ogg)]
    Oga,
    ///OGG video
    #[mime_type(video/ogg)]
    Ogv,
    ///OGG
    #[mime_type(application/ogg)]
    Ogx,
    ///Opus audio
    #[mime_type(audio/opus)]
    Opus,
    ///OpenType font
    #[mime_type(font/otf)]
    Otf,
    ///Portable Network Graphics
    #[mime_type(image/png)]
    Png,
    ///Adobe Portable Document Format (PDF)
    #[mime_type(application/pdf)]
    Pdf,
    ///Hypertext Preprocessor (Personal Home Page)
    #[mime_type(application/x-httpd-php)]
    Php,
    ///Microsoft PowerPoint
    #[mime_type(application/vnd.ms-powerpoint)]
    Ppt,
    ///Microsoft PowerPoint (OpenXML)
    #[mime_type(application/vnd.openxmlformats-officedocument.presentationml.presentation)]
    Pptx,
    ///RAR archive
    #[mime_type(application/vnd.rar)]
    Rar,
    ///Rich Text Format (RTF)
    #[mime_type(application/rtf)]
    Rtf,
    ///Bourne shell script
    #[mime_type(application/x-sh)]
    Sh,
    ///Scalable Vector Graphics (SVG)
    #[mime_type(image/svg+xml)]
    Svg,
    ///Tape Archive (TAR)
    #[mime_type(application/x-tar)]
    Tar,
    ///Tagged Image File Format (TIFF)
    #[mime_type(image/tiff)]
    Tif,
    ///Tagged Image File Format (TIFF)
    #[mime_type(#[mime_type(image/tiff)])]
    Tiff,
    ///MPEG transport stream
    #[mime_type(video/mp2t)]
    Ts,
    ///TrueType Font
    #[mime_type(font/ttf)]
    Ttf,
    ///Text, (generally ASCII or ISO 8859-n)
    #[mime_type(text/plain)]
    Txt,
    ///Microsoft Visio
    #[mime_type(application/vnd.visio)]
    Vsd,
    ///Waveform Audio Format
    #[mime_type(audio/wav)]
    Wav,
    ///WEBM audio
    #[mime_type(audio/webm)]
    Weba,
    ///WEBM video
    #[mime_type(video/webm)]
    Webm,
    ///WEBP image
    #[mime_type(image/webp)]
    Webp,
    ///Web Open Font Format (WOFF)
    #[mime_type(font/woff)]
    Woff,
    ///Web Open Font Format (WOFF)
    #[mime_type(font/woff2)]
    Woff2,
    ///XHTML
    #[mime_type(application/xhtml+xml)]
    Xhtml,
    ///Microsoft Excel
    #[mime_type(application/vnd.ms-excel)]
    Xls,
    ///Microsoft Excel (OpenXML)
    #[mime_type(application/vnd.openxmlformats-officedocument.spreadsheetml.sheet)]
    Xlsx,
    ///XML
    #[mime_type(application/xml)]
    Xml,
    ///XUL
    #[mime_type(application/vnd.mozilla.xul+xml)]
    Xul,
    ///ZIP archive
    #[mime_type(application/zip)]
    Zip,
    ///3GPP audio/video container
    #[mime_type(video/3gpp)]
    #[mime_ext(3gp)]
    _3gp,
    ///3GPP2 audio/video container
    #[mime_type(video/3gpp2)]
    #[mime_ext(3g2)]
    _3g2,
    ///7-zip archive
    #[mime_type(application/x-7z-compressed)]
    #[mime_ext(7z)]
    _7z,
}
