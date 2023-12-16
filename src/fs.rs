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
    //
    //
}

#[derive(MimeType)]
pub enum MimeTypes {
    ///AAC audio
    #[mime_type(audio/aac)]
    #[mime_ext(.aac)]
    Aac,
    ///AbiWord document
    #[mime_type(application/x-abiword)]
    #[mime_ext(.abw)]
    Abw,
    ///Archive document (multiple files embedded)
    #[mime_type(application/x-freearc)]
    #[mime_ext(.arc)]
    Arc,
    ///AVIF image
    #[mime_type(image/avif)]
    #[mime_ext(.avif)]
    Avif,
    ///AVI: Audio Video Interleave
    #[mime_type(video/x-msvideo)]
    #[mime_ext(.avi)]
    Avi,
    ///Amazon Kindle eBook format
    #[mime_type(application/vnd.amazon.ebook)]
    #[mime_ext(.azw)]
    Azw,
    ///Any kind of binary data
    #[mime_type(application/octet-stream)]
    #[mime_ext(.bin)]
    Bin,
    ///Windows OS/2 Bitmap Graphics
    #[mime_type(image/bmp)]
    #[mime_ext(.bmp)]
    Bmp,
    ///BZip archive
    #[mime_type(application/x-bzip)]
    #[mime_ext(.bz)]
    Bz,
    ///BZip2 archive
    #[mime_type(application/x-bzip2)]
    #[mime_ext(.bz2)]
    Bz2,
    ///CD audio
    #[mime_type(application/x-cdf)]
    #[mime_ext(.cda)]
    Cda,
    ///C-Shell script
    #[mime_type(application/x-csh)]
    #[mime_ext(.csh)]
    Csh,
    ///Cascading Style Sheets (CSS)
    #[mime_type(text/css)]
    #[mime_ext(.css)]
    Css,
    ///Comma-separated values (CSV)
    #[mime_type(text/csv)]
    #[mime_ext(.csv)]
    Csv,
    ///Microsoft Word
    #[mime_type(application/msword)]
    #[mime_ext(.doc)]
    Doc,
    ///Microsoft Word (OpenXML)
    #[mime_type(application/vnd.openxmlformats-officedocument.wordprocessingml.document)]
    #[mime_ext(.docx)]
    Docx,
    ///MS Embedded OpenType fonts
    #[mime_type(application/vnd.ms-fontobject)]
    #[mime_ext(.eot)]
    Eot,
    ///Electronic publication (EPUB)
    #[mime_type(application/epub+zip)]
    #[mime_ext(.epub)]
    Epub,
    ///GZip Compressed Archive
    #[mime_type(application/gzip)]
    #[mime_ext(.gz)]
    Gz,
    ///Graphics Interchange Format (GIF)
    #[mime_type(image/gif)]
    #[mime_ext(.gif)]
    Gif,
    ///HyperText Markup Language (HTML)
    #[mime_type(text/html)]
    #[mime_ext(.htm)]
    Htm,
    ///HyperText Markup Language (HTML)
    #[mime_type(#[mime_type(text/html)])]
    #[mime_ext( .html)]
    Html,
    ///Icon format
    #[mime_type(image/vnd.microsoft.icon)]
    #[mime_ext(.ico)]
    Ico,
    ///iCalendar format
    #[mime_type(text/calendar)]
    #[mime_ext(.ics)]
    Ics,
    ///Java Archive (JAR)
    #[mime_type(application/java-archive)]
    #[mime_ext(.jar)]
    Jar,
    ///JPEG images
    #[mime_type(image/jpeg)]
    #[mime_ext(.jpeg)]
    Jpeg,
    ///JPEG images
    #[mime_type(#[mime_type(image/jpeg)])]
    #[mime_ext( .jpg)]
    Jpg,
    ///JavaScript
    #[mime_type(text/javascript)]
    #[mime_ext(.js)]
    Js,
    ///JSON format
    #[mime_type(application/json)]
    #[mime_ext(.json)]
    Json,
    ///JSON-LD format
    #[mime_type(application/ld+json)]
    #[mime_ext(.jsonld)]
    Jsonld,
    ///Musical Instrument Digital Interface (MIDI)
    #[mime_type(audio/midi,)]
    #[mime_ext(.mid)]
    Mid,
    ///Musical Instrument Digital Interface (MIDI)
    #[mime_type(#[mime_type(audio/midi,)])]
    #[mime_ext(.midi)]
    Midi,
    ///JavaScript module
    #[mime_type(text/javascript)]
    #[mime_ext(.mjs)]
    Mjs,
    ///MP3 audio
    #[mime_type(audio/mpeg)]
    #[mime_ext(.mp3)]
    Mp3,
    ///MP4 video
    #[mime_type(video/mp4)]
    #[mime_ext(.mp4)]
    Mp4,
    ///MPEG Video
    #[mime_type(video/mpeg)]
    #[mime_ext(.mpeg)]
    Mpeg,
    ///Apple Installer Package
    #[mime_type(application/vnd.apple.installer+xml)]
    #[mime_ext(.mpkg)]
    Mpkg,
    ///OpenDocument presentation document
    #[mime_type(application/vnd.oasis.opendocument.presentation)]
    #[mime_ext(.odp)]
    Odp,
    ///OpenDocument spreadsheet document
    #[mime_type(application/vnd.oasis.opendocument.spreadsheet)]
    #[mime_ext(.ods)]
    Ods,
    ///OpenDocument text document
    #[mime_type(application/vnd.oasis.opendocument.text)]
    #[mime_ext(.odt)]
    Odt,
    ///OGG audio
    #[mime_type(audio/ogg)]
    #[mime_ext(.oga)]
    Oga,
    ///OGG video
    #[mime_type(video/ogg)]
    #[mime_ext(.ogv)]
    Ogv,
    ///OGG
    #[mime_type(application/ogg)]
    #[mime_ext(.ogx)]
    Ogx,
    ///Opus audio
    #[mime_type(audio/opus)]
    #[mime_ext(.opus)]
    Opus,
    ///OpenType font
    #[mime_type(font/otf)]
    #[mime_ext(.otf)]
    Otf,
    ///Portable Network Graphics
    #[mime_type(image/png)]
    #[mime_ext(.png)]
    Png,
    ///Adobe Portable Document Format (PDF)
    #[mime_type(application/pdf)]
    #[mime_ext(.pdf)]
    Pdf,
    ///Hypertext Preprocessor (Personal Home Page)
    #[mime_type(application/x-httpd-php)]
    #[mime_ext(.php)]
    Php,
    ///Microsoft PowerPoint
    #[mime_type(application/vnd.ms-powerpoint)]
    #[mime_ext(.ppt)]
    Ppt,
    ///Microsoft PowerPoint (OpenXML)
    #[mime_type(application/vnd.openxmlformats-officedocument.presentationml.presentation)]
    #[mime_ext(.pptx)]
    Pptx,
    ///RAR archive
    #[mime_type(application/vnd.rar)]
    #[mime_ext(.rar)]
    Rar,
    ///Rich Text Format (RTF)
    #[mime_type(application/rtf)]
    #[mime_ext(.rtf)]
    Rtf,
    ///Bourne shell script
    #[mime_type(application/x-sh)]
    #[mime_ext(.sh)]
    Sh,
    ///Scalable Vector Graphics (SVG)
    #[mime_type(image/svg+xml)]
    #[mime_ext(.svg)]
    Svg,
    ///Tape Archive (TAR)
    #[mime_type(application/x-tar)]
    #[mime_ext(.tar)]
    Tar,
    ///Tagged Image File Format (TIFF)
    #[mime_type(image/tiff)]
    #[mime_ext(.tif)]
    Tif,
    ///Tagged Image File Format (TIFF)
    #[mime_type(#[mime_type(image/tiff)])]
    #[mime_ext( .tiff)]
    Tiff,
    ///MPEG transport stream
    #[mime_type(video/mp2t)]
    #[mime_ext(.ts)]
    Ts,
    ///TrueType Font
    #[mime_type(font/ttf)]
    #[mime_ext(.ttf)]
    Ttf,
    ///Text, (generally ASCII or ISO 8859-n)
    #[mime_type(text/plain)]
    #[mime_ext(.txt)]
    Txt,
    ///Microsoft Visio
    #[mime_type(application/vnd.visio)]
    #[mime_ext(.vsd)]
    Vsd,
    ///Waveform Audio Format
    #[mime_type(audio/wav)]
    #[mime_ext(.wav)]
    Wav,
    ///WEBM audio
    #[mime_type(audio/webm)]
    #[mime_ext(.weba)]
    Weba,
    ///WEBM video
    #[mime_type(video/webm)]
    #[mime_ext(.webm)]
    Webm,
    ///WEBP image
    #[mime_type(image/webp)]
    #[mime_ext(.webp)]
    Webp,
    ///Web Open Font Format (WOFF)
    #[mime_type(font/woff)]
    #[mime_ext(.woff)]
    Woff,
    ///Web Open Font Format (WOFF)
    #[mime_type(font/woff2)]
    #[mime_ext(.woff2)]
    Woff2,
    ///XHTML
    #[mime_type(application/xhtml+xml)]
    #[mime_ext(.xhtml)]
    Xhtml,
    ///Microsoft Excel
    #[mime_type(application/vnd.ms-excel)]
    #[mime_ext(.xls)]
    Xls,
    ///Microsoft Excel (OpenXML)
    #[mime_type(application/vnd.openxmlformats-officedocument.spreadsheetml.sheet)]
    #[mime_ext(.xlsx)]
    Xlsx,
    ///XML
    #[mime_type(application/xml)]
    #[mime_ext(.xml)]
    Xml,
    ///XUL
    #[mime_type(application/vnd.mozilla.xul+xml)]
    #[mime_ext(.xul)]
    Xul,
    ///ZIP archive
    #[mime_type(application/zip)]
    #[mime_ext(.zip)]
    Zip,
    ///3GPP audio/video container
    #[mime_type(video/3gpp)]
    #[mime_ext(.3gp)]
    _3gp,
    ///3GPP2 audio/video container
    #[mime_type(video/3gpp2)]
    #[mime_ext(.3g2)]
    _3g2,
    ///7-zip archive
    #[mime_type(application/x-7z-compressed)]
    #[mime_ext(.7z)]
    _7z,
}
