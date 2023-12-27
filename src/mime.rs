macro_rules! mime_types {
    (
        $(
            $(#[$docs:meta])+
            ($name:ident, $name_str:literal);
        )+
    ) => {

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum MimeType {
            $(
                $(#[$docs])*
                $name,
            )+
        }
        impl MimeType {
            pub fn as_str(&self) -> &str {
                match *self {
                    $(
                        MimeType::$name => $name_str,
                    )+
                }
            }

            pub fn from_ext(ext: &str) -> Option<MimeType> {
                let cap = Self::capitalize(ext);
                match cap.as_str(){
                    $(
                        stringify!($name) => Some(MimeType::$name),
                    )+
                    _ => None
                }
            }

            fn capitalize(ext: &str) -> String {
                let mut c = ext.chars();
                match c.next() {
                    None => String::new(),
                    Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                }
            }
        }
        impl std::fmt::Display for MimeType {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }

    };
}

mime_types! {
    ///AAC audio
    (Aac,"audio/aac");
    ///AbiWord document
    (Abw,"application/x-abiword");
    ///Archive document (multiple files embedded)
    (Arc,"application/x-freearc");
    ///AVIF image
    (Avif,"image/avif");
    ///AVI: Audio Video Interleave
    (Avi,"video/x-msvideo");
    ///Amazon Kindle eBook format
    (Azw,"application/vnd.amazon.ebook");
    ///Any kind of binary data
    (Bin,"application/octet-stream");
    ///Windows OS/2 Bitmap Graphics
    (Bmp,"image/bmp");
    ///BZip archive
    (Bz,"application/x-bzip");
    ///BZip2 archive
    (Bz2,"application/x-bzip2");
    ///CD audio
    (Cda,"application/x-cdf");
    ///C-Shell script
    (Csh,"application/x-csh");
    ///Cascading Style Sheets (CSS)
    (Css,"text/css");
    ///Comma-separated values (CSV)
    (Csv,"text/csv");
    ///Microsoft Word
    (Doc,"application/msword");
    ///Microsoft Word (OpenXML)
    (Docx,"application/vnd.openxmlformats-officedocument.wordprocessingml.document");
    ///MS Embedded OpenType fonts
    (Eot,"application/vnd.ms-fontobject");
    ///Electronic publication (EPUB)
    (Epub,"application/epub+zip");
    ///GZip Compressed Archive
    (Gz,"application/gzip");
    ///Graphics Interchange Format (GIF)
    (Gif,"image/gif");
    ///HyperText Markup Language (HTML)
    (Htm,"text/html");
    ///HyperText Markup Language (HTML)
    (Html,"text/html");
    ///Icon format
    (Ico,"image/vnd.microsoft.icon");
    ///iCalendar format
    (Ics,"text/calendar");
    ///Java Archive (JAR)
    (Jar,"application/java-archive");
    ///JPEG images
    (Jpeg,"image/jpeg");
    ///JPEG images
    (Jpg,"image/jpeg");
    ///JavaScript
    (Js,"text/javascript");
    ///JSON format
    (Json,"application/json");
    ///JSON-LD format
    (Jsonld,"application/ld+json");
    ///Musical Instrument Digital Interface (MIDI)
    (Mid,"audio/midi,");
    ///Musical Instrument Digital Interface (MIDI)
    (Midi,"audio/midi,");
    ///JavaScript module
    (Mjs,"text/javascript");
    ///MP3 audio
    (Mp3,"audio/mpeg");
    ///MP4 video
    (Mp4,"video/mp4");
    ///MPEG Video
    (Mpeg,"video/mpeg");
    ///Apple Installer Package
    (Mpkg,"application/vnd.apple.installer+xml");
    ///OpenDocument presentation document
    (Odp,"application/vnd.oasis.opendocument.presentation");
    ///OpenDocument spreadsheet document
    (Ods,"application/vnd.oasis.opendocument.spreadsheet");
    ///OpenDocument text document
    (Odt,"application/vnd.oasis.opendocument.text");
    ///OGG audio
    (Oga,"audio/ogg");
    ///OGG video
    (Ogv,"video/ogg");
    ///OGG
    (Ogx,"application/ogg");
    ///Opus audio
    (Opus,"audio/opus");
    ///OpenType font
    (Otf,"font/otf");
    ///Portable Network Graphics
    (Png,"image/png");
    ///Adobe Portable Document Format (PDF)
    (Pdf,"application/pdf");
    ///Hypertext Preprocessor (Personal Home Page)
    (Php,"application/x-httpd-php");
    ///Microsoft PowerPoint
    (Ppt,"application/vnd.ms-powerpoint");
    ///Microsoft PowerPoint (OpenXML)
    (Pptx,"application/vnd.openxmlformats-officedocument.presentationml.presentation");
    ///RAR archive
    (Rar,"application/vnd.rar");
    ///Rich Text Format (RTF)
    (Rtf,"application/rtf");
    ///Bourne shell script
    (Sh,"application/x-sh");
    ///Scalable Vector Graphics (SVG)
    (Svg,"image/svg+xml");
    ///Tape Archive (TAR)
    (Tar,"application/x-tar");
    ///Tagged Image File Format (TIFF)
    (Tif,"image/tiff");
    ///Tagged Image File Format (TIFF)
    (Tiff,"image/tiff");
    /// Toml text file
    (Toml,"application/toml");
    ///MPEG transport stream
    (Ts,"video/mp2t");
    ///TrueType Font
    (Ttf,"font/ttf");
    ///Text, (generally ASCII or ISO 8859-n)
    (Txt,"text/plain");
    ///Microsoft Visio
    (Vsd,"application/vnd.visio");
    ///Waveform Audio Format
    (Wav,"audio/wav");
    ///WEBM audio
    (Weba,"audio/webm");
    ///WEBM video
    (Webm,"video/webm");
    ///WEBP image
    (Webp,"image/webp");
    ///Web Open Font Format (WOFF)
    (Woff,"font/woff");
    ///Web Open Font Format (WOFF)
    (Woff2,"font/woff2");
    ///XHTML
    (Xhtml,"application/xhtml+xml");
    ///Microsoft Excel
    (Xls,"application/vnd.ms-excel");
    ///Microsoft Excel (OpenXML)
    (Xlsx,"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
    ///XML
    (Xml,"application/xml");
    ///XUL
    (Xul,"application/vnd.mozilla.xul+xml");
    ///ZIP archive
    (Zip,"application/zip");
    ///3GPP audio/video container
    (_3Gp,"video/3gpp");
    ///3GPP2 audio/video container
    (_3G2,"video/3gpp2");
    ///7-zip archive
    (_7Z,"application/x-7z-compressed");
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::errors::Result;

    #[test]
    fn check_mime_ext_parsing() -> Result<()> {
        //Given
        let ext = "zip";
        // When
        let mime = MimeType::from_ext(ext);
        // Then
        assert_eq!(mime, Some(MimeType::Zip));

        Ok(())
    }

    #[test]
    fn check_mime_str() -> Result<()> {
        // Given
        let mime = MimeType::Aac;
        // When
        let mime_str = mime.as_str();
        // Then
        assert_eq!(mime_str, "audio/aac");
        Ok(())
    }

    #[test]
    fn check_mime_display() -> Result<()> {
        // Given
        let css = MimeType::Css;
        // When
        let disp = format!("{}", css);
        // Then
        assert_eq!(&disp, "text/css");

        Ok(())
    }
}
