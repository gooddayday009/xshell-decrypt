use crate::{Session, parse_session, read_session};
use std::{
    fs::File,
    io::{Read, Seek},
    path::Path,
};

pub const MAX_SESSIONS: usize = 1000;
const MAX_SESSION_BYTES: u64 = 2 * 1024 * 1024;
const MAX_EXPANDED_BYTES: u64 = 32 * 1024 * 1024;

pub struct ImportedSession {
    pub label: String,
    pub session: Result<Session, String>,
}

pub fn read_source(path: &Path) -> Result<Vec<ImportedSession>, String> {
    if path
        .extension()
        .is_some_and(|s| s.eq_ignore_ascii_case("xts"))
    {
        let file = File::open(path).map_err(|e| format!("无法读取 XTS：{e}"))?;
        if file.metadata().map_err(|e| e.to_string())?.len() > 100 * 1024 * 1024 {
            return Err("XTS 文件超过 100 MiB，请拆分导出".into());
        }
        read_archive(file, &path.display().to_string())
    } else {
        Ok(vec![ImportedSession {
            label: path.display().to_string(),
            session: read_session(path),
        }])
    }
}

fn safe_member(name: &str) -> bool {
    let name = name.replace('\\', "/");
    !name.starts_with('/')
        && !name.contains(':')
        && !name.chars().any(char::is_control)
        && !name.split('/').any(|p| p == "..")
}

fn read_archive<R: Read + Seek>(source: R, label: &str) -> Result<Vec<ImportedSession>, String> {
    let mut archive = zip::ZipArchive::new(source)
        .map_err(|_| "不是有效的 ZIP 格式 XTS 导出包，或文件已损坏".to_string())?;
    if archive.len() > 10_000 {
        return Err("XTS 条目超过 10000 个，请拆分导出".into());
    }
    let mut sessions = Vec::new();
    let mut expanded = 0u64;
    for index in 0..archive.len() {
        // Inspect metadata first, so unrelated encrypted/non-session entries can be ignored.
        let member = archive
            .by_index_raw(index)
            .map_err(|e| format!("XTS 目录损坏：{e}"))?;
        let name = member.name().to_owned();
        let lower = name.to_ascii_lowercase();
        if member.is_dir() || (!lower.ends_with(".xsh") && !lower.ends_with(".xfp")) {
            continue;
        }
        if sessions.len() >= MAX_SESSIONS {
            return Err("XTS 会话超过 1000 个，请拆分导出".into());
        }
        if !safe_member(&name) || member.is_symlink() {
            return Err("XTS 含有不安全的会话路径或符号链接".into());
        }
        let label = format!("{label} :: {name}");
        if member.encrypted() {
            sessions.push(ImportedSession {
                label,
                session: Err(
                    "该 XTS 的 ZIP 条目已加密，暂不支持；请通过 Xshell 导入后选择会话文件".into(),
                ),
            });
            continue;
        }
        if member.size() > MAX_SESSION_BYTES {
            return Err("XTS 中有会话超过 2 MiB".into());
        }
        expanded = expanded.checked_add(member.size()).ok_or("XTS 长度溢出")?;
        if expanded > MAX_EXPANDED_BYTES {
            return Err("XTS 会话解压后总大小超过 32 MiB".into());
        }
        drop(member);
        let session = match archive.by_index(index) {
            Ok(member) => {
                let mut bytes = Vec::new();
                member
                    .take(MAX_SESSION_BYTES + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| "无法解压或校验 XTS 会话，可能已损坏".to_string())
                    .and_then(|_| {
                        if bytes.len() as u64 > MAX_SESSION_BYTES {
                            return Err("会话解压后超过 2 MiB".into());
                        }
                        parse_session(&bytes, lower.ends_with(".xfp"))
                    })
            }
            Err(e) => Err(format!("无法读取 XTS 会话：{e}")),
        };
        sessions.push(ImportedSession { label, session });
    }
    if sessions.is_empty() {
        return Err("XTS 中未找到 .xsh 或 .xfp 会话".into());
    }
    Ok(sessions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

    fn archive(entries: &[(&str, &[u8])], method: CompressionMethod) -> Vec<u8> {
        let mut out = ZipWriter::new(Cursor::new(Vec::new()));
        for (name, bytes) in entries {
            out.start_file(
                *name,
                SimpleFileOptions::default().compression_method(method),
            )
            .unwrap();
            out.write_all(bytes).unwrap();
        }
        out.finish().unwrap().into_inner()
    }
    #[test]
    fn xts_stored_and_deflate_recover_nested_session() {
        let input = include_bytes!("../tests/fixtures/xshell8-synthetic.xsh");
        for method in [CompressionMethod::Stored, CompressionMethod::Deflated] {
            let bytes = archive(
                &[("Xshell/组/test.XSH", input), ("metadata.txt", b"ignored")],
                method,
            );
            let result = read_archive(Cursor::new(bytes), "test.xts").unwrap();
            assert_eq!(result.len(), 1);
            assert!(result[0].label.ends_with("Xshell/组/test.XSH"));
            let session = result[0].session.as_ref().ok().unwrap();
            assert_eq!(
                crate::decrypt(
                    &session.encrypted,
                    "testuser",
                    "S-1-5-21-111-222-333-1001",
                    crate::Version::V8
                )
                .unwrap()
                .0
                .as_str(),
                "Test-only_密码!"
            );
        }
    }
    #[test]
    fn xts_utf16_xftp_and_missing_password() {
        let text = "[Connection]\nHost=example.test\nUserName=test\nPassword=abc==";
        let mut utf16 = vec![0xff, 0xfe];
        for word in text.encode_utf16() {
            utf16.extend(word.to_le_bytes());
        }
        let bytes = archive(
            &[
                ("Xftp/test.xfp", &utf16),
                ("no-password.xsh", b"[CONNECTION]\nHost=example.test"),
            ],
            CompressionMethod::Deflated,
        );
        let result = read_archive(Cursor::new(bytes), "test.xts").unwrap();
        assert!(result[0].session.is_ok());
        assert!(
            result[1]
                .session
                .as_ref()
                .err()
                .unwrap()
                .contains("没有保存密码")
        );
    }
    #[test]
    fn xts_rejects_invalid_empty_and_traversal() {
        assert!(read_archive(Cursor::new(b"not zip"), "bad.xts").is_err());
        for name in [
            "metadata.txt",
            "../test.xsh",
            "C:\\test.xsh",
            "/test.xsh",
            "..\\test.xsh",
        ] {
            let bytes = archive(&[(name, b"test")], CompressionMethod::Stored);
            assert!(read_archive(Cursor::new(bytes), "bad.xts").is_err());
        }
    }
    #[test]
    fn xts_enforces_expansion_limit() {
        let big = vec![b'A'; MAX_SESSION_BYTES as usize + 1];
        let bytes = archive(&[("big.xsh", &big)], CompressionMethod::Deflated);
        assert!(
            read_archive(Cursor::new(bytes), "big.xts")
                .err()
                .unwrap()
                .contains("2 MiB")
        );
    }
}
