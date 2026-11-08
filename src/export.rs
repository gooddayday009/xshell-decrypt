use std::{fmt::Write as _, fs::OpenOptions, io::Write as _, path::Path};
use zeroize::Zeroizing;

pub struct ExportEntry<'a> {
    pub source: &'a str,
    pub detail: &'a str,
    pub algorithm: &'a str,
    pub password: &'a str,
}

fn field(out: &mut String, name: &str, text: &str) {
    out.push_str(name);
    out.push_str(": ");
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{{{:x}}}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push_str("\r\n");
}

fn render(entries: &[ExportEntry<'_>]) -> Zeroizing<String> {
    let mut text = Zeroizing::new(String::from(
        "\u{feff}Xdecrypt Rust — 成功恢复结果\r\n此文件包含明文登录密码。\r\n字段内反斜杠、换行和制表符分别表示为 \\\\、\\n、\\r、\\t。\r\n\r\n",
    ));
    for (i, entry) in entries.iter().enumerate() {
        let _ = write!(text, "[{}]\r\n", i + 1);
        field(&mut text, "来源", entry.source);
        field(&mut text, "会话", entry.detail);
        field(&mut text, "解密方式", entry.algorithm);
        field(&mut text, "密码", entry.password);
        text.push_str("\r\n");
    }
    text
}

pub fn save_txt(path: &Path, entries: &[ExportEntry<'_>]) -> Result<(), String> {
    if entries.is_empty() {
        return Err("没有成功恢复的结果可导出".into());
    }
    if !path
        .extension()
        .is_some_and(|s| s.eq_ignore_ascii_case("txt"))
    {
        return Err("请选择 .txt 文件名".into());
    }
    // Never silently replace an existing file or a source session.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                "文件已存在，请换一个 TXT 文件名后导出".into()
            } else {
                format!("无法创建 TXT：{e}")
            }
        })?;
    let text = render(entries);
    file.write_all(text.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("导出未完成，目标文件可能不完整：{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn renders_unicode_password_and_escapes_without_ambiguity() {
        let text = render(&[ExportEntry {
            source: "test.xsh",
            detail: "example.test:22 · 用户 test",
            algorithm: "主密码",
            password: " 密码\\test\n\r\t ",
        }]);
        assert!(text.starts_with('\u{feff}'));
        assert!(text.contains("密码:  密码\\\\test\\n\\r\\t \r\n"));
        assert!(text.contains("example.test:22"));
    }
    #[test]
    fn export_creates_file_but_never_overwrites() {
        let path = std::env::temp_dir().join(format!(
            "xdecrypt-export-test-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let entries = [ExportEntry {
            source: "synthetic.xsh",
            detail: "example.test:22",
            algorithm: "主密码",
            password: "Test-only!",
        }];
        assert!(save_txt(&path, &[]).is_err());
        assert!(!path.exists());
        save_txt(&path, &entries).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), *render(&entries));
        assert!(save_txt(&path, &entries).is_err());
        assert!(save_txt(&path.with_extension("xsh"), &entries).is_err());
        std::fs::remove_file(path).unwrap();
    }
}
