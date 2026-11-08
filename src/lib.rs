use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, fs::File, io::Read, path::Path};
use zeroize::{Zeroize, Zeroizing};

pub mod discovery;
pub mod export;
pub mod imports;

pub fn matches_query(query: &str, source: &str, detail: &str) -> bool {
    let haystack = format!("{source}\n{detail}").to_lowercase();
    query
        .split_whitespace()
        .all(|word| haystack.contains(&word.to_lowercase()))
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Version {
    #[default]
    Auto,
    V6,
    V7,
    V8,
}

impl Version {
    pub fn label(self) -> &'static str {
        match self {
            Self::Auto => "自动识别",
            Self::V6 => "6",
            Self::V7 => "7",
            Self::V8 => "8",
        }
    }
}

pub struct Session {
    pub host: String,
    pub port: String,
    pub username: String,
    pub version: String,
    pub encrypted: String,
}

fn decode_text(bytes: &[u8]) -> Result<String, String> {
    let utf16 = bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]);
    if utf16 {
        if !bytes.len().is_multiple_of(2) {
            return Err("UTF-16 文件长度不正确".into());
        }
        let little = bytes[0] == 0xff;
        let words: Vec<u16> = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| {
                if little {
                    u16::from_le_bytes([p[0], p[1]])
                } else {
                    u16::from_be_bytes([p[0], p[1]])
                }
            })
            .collect();
        return String::from_utf16(&words).map_err(|_| "无效的 UTF-16 文件".into());
    }
    if let Ok(s) = std::str::from_utf8(bytes) {
        return Ok(s.trim_start_matches('\u{feff}').to_owned());
    }
    let (text, _, errors) = encoding_rs::GBK.decode(bytes);
    if errors {
        return Err("无法识别文件编码；支持 UTF-8、UTF-16 和 GBK".into());
    }
    Ok(text.into_owned())
}

pub fn parse_session(bytes: &[u8], xftp: bool) -> Result<Session, String> {
    let text = decode_text(bytes)?;
    let mut section = String::new();
    let mut fields = HashMap::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].to_ascii_lowercase();
        } else if let Some((key, value)) = line.split_once('=') {
            let key = (section.clone(), key.trim().to_ascii_lowercase());
            if fields.insert(key, value.trim().to_owned()).is_some() {
                return Err("会话包含重复配置项".into());
            }
        }
    }
    let field = |s: &str, k: &str| {
        fields
            .get(&(s.to_owned(), k.to_owned()))
            .cloned()
            .unwrap_or_default()
    };
    let auth = if xftp {
        "connection"
    } else {
        "connection:authentication"
    };
    let host = field("connection", "host");
    if host.is_empty() {
        return Err("未找到 CONNECTION/Host，不是有效的会话文件".into());
    }
    let encrypted = field(auth, "password");
    if encrypted.is_empty() {
        return Err("会话没有保存密码（可能使用私钥或认证配置文件）".into());
    }
    Ok(Session {
        host,
        port: field("connection", "port"),
        username: field(auth, "username"),
        version: field("sessioninfo", "version"),
        encrypted,
    })
}

pub fn read_session(path: &Path) -> Result<Session, String> {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if ext != "xsh" && ext != "xfp" {
        return Err("请选择 .xsh 或 .xfp 会话文件".into());
    }
    let file = File::open(path).map_err(|e| format!("无法读取文件：{e}"))?;
    let mut bytes = Vec::new();
    file.take(2 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("读取失败：{e}"))?;
    if bytes.len() > 2 * 1024 * 1024 {
        return Err("会话文件超过 2 MiB".into());
    }
    parse_session(&bytes, ext == "xfp")
}

// RC4 is required only for compatibility with the existing session format.
fn rc4(key: &[u8], data: &mut [u8]) {
    let mut state = Zeroizing::new([0u8; 256]);
    for (i, n) in state.iter_mut().enumerate() {
        *n = i as u8;
    }
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + state[i] as usize + key[i % key.len()] as usize) & 255;
        state.swap(i, j);
    }
    let (mut i, mut j) = (0usize, 0usize);
    for b in data {
        i = (i + 1) & 255;
        j = (j + state[i] as usize) & 255;
        state.swap(i, j);
        *b ^= state[(state[i] as usize + state[j] as usize) & 255];
    }
}

pub fn decrypt(
    encoded: &str,
    user: &str,
    sid: &str,
    version: Version,
) -> Result<(Zeroizing<String>, &'static str), String> {
    let user = user.trim();
    let sid = sid.trim();
    if user.is_empty() || !user.is_ascii() {
        return Err(
            "请输入原 Windows 用户名（当前兼容规则仅支持 ASCII 用户名，不含计算机名）".into(),
        );
    }
    if !sid.starts_with("S-1-")
        || !sid[2..]
            .split('-')
            .all(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err("请输入原 Windows 账户 SID，例如 S-1-5-21-…".into());
    }
    let payload = decode_payload(encoded)?;
    let candidates: &[bool] = match version {
        Version::Auto => &[true, false],
        Version::V6 => &[false],
        Version::V7 | Version::V8 => &[true],
    };
    for modern in candidates {
        let material = Zeroizing::new(if *modern {
            format!("{}{user}", sid.chars().rev().collect::<String>())
        } else {
            format!("{user}{sid}")
        });
        if let Some(plain) = decrypt_payload(&payload, &material)? {
            return Ok((plain, if *modern { "7 / 8" } else { "6" }));
        }
    }
    Err("校验未通过：请检查原账户用户名、SID 和版本；若设置过主密码，请切换到主密码模式；也可能是其他加密格式".into())
}

/// Decrypt with the explicitly supplied master password, without OS account data.
pub fn decrypt_master(
    encoded: &str,
    master: &str,
) -> Result<(Zeroizing<String>, &'static str), String> {
    if master.is_empty() {
        return Err("请输入保存会话时设置的主密码".into());
    }
    let payload = decode_payload(encoded)?;
    decrypt_payload(&payload, master)?
        .map(|plain| (plain, "主密码"))
        .ok_or_else(|| {
            "主密码校验未通过：请检查主密码是否与保存/导出时一致；文件也可能损坏或使用其他加密格式"
                .into()
        })
}

fn decode_payload(encoded: &str) -> Result<Vec<u8>, String> {
    let compact: String = encoded
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let payload = STANDARD
        .decode(&compact)
        .map_err(|_| "Password 不是有效的 Base64".to_string())?;
    if payload.len() < 32 {
        return Err("密码数据过短，缺少校验值".into());
    }
    Ok(payload)
}

fn decrypt_payload(payload: &[u8], material: &str) -> Result<Option<Zeroizing<String>>, String> {
    let (cipher, expected) = payload.split_at(payload.len() - 32);
    let mut key = Sha256::digest(material.as_bytes());
    let mut plain = Zeroizing::new(cipher.to_vec());
    rc4(&key, &mut plain);
    key.as_mut_slice().zeroize();
    let mut actual = Sha256::digest(&*plain);
    let difference = actual
        .iter()
        .zip(expected)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    actual.as_mut_slice().zeroize();
    if difference != 0 {
        return Ok(None);
    }
    let text = std::str::from_utf8(&plain)
        .map_err(|_| "校验通过，但密码不是 UTF-8，无法安全显示".to_string())?;
    Ok(Some(Zeroizing::new(text.to_owned())))
}

#[cfg(test)]
mod tests {
    use super::*;
    const USER: &str = "testuser";
    const SID: &str = "S-1-5-21-111-222-333-1001";
    const V6: &str = "dwYgTON5q9d31mUVmQAzuaBbjSI1KS1WUG5wxQnIsMdYVc/SCociM+/tT/mssBD6Sg==";
    const V78: &str = "D42FwExKSic5o7ezZURg87xbjSI1KS1WUG5wxQnIsMdYVc/SCociM+/tT/mssBD6Sg==";
    #[test]
    fn search_matches_ip_name_user_and_combined_words() {
        let path = "sessions/后台/Production.xsh";
        let detail = "192.0.2.12:22 · 登录用户 admin";
        for query in [
            "",
            "后台",
            "production",
            "192.0.2",
            "ADMIN",
            "后台 192.0.2 admin",
        ] {
            assert!(matches_query(query, path, detail));
        }
        assert!(!matches_query("192.0.2 missing", path, detail));
    }
    #[test]
    fn published_master_password_vector() {
        let encoded = "Rrm3P3AL0iDV7nBbS2bHvh7ZAvuN1NSJl8ZFL11+UJ+82+KAixa89O3OTAfRTg==";
        assert_eq!(
            decrypt_master(encoded, "123123").unwrap().0.as_str(),
            "This is a test"
        );
        assert!(decrypt_master(encoded, "wrong").is_err());
        assert!(decrypt_master(encoded, "").is_err());
        assert!(decrypt_master("not base64", "123123").is_err());
    }
    #[test]
    fn master_preserves_unicode_and_whitespace() {
        // Independently generated with Python hashlib + PyCryptodome, including spaces.
        let encoded = "v4eI0W4Tn9eBCsbUYN0SQEFbjSI1KS1WUG5wxQnIsMdYVc/SCociM+/tT/mssBD6Sg==";
        assert_eq!(
            decrypt_master(encoded, " 主密码-Test! ")
                .unwrap()
                .0
                .as_str(),
            "Test-only_密码!"
        );
        assert!(decrypt_master(encoded, "主密码-Test!").is_err());
        assert!(decrypt(encoded, USER, SID, Version::Auto).is_err());
    }
    // Independent vectors generated using Python hashlib + PyCryptodome ARC4.
    #[test]
    fn python_compatibility_vectors() {
        for (input, version) in [
            (V6, Version::V6),
            (V6, Version::Auto),
            (V78, Version::V7),
            (V78, Version::V8),
            (V78, Version::Auto),
        ] {
            assert_eq!(
                decrypt(input, USER, SID, version).unwrap().0.as_str(),
                "Test-only_密码!"
            );
        }
    }
    #[test]
    fn rejects_wrong_identity_and_version() {
        assert!(decrypt(V78, "someone", SID, Version::Auto).is_err());
        assert!(decrypt(V78, USER, "S-1-5-21-999", Version::Auto).is_err());
        assert!(decrypt(V78, USER, SID, Version::V6).is_err());
        assert!(decrypt(V6, USER, SID, Version::V8).is_err());
    }
    #[test]
    fn rejects_corruption_and_bad_inputs() {
        for bad in ["", "!", "YWJj", &V78.replacen('D', "A", 1)] {
            assert!(decrypt(bad, USER, SID, Version::Auto).is_err());
        }
        assert!(decrypt(V78, USER, "oops", Version::Auto).is_err());
        assert!(decrypt(V78, "", SID, Version::Auto).is_err());
    }
    #[test]
    fn rc4_standard_vector() {
        let mut data = b"Plaintext".to_vec();
        rc4(b"Key", &mut data);
        assert_eq!(data, [0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3]);
    }
    #[test]
    fn parses_sections_and_equal_signs() {
        let s = parse_session(b"[SessionInfo]\nVersion=8.0\n[CONNECTION]\nHost=example.test\nPort=22\n[CONNECTION:AUTHENTICATION]\nUserName=root\nPassword=abc==\n[OTHER]\nPassword=wrong", false).unwrap();
        assert_eq!(s.encrypted, "abc==");
        assert_eq!(s.version, "8.0");
    }
    #[test]
    fn parses_utf16_both_orders_and_xftp() {
        let text = "[Connection]\r\nHost=测试.test\r\nUserName=test\r\nPassword=abc==";
        for little in [true, false] {
            let mut bytes = if little {
                vec![0xff, 0xfe]
            } else {
                vec![0xfe, 0xff]
            };
            for w in text.encode_utf16() {
                bytes.extend(if little {
                    w.to_le_bytes()
                } else {
                    w.to_be_bytes()
                });
            }
            assert_eq!(parse_session(&bytes, true).unwrap().host, "测试.test");
        }
    }
    #[test]
    fn rejects_missing_password_and_duplicates() {
        assert!(parse_session(b"[CONNECTION]\nHost=test", false).is_err());
        assert!(parse_session(b"[CONNECTION]\nHost=test\nHost=other", false).is_err());
        assert!(decode_text(&[0xff, 0xfe, 0]).is_err());
    }
    #[test]
    fn fixture_end_to_end() {
        let s = read_session(Path::new("tests/fixtures/xshell8-synthetic.xsh")).unwrap();
        assert_eq!(s.version, "8.0");
        assert_eq!(
            decrypt(&s.encrypted, USER, SID, Version::V8)
                .unwrap()
                .0
                .as_str(),
            "Test-only_密码!"
        );
    }
}
