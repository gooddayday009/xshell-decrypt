use crate::imports::MAX_SESSIONS;
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

#[derive(Default)]
pub struct Discovery {
    pub paths: Vec<PathBuf>,
    pub warnings: Vec<String>,
}

pub fn roots_in_documents(documents: &Path) -> Vec<PathBuf> {
    ["6", "7", "8"]
        .iter()
        .map(|v| documents.join("NetSarang Computer").join(v))
        .collect()
}

#[cfg(windows)]
pub fn default_roots() -> Vec<PathBuf> {
    #[repr(C)]
    struct Guid {
        a: u32,
        b: u16,
        c: u16,
        d: [u8; 8],
    }
    #[link(name = "shell32")]
    unsafe extern "system" {
        fn SHGetKnownFolderPath(
            id: *const Guid,
            flags: u32,
            token: *mut std::ffi::c_void,
            path: *mut *mut u16,
        ) -> i32;
    }
    #[link(name = "ole32")]
    unsafe extern "system" {
        fn CoTaskMemFree(ptr: *mut std::ffi::c_void);
    }
    // FOLDERID_Documents includes a redirected/OneDrive Documents folder.
    let id = Guid {
        a: 0xfdd39ad0,
        b: 0x238f,
        c: 0x46af,
        d: [0xad, 0xb4, 0x6c, 0x85, 0x48, 0x03, 0x69, 0xc7],
    };
    let mut ptr = std::ptr::null_mut();
    let mut roots = Vec::new();
    unsafe {
        if SHGetKnownFolderPath(&id, 0, std::ptr::null_mut(), &mut ptr) >= 0 && !ptr.is_null() {
            let mut len = 0;
            while *ptr.add(len) != 0 {
                len += 1;
            }
            let path = String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len));
            roots.extend(roots_in_documents(Path::new(&path)));
            CoTaskMemFree(ptr.cast());
        }
    }
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        roots.extend(roots_in_documents(
            &PathBuf::from(profile).join("Documents"),
        ));
    }
    roots
}

pub fn discover(roots: &[PathBuf]) -> Discovery {
    let mut result = Discovery::default();
    let mut visited = HashSet::new();
    let mut stack: Vec<_> = roots.iter().cloned().map(|p| (p, 0)).collect();
    let mut entries_seen = 0usize;
    while let Some((directory, depth)) = stack.pop() {
        if depth > 32 || visited.len() >= 5000 {
            result
                .warnings
                .push("搜索达到目录深度/数量上限，请选择更具体的目录".into());
            break;
        }
        let metadata = match fs::symlink_metadata(&directory) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                result
                    .warnings
                    .push(format!("无法访问 {}：{e}", directory.display()));
                continue;
            }
        };
        if !metadata.is_dir() || is_link(&metadata) {
            continue;
        }
        let Ok(canonical) = directory.canonicalize() else {
            continue;
        };
        if !visited.insert(canonical) {
            continue;
        }
        let entries = match fs::read_dir(&directory) {
            Ok(v) => v,
            Err(e) => {
                result
                    .warnings
                    .push(format!("无法读取 {}：{e}", directory.display()));
                continue;
            }
        };
        for entry in entries {
            entries_seen += 1;
            if entries_seen > 50_000 {
                result
                    .warnings
                    .push("搜索达到 50000 个目录项上限，请缩小搜索目录".into());
                return result;
            }
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    result.warnings.push(e.to_string());
                    continue;
                }
            };
            let Ok(metadata) = fs::symlink_metadata(entry.path()) else {
                continue;
            };
            if is_link(&metadata) {
                continue;
            }
            if metadata.is_dir() {
                stack.push((entry.path(), depth + 1));
            } else if metadata.is_file()
                && entry.path().extension().is_some_and(|ext| {
                    ["xsh", "xfp", "xts"]
                        .iter()
                        .any(|s| ext.eq_ignore_ascii_case(s))
                })
            {
                if result.paths.len() >= MAX_SESSIONS {
                    result
                        .warnings
                        .push("最多发现 1000 个文件，请缩小搜索目录".into());
                    return result;
                }
                result.paths.push(entry.path());
            }
        }
    }
    result.paths.sort();
    result
}

fn is_link(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_roots_cover_only_versioned_current_documents() {
        let roots = roots_in_documents(Path::new("test-documents"));
        assert_eq!(roots.len(), 3);
        assert_eq!(
            roots[2],
            Path::new("test-documents")
                .join("NetSarang Computer")
                .join("8")
        );
    }
    #[test]
    fn discover_nested_files_and_deduplicate_overlapping_roots() {
        let root = std::env::temp_dir().join(format!(
            "xdecrypt-discovery-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::write(root.join("a.XSH"), b"synthetic").unwrap();
        fs::write(root.join("nested/b.xfp"), b"synthetic").unwrap();
        fs::write(root.join("nested/c.xts"), b"synthetic").unwrap();
        fs::write(root.join("ignored.txt"), b"synthetic").unwrap();
        let result = discover(&[root.clone(), root.join("nested"), root.join("absent")]);
        assert_eq!(result.paths.len(), 3);
        assert!(result.warnings.is_empty());
        fs::remove_dir_all(root).unwrap();
    }
}
