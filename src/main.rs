#![windows_subsystem = "windows"]

use eframe::egui;
use std::{path::PathBuf, sync::mpsc, time::Duration};
use xdecrypt_rust::{
    Version, decrypt,
    discovery::{self, Discovery},
    imports::{MAX_SESSIONS, read_source},
};
use zeroize::Zeroizing;

struct Row {
    path: String,
    detail: String,
    result: Result<(Zeroizing<String>, &'static str), String>,
    visible: bool,
}

enum JobResult {
    Discovered(Discovery),
    Recovered(Vec<Row>),
}

#[derive(Default)]
struct App {
    paths: Vec<PathBuf>,
    user: String,
    sid: String,
    version: Version,
    rows: Vec<Row>,
    status: String,
    pending: Option<mpsc::Receiver<JobResult>>,
}

fn current_identity() -> Result<(String, String), String> {
    use std::os::windows::process::CommandExt;
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn GetUserNameW(buffer: *mut u16, size: *mut u32) -> i32;
    }
    let mut name = [0u16; 257];
    let mut size = name.len() as u32;
    // Buffer has 257 UTF-16 code units, enough for UNLEN plus terminator.
    if unsafe { GetUserNameW(name.as_mut_ptr(), &mut size) } == 0 {
        return Err("无法读取当前 Windows 用户名".into());
    }
    let user = String::from_utf16_lossy(&name[..size.saturating_sub(1) as usize]);
    let root = std::env::var_os("SystemRoot").ok_or("无法定位 Windows 目录")?;
    let output = std::process::Command::new(PathBuf::from(root).join("System32/whoami.exe"))
        .args(["/user", "/fo", "csv", "/nh"])
        .creation_flags(0x08000000)
        .output()
        .map_err(|_| "无法读取当前 Windows SID")?;
    if !output.status.success() {
        return Err("读取 SID 失败，请手动输入".into());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let sid = text
        .trim()
        .rsplit(',')
        .next()
        .unwrap_or("")
        .trim_matches('"')
        .to_string();
    if !sid.starts_with("S-1-") {
        return Err("未识别当前账户 SID，请手动输入".into());
    }
    Ok((user, sid))
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut fonts = egui::FontDefinitions::default();
        let windows = std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("C:/Windows"));
        for file in ["msyh.ttc", "simhei.ttf", "simsun.ttc"] {
            if let Ok(data) = std::fs::read(windows.join("Fonts").join(file)) {
                fonts
                    .font_data
                    .insert("chinese".into(), egui::FontData::from_owned(data).into());
                fonts
                    .families
                    .entry(egui::FontFamily::Proportional)
                    .or_default()
                    .insert(0, "chinese".into());
                fonts
                    .families
                    .entry(egui::FontFamily::Monospace)
                    .or_default()
                    .push("chinese".into());
                break;
            }
        }
        cc.egui_ctx.set_fonts(fonts);
        cc.egui_ctx.set_visuals(egui::Visuals::light());
        let mut style = (*cc.egui_ctx.style_of(egui::Theme::Light)).clone();
        style.spacing.item_spacing = egui::vec2(10., 10.);
        style.spacing.button_padding = egui::vec2(14., 8.);
        cc.egui_ctx.set_style_of(egui::Theme::Light, style);
        let mut app = Self {
            status: "正在搜索当前用户的默认会话目录…".into(),
            ..Self::default()
        };
        if let Ok((user, sid)) = current_identity() {
            app.user = user;
            app.sid = sid;
        }
        app.search(discovery::default_roots());
        app
    }

    fn search(&mut self, roots: Vec<PathBuf>) {
        self.rows.clear();
        self.status = "正在搜索会话文件…".into();
        let (send, receive) = mpsc::channel();
        self.pending = Some(receive);
        std::thread::spawn(move || {
            let _ = send.send(JobResult::Discovered(discovery::discover(&roots)));
        });
    }

    fn start(&mut self) {
        self.rows.clear();
        let paths = self.paths.clone();
        let user = self.user.clone();
        let sid = self.sid.clone();
        let version = self.version;
        let (send, receive) = mpsc::channel();
        self.pending = Some(receive);
        self.status = "正在读取并校验所选文件…".into();
        std::thread::spawn(move || {
            let mut rows = Vec::new();
            'sources: for path in paths {
                let imported = match read_source(&path) {
                    Ok(sessions) => sessions,
                    Err(error) => {
                        rows.push(Row {
                            path: path.display().to_string(),
                            detail: String::new(),
                            result: Err(error),
                            visible: false,
                        });
                        continue;
                    }
                };
                for item in imported {
                    if rows.len() >= MAX_SESSIONS {
                        rows.push(Row {
                            path: "处理上限".into(),
                            detail: String::new(),
                            result: Err("单次最多处理 1000 个会话，请分批选择文件".into()),
                            visible: false,
                        });
                        break 'sources;
                    }
                    let (detail, result) = match item.session {
                        Ok(session) => {
                            let detail = format!(
                                "{}:{}  ·  登录用户 {}  ·  文件版本 {}",
                                session.host,
                                session.port,
                                session.username,
                                if session.version.is_empty() {
                                    "未标注"
                                } else {
                                    &session.version
                                }
                            );
                            (detail, decrypt(&session.encrypted, &user, &sid, version))
                        }
                        Err(e) => (String::new(), Err(e)),
                    };
                    rows.push(Row {
                        path: item.label,
                        detail,
                        result,
                        visible: false,
                    });
                }
            }
            let _ = send.send(JobResult::Recovered(rows));
        });
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _: &mut eframe::Frame) {
        if let Some(receiver) = &self.pending {
            match receiver.try_recv() {
                Ok(JobResult::Discovered(found)) => {
                    self.paths = found.paths;
                    self.status = if self.paths.is_empty() {
                        "未找到会话。可点击“搜索目录…”选择自定义数据目录，或直接选择 .xts 导出包。"
                            .into()
                    } else {
                        format!(
                            "发现 {} 个会话文件/导出包，已加入列表。确认原账户信息后点击“开始恢复”。",
                            self.paths.len()
                        )
                    };
                    if !found.warnings.is_empty() {
                        self.status
                            .push_str(&format!(" 部分目录未搜索：{}", found.warnings.join("；")));
                    }
                    self.pending = None;
                }
                Ok(JobResult::Recovered(rows)) => {
                    let count = rows.iter().filter(|r| r.result.is_ok()).count();
                    self.status = format!(
                        "处理完成：{} 个会话/结果，{} 个校验通过，{} 个未恢复。",
                        rows.len(),
                        count,
                        rows.len() - count
                    );
                    self.rows = rows;
                    self.pending = None;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.pending = None;
                    self.status = "处理未完成，请重试。".into();
                }
                Err(mpsc::TryRecvError::Empty) => {
                    ui.ctx().request_repaint_after(Duration::from_millis(100));
                }
            }
        }
        if !ui.ctx().input(|i| i.focused) {
            for row in &mut self.rows {
                row.visible = false;
            }
        }
        egui::CentralPanel::default().show(ui, |ui| {
            ui.add_space(6.);
            ui.heading(concat!("Xdecrypt Rust ", env!("CARGO_PKG_VERSION")));
            ui.label("Xshell / Xftp 会话密码恢复  ·  6 / 7 / 8  ·  本地离线");
            ui.separator();
            ui.add_enabled_ui(self.pending.is_none(), |ui| {
                ui.horizontal_wrapped(|ui| {
                    if ui.button("自动搜索").clicked() { self.search(discovery::default_roots()); }
                    if ui.button("搜索目录…").clicked()
                        && let Some(directory) = rfd::FileDialog::new().set_title("选择要搜索的会话目录").pick_folder() { self.search(vec![directory]); }
                    if ui.button("选择文件 / XTS…").clicked()
                        && let Some(paths) = rfd::FileDialog::new().set_title("选择会话文件或 XTS 导出包").add_filter("会话 / XTS 导出包", &["xsh","xfp","xts"]).pick_files() {
                            if paths.len() > MAX_SESSIONS { self.status = "每次最多选择 1000 个文件，请重新选择。".into(); }
                            else { self.paths = paths; self.rows.clear(); self.status = format!("已选择 {} 个文件，填写原 Windows 账户信息后开始恢复。", self.paths.len()); }
                        }
                    if ui.button("清空").clicked() { self.paths.clear(); self.rows.clear(); self.status = "已清空所选文件与恢复结果。".into(); }
                    ui.label(format!("已选 {} 个", self.paths.len()));
                });
                ui.small("启动自动发现当前用户 Documents 下 NetSarang Computer 的 6 / 7 / 8 目录。自定义路径请用“搜索目录…”。");
                egui::CollapsingHeader::new("查看所选文件").show(ui, |ui| {
                    egui::ScrollArea::vertical().max_height(110.).show(ui, |ui| { for path in &self.paths { ui.label(path.display().to_string()); } });
                });
                ui.separator();
                ui.label(egui::RichText::new("原 Windows 账户信息").strong());
                ui.label("使用保存会话时的 Windows 用户名与 SID；不是服务器登录账号。迁移文件请填写原电脑的信息。");
                let mut changed = false;
                egui::Grid::new("identity").num_columns(2).spacing([16.,10.]).show(ui, |ui| {
                    ui.label("Windows 用户名");
                    changed |= ui.add(egui::TextEdit::singleline(&mut self.user).desired_width(470.).hint_text("例如 Administrator，不含计算机名\\ 前缀")).changed(); ui.end_row();
                    ui.label("Windows SID");
                    changed |= ui.add(egui::TextEdit::singleline(&mut self.sid).desired_width(470.).hint_text("S-1-5-21-…")).changed(); ui.end_row();
                    ui.label("会话加密版本");
                    ui.horizontal(|ui| { for version in [Version::Auto,Version::V6,Version::V7,Version::V8] { changed |= ui.selectable_value(&mut self.version,version,version.label()).changed(); } }); ui.end_row();
                });
                if ui.button("填入当前 Windows 账户").clicked() {
                    match current_identity() { Ok((user,sid)) => { self.user = user; self.sid = sid; changed = true; self.status = "已填入当前 Windows 账户。".into(); }, Err(e) => self.status = e }
                }
                if changed { self.rows.clear(); }
                ui.add_space(4.);
                if ui.add_enabled(!self.paths.is_empty() && !self.user.trim().is_empty() && !self.sid.trim().is_empty(), egui::Button::new(egui::RichText::new("开始恢复").strong()).fill(egui::Color32::from_rgb(174,225,211))).clicked() { self.start(); }
            });
            ui.separator();
            ui.label(&self.status);
            ui.small("7 / 8 共用密钥规则；Xshell 8 已完成算法测试，真实会话兼容性待验证。主密码保护与认证配置文件暂不支持。");
            ui.add_space(4.);
            egui::ScrollArea::vertical().auto_shrink([false,false]).show(ui, |ui| {
                for row in &mut self.rows {
                    ui.group(|ui| {
                        ui.label(egui::RichText::new(row.path.rsplit(['/', '\\']).next().unwrap_or(&row.path)).strong());
                        ui.small(&row.path);
                        if !row.detail.is_empty() { ui.label(&row.detail); }
                        match &row.result {
                            Ok((secret, algorithm)) => {
                                ui.horizontal(|ui| { ui.colored_label(egui::Color32::from_rgb(20,120,88), format!("校验通过 · {algorithm}")); ui.checkbox(&mut row.visible,"显示密码"); });
                                if row.visible { ui.label(egui::RichText::new(if secret.is_empty() { "（空密码）" } else { secret.as_str() }).monospace()); }
                                else { ui.label("密码：••••••••"); }
                            }
                            Err(e) => { ui.colored_label(egui::Color32::from_rgb(180,65,45), e); }
                        }
                    });
                }
            });
        });
    }
}

fn main() -> eframe::Result {
    eframe::run_native(
        "Xdecrypt Rust",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([870., 730.])
                .with_min_inner_size([680., 560.]),
            renderer: eframe::Renderer::Glow,
            ..Default::default()
        },
        Box::new(|cc| Ok(Box::new(App::new(cc)))),
    )
}
