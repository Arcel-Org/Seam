/// Interactive TUI — launched when `seam` is run with no arguments.
///
/// Shortcuts:
///   1-9  0  w  p  r  m  — select action directly
///   Tab / Shift-Tab      — cycle focus (Host → Actions → Param → Recent)
///   ↑↓  /  j k          — move in action/recent list
///   Ctrl-A / Home        — start of line
///   Ctrl-E / End         — end of line
///   Ctrl-K               — kill to end of line
///   Ctrl-W               — delete word back
///   Enter                — run command or select recent
///   ?                    — toggle help overlay
///   Esc / q              — quit (outside text fields)
///   Ctrl-C               — quit always
use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
};
use std::io;
use std::path::PathBuf;

const VERSION: &str = env!("CARGO_PKG_VERSION");

// ── Palette ───────────────────────────────────────────────────────────────────

const C_ACCENT: Color = Color::Cyan;
const C_GREEN: Color = Color::Green;
const C_YELLOW: Color = Color::Yellow;
const C_RED: Color = Color::Red;
const C_WHITE: Color = Color::White;
const C_GRAY: Color = Color::Gray;
const C_DIM: Color = Color::DarkGray;
const C_HL_BG: Color = Color::Cyan;
const C_HL_FG: Color = Color::Black;

fn style_accent() -> Style {
    Style::default().fg(C_ACCENT)
}
fn style_dim() -> Style {
    Style::default().fg(C_DIM)
}
fn style_muted() -> Style {
    Style::default().fg(C_GRAY)
}
fn style_white() -> Style {
    Style::default().fg(C_WHITE)
}
fn style_bold(c: Color) -> Style {
    Style::default().fg(c).add_modifier(Modifier::BOLD)
}
fn border_style(focused: bool) -> Style {
    if focused { style_accent() } else { style_dim() }
}

// ── Actions ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
enum Action {
    Shell,
    Forward,
    Tunnel,
    Fwd,
    Copy,
    Sync,
    Ping,
    Proxy,
    Scan,
    Share,
    Watch,
    Punch,
    Route,
    Mount,
}

impl Action {
    const ALL: &'static [Action] = &[
        Action::Shell,
        Action::Forward,
        Action::Tunnel,
        Action::Fwd,
        Action::Copy,
        Action::Sync,
        Action::Ping,
        Action::Proxy,
        Action::Scan,
        // ── extra ──
        Action::Share,
        Action::Watch,
        Action::Punch,
        Action::Route,
        Action::Mount,
    ];

    fn shortcut(self) -> char {
        match self {
            Action::Shell => '1',
            Action::Forward => '2',
            Action::Tunnel => '3',
            Action::Fwd => '4',
            Action::Copy => '5',
            Action::Sync => '6',
            Action::Ping => '7',
            Action::Proxy => '8',
            Action::Scan => '9',
            Action::Share => '0',
            Action::Watch => 'w',
            Action::Punch => 'p',
            Action::Route => 'r',
            Action::Mount => 'm',
        }
    }

    fn icon(self) -> &'static str {
        match self {
            Action::Shell => ">_",
            Action::Forward => "→ ",
            Action::Tunnel => "⇄ ",
            Action::Fwd => "← ",
            Action::Copy => "⊕ ",
            Action::Sync => "↺ ",
            Action::Ping => "◎ ",
            Action::Proxy => "⬡ ",
            Action::Scan => "⊙ ",
            Action::Share => "↑ ",
            Action::Watch => "◉ ",
            Action::Punch => "><",
            Action::Route => "↪ ",
            Action::Mount => "⊞ ",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Action::Shell => "Shell",
            Action::Forward => "Forward",
            Action::Tunnel => "Tunnel",
            Action::Fwd => "Reverse",
            Action::Copy => "Copy",
            Action::Sync => "Sync",
            Action::Ping => "Ping",
            Action::Proxy => "Proxy",
            Action::Scan => "Scan",
            Action::Share => "Share",
            Action::Watch => "Watch",
            Action::Punch => "Punch",
            Action::Route => "Route",
            Action::Mount => "Mount",
        }
    }

    fn desc(self) -> &'static str {
        match self {
            Action::Shell => "remote terminal",
            Action::Forward => "local → remote  (ssh -L)",
            Action::Tunnel => "expose local port to relay",
            Action::Fwd => "remote → local  (ssh -R)",
            Action::Copy => "transfer files",
            Action::Sync => "mirror directory",
            Action::Ping => "measure round-trip latency",
            Action::Proxy => "SOCKS5 proxy via remote host",
            Action::Scan => "TCP port scanner",
            Action::Share => "one-time share link with token",
            Action::Watch => "live directory sync on change",
            Action::Punch => "NAT hole punch via STUN",
            Action::Route => "multi-hop through relay(s)",
            Action::Mount => "mount remote filesystem (FUSE)",
        }
    }

    fn param_label(self) -> Option<&'static str> {
        match self {
            Action::Forward => Some("Spec"),
            Action::Tunnel => Some("Ports"),
            Action::Fwd => Some("Spec"),
            Action::Copy => Some("Path"),
            Action::Sync => Some("Path"),
            Action::Proxy => Some("Local port"),
            Action::Scan => Some("Ports"),
            Action::Share => Some("File/dir"),
            Action::Watch => Some("Local path"),
            Action::Route => Some("Via hops"),
            Action::Mount => Some("Mountpoint"),
            _ => None,
        }
    }

    fn param_placeholder(self) -> &'static str {
        match self {
            Action::Forward => "8080:localhost:80",
            Action::Tunnel => "8080 8443",
            Action::Fwd => "3000:8080",
            Action::Copy => "./file.txt",
            Action::Sync => "./mydir",
            Action::Proxy => "1080",
            Action::Scan => "22,80,443",
            Action::Share => "./file.txt",
            Action::Watch => "./mydir",
            Action::Route => "--via relay1.example.com",
            Action::Mount => "/mnt/remote",
            _ => "",
        }
    }

    fn needs_param(self) -> bool {
        self.param_label().is_some()
    }

    fn to_args(self, host: &str, param: &str) -> Vec<String> {
        let host = host.trim().to_string();
        let param = param.trim().to_string();
        match self {
            Action::Shell => vec!["shell".into(), host],
            Action::Forward => vec!["forward".into(), param, host],
            Action::Tunnel => {
                let mut a = vec!["tunnel".into()];
                a.extend(param.split_whitespace().map(str::to_string));
                a.push(host);
                a
            }
            Action::Fwd => {
                let parts: Vec<&str> = param.splitn(2, ':').collect();
                let (rp, lp) = if parts.len() == 2 {
                    (parts[0], parts[1].parse::<u16>().unwrap_or(8080))
                } else {
                    (param.as_str(), 8080u16)
                };
                vec!["fwd".into(), format!("{host}:{rp}"), lp.to_string()]
            }
            Action::Copy => {
                if param.contains('@') || (param.starts_with('/') && host.contains(':')) {
                    vec!["cp".into(), param, host]
                } else {
                    vec!["cp".into(), param, format!("{host}:")]
                }
            }
            Action::Sync => {
                if param.contains('@') {
                    vec!["sync".into(), param, host]
                } else {
                    vec!["sync".into(), param, format!("{host}:")]
                }
            }
            Action::Ping => vec!["ping".into(), host],
            Action::Proxy => {
                let port = if param.is_empty() { "1080" } else { &param };
                vec!["proxy".into(), host, "--port".into(), port.into()]
            }
            Action::Scan => {
                let mut a = vec!["scan".into(), host];
                if !param.is_empty() {
                    a.extend(["--ports".into(), param]);
                }
                a
            }
            Action::Share => {
                let mut a = vec!["share".into()];
                if !param.is_empty() {
                    a.push(param);
                }
                a
            }
            Action::Watch => {
                if !param.is_empty() {
                    vec!["watch".into(), param, format!("{host}:")]
                } else {
                    vec!["watch".into(), host]
                }
            }
            Action::Punch => vec!["punch".into(), "--peer".into(), host],
            Action::Route => {
                let mut a = vec!["route".into()];
                if !param.is_empty() {
                    a.extend(param.split_whitespace().map(str::to_string));
                }
                a.push(host);
                a
            }
            Action::Mount => {
                let mp = if param.is_empty() {
                    "/mnt/remote".into()
                } else {
                    param
                };
                vec!["mount".into(), format!("{host}:/"), mp]
            }
        }
    }

    fn from_shortcut(c: char) -> Option<usize> {
        Action::ALL.iter().position(|a| a.shortcut() == c)
    }
}

// ── Recent connections ────────────────────────────────────────────────────────

#[derive(Clone)]
struct Recent {
    remote: String,
    subcommand: String,
    ts: String,
}

fn audit_log_path() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("seam")
        .join("audit.jsonl")
}

fn load_recent() -> Vec<Recent> {
    let text = std::fs::read_to_string(audit_log_path()).unwrap_or_default();
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for line in text.lines().rev() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            let remote = v["remote"].as_str().unwrap_or("").to_string();
            if remote.is_empty() || !remote.contains('@') {
                continue;
            }
            let subcommand = v["subcommand"].as_str().unwrap_or("").to_string();
            if subcommand.starts_with('_') || matches!(subcommand.as_str(), "recv" | "serve") {
                continue;
            }
            let ts = v["ts"].as_str().unwrap_or("").to_string();
            let key = format!("{remote}:{subcommand}");
            if seen.insert(key) {
                out.push(Recent {
                    remote,
                    subcommand,
                    ts,
                });
                if out.len() >= 10 {
                    break;
                }
            }
        }
    }
    out
}

fn format_ts_ago(ts: &str) -> String {
    if ts.len() >= 16 {
        format!("{} {}", &ts[5..10], &ts[11..16])
    } else {
        ts.to_string()
    }
}

fn load_identity_fp() -> String {
    let path = dirs::config_dir()
        .unwrap_or_default()
        .join("seam")
        .join("identity");
    match std::fs::read(&path) {
        Ok(b) if b.len() >= 4 => format!("{:02x}:{:02x}:{:02x}:{:02x}", b[0], b[1], b[2], b[3]),
        _ => "--:--:--:--".into(),
    }
}

// ── Focus ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
enum Focus {
    Host,
    Actions,
    Param,
    Recent,
}

// ── App state ─────────────────────────────────────────────────────────────────

struct App {
    focus: Focus,
    host: String,
    host_cursor: usize,
    action_idx: usize,
    param: String,
    param_cursor: usize,
    recent: Vec<Recent>,
    recent_state: ListState,
    last_run: Option<(String, i32)>,
    validation: Option<String>,
    show_help: bool,
    identity_fp: String,
}

impl App {
    fn new() -> Self {
        let recent = load_recent();
        let mut recent_state = ListState::default();
        if !recent.is_empty() {
            recent_state.select(Some(0));
        }
        Self {
            focus: Focus::Host,
            host: String::new(),
            host_cursor: 0,
            action_idx: 0,
            param: String::new(),
            param_cursor: 0,
            recent,
            recent_state,
            last_run: None,
            validation: None,
            show_help: false,
            identity_fp: load_identity_fp(),
        }
    }

    fn action(&self) -> Action {
        Action::ALL[self.action_idx]
    }
    fn needs_param(&self) -> bool {
        self.action().needs_param()
    }

    fn ready(&self) -> bool {
        let h = self.host.trim();
        if h.is_empty() {
            return false;
        }
        match self.action() {
            Action::Proxy | Action::Scan | Action::Share => true,
            a if a.needs_param() => !self.param.trim().is_empty(),
            _ => true,
        }
    }

    fn build_args(&self) -> Vec<String> {
        self.action().to_args(&self.host, &self.param)
    }
    fn preview_command(&self) -> String {
        let args = self.build_args();
        format!("seam {}", args.join(" "))
    }

    fn on_command_return(&mut self, cmd: String, exit_code: i32) {
        self.last_run = Some((cmd, exit_code));
        self.validation = None;
        let new_recent = load_recent();
        let had = !self.recent.is_empty();
        let prev = self.recent_state.selected().unwrap_or(0);
        self.recent = new_recent;
        if !self.recent.is_empty() {
            self.recent_state.select(Some(if had {
                prev.min(self.recent.len() - 1)
            } else {
                0
            }));
        }
    }

    // ── Text editing ──────────────────────────────────────────────────────────

    fn insert_char(&mut self, ch: char) {
        match self.focus {
            Focus::Host => {
                self.host.insert(self.host_cursor, ch);
                self.host_cursor += ch.len_utf8();
            }
            Focus::Param => {
                self.param.insert(self.param_cursor, ch);
                self.param_cursor += ch.len_utf8();
            }
            _ => {}
        }
    }

    fn backspace(&mut self) {
        match self.focus {
            Focus::Host if self.host_cursor > 0 => {
                let p = prev_boundary(&self.host, self.host_cursor);
                self.host.remove(p);
                self.host_cursor = p;
            }
            Focus::Param if self.param_cursor > 0 => {
                let p = prev_boundary(&self.param, self.param_cursor);
                self.param.remove(p);
                self.param_cursor = p;
            }
            _ => {}
        }
    }

    fn cursor_left(&mut self) {
        match self.focus {
            Focus::Host => self.host_cursor = prev_boundary(&self.host, self.host_cursor),
            Focus::Param => self.param_cursor = prev_boundary(&self.param, self.param_cursor),
            _ => {}
        }
    }

    fn cursor_right(&mut self) {
        match self.focus {
            Focus::Host => self.host_cursor = next_boundary(&self.host, self.host_cursor),
            Focus::Param => self.param_cursor = next_boundary(&self.param, self.param_cursor),
            _ => {}
        }
    }

    fn cursor_home(&mut self) {
        match self.focus {
            Focus::Host => self.host_cursor = 0,
            Focus::Param => self.param_cursor = 0,
            _ => {}
        }
    }

    fn cursor_end(&mut self) {
        match self.focus {
            Focus::Host => self.host_cursor = self.host.len(),
            Focus::Param => self.param_cursor = self.param.len(),
            _ => {}
        }
    }

    fn delete_word(&mut self) {
        match self.focus {
            Focus::Host => del_word_back(&mut self.host, &mut self.host_cursor),
            Focus::Param => del_word_back(&mut self.param, &mut self.param_cursor),
            _ => {}
        }
    }

    fn kill_to_end(&mut self) {
        match self.focus {
            Focus::Host => {
                self.host.truncate(self.host_cursor);
            }
            Focus::Param => {
                self.param.truncate(self.param_cursor);
            }
            _ => {}
        }
    }

    // ── Navigation ────────────────────────────────────────────────────────────

    fn action_up(&mut self) {
        if self.action_idx > 0 {
            self.action_idx -= 1;
            self.param.clear();
            self.param_cursor = 0;
        }
    }

    fn action_down(&mut self) {
        if self.action_idx + 1 < Action::ALL.len() {
            self.action_idx += 1;
            self.param.clear();
            self.param_cursor = 0;
        }
    }

    fn recent_up(&mut self) {
        if let Some(i) = self.recent_state.selected()
            && i > 0
        {
            self.recent_state.select(Some(i - 1));
        }
    }

    fn recent_down(&mut self) {
        if let Some(i) = self.recent_state.selected()
            && i + 1 < self.recent.len()
        {
            self.recent_state.select(Some(i + 1));
        }
    }

    fn select_recent(&mut self) {
        if let Some(i) = self.recent_state.selected()
            && let Some(r) = self.recent.get(i)
        {
            self.host = r.remote.clone();
            self.host_cursor = self.host.len();
            self.focus = Focus::Actions;
            self.validation = None;
        }
    }

    fn set_action(&mut self, idx: usize) {
        self.action_idx = idx;
        self.param.clear();
        self.param_cursor = 0;
        self.focus = if Action::ALL[idx].needs_param() {
            Focus::Param
        } else {
            Focus::Actions
        };
    }

    fn tab_next(&mut self) {
        self.focus = match self.focus {
            Focus::Host => Focus::Actions,
            Focus::Actions => {
                if self.needs_param() {
                    Focus::Param
                } else if !self.recent.is_empty() {
                    Focus::Recent
                } else {
                    Focus::Host
                }
            }
            Focus::Param => {
                if !self.recent.is_empty() {
                    Focus::Recent
                } else {
                    Focus::Host
                }
            }
            Focus::Recent => Focus::Host,
        };
    }

    fn tab_prev(&mut self) {
        self.focus = match self.focus {
            Focus::Host => {
                if !self.recent.is_empty() {
                    Focus::Recent
                } else if self.needs_param() {
                    Focus::Param
                } else {
                    Focus::Actions
                }
            }
            Focus::Actions => Focus::Host,
            Focus::Param => Focus::Actions,
            Focus::Recent => {
                if self.needs_param() {
                    Focus::Param
                } else {
                    Focus::Actions
                }
            }
        };
    }
}

// ── Cursor helpers ────────────────────────────────────────────────────────────

fn prev_boundary(s: &str, pos: usize) -> usize {
    if pos == 0 {
        return 0;
    }
    let mut p = pos - 1;
    while p > 0 && !s.is_char_boundary(p) {
        p -= 1;
    }
    p
}

fn next_boundary(s: &str, pos: usize) -> usize {
    if pos >= s.len() {
        return s.len();
    }
    let mut p = pos + 1;
    while p < s.len() && !s.is_char_boundary(p) {
        p += 1;
    }
    p
}

fn del_word_back(s: &mut String, cursor: &mut usize) {
    if *cursor == 0 {
        return;
    }
    let new_end = s[..*cursor]
        .trim_end_matches(|c: char| c != ' ' && c != '/')
        .trim_end_matches([' ', '/'])
        .len();
    s.drain(new_end..*cursor);
    *cursor = new_end;
}

// ── Layout helpers ────────────────────────────────────────────────────────────

fn centered_rect(pct_x: u16, pct_y: u16, r: Rect) -> Rect {
    let vert = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - pct_y) / 2),
            Constraint::Percentage(pct_y),
            Constraint::Percentage((100 - pct_y) / 2),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - pct_x) / 2),
            Constraint::Percentage(pct_x),
            Constraint::Percentage((100 - pct_x) / 2),
        ])
        .split(vert[1])[1]
}

// ── Input rendering ───────────────────────────────────────────────────────────

fn render_input<'a>(
    text: &'a str,
    cursor: usize,
    focused: bool,
    placeholder: &'a str,
) -> Paragraph<'a> {
    let line = if focused {
        let before = &text[..cursor];
        let ch = text[cursor..]
            .chars()
            .next()
            .map(|c| c.to_string())
            .unwrap_or_else(|| " ".into());
        let after: String = text[cursor..].chars().skip(1).collect();
        Line::from(vec![
            Span::raw(" "),
            Span::styled(before, style_white()),
            Span::styled(ch, Style::default().bg(C_WHITE).fg(Color::Black)),
            Span::styled(after, style_white()),
        ])
    } else if text.is_empty() {
        Line::from(Span::styled(format!(" {placeholder}"), style_dim()))
    } else {
        Line::from(vec![Span::raw(" "), Span::styled(text, style_muted())])
    };
    Paragraph::new(line)
}

// ── Main draw ─────────────────────────────────────────────────────────────────

fn draw(f: &mut Frame, app: &mut App) {
    let full = f.area();

    // ── Outer block ───────────────────────────────────────────────────────────
    let title_l = Line::from(vec![
        Span::raw(" "),
        Span::styled("seam", style_bold(C_ACCENT)),
        Span::styled(format!("  v{VERSION}"), style_dim()),
        Span::raw("  "),
    ]);
    let title_r = Line::from(vec![Span::styled(
        format!(" id:{} ", app.identity_fp),
        style_dim(),
    )])
    .right_aligned();
    let outer = Block::default()
        .title_top(title_l)
        .title_top(title_r)
        .borders(Borders::ALL)
        .border_style(style_dim());
    let inner = outer.inner(full);
    f.render_widget(outer, full);

    // ── Horizontal split: recent | form ───────────────────────────────────────
    let recent_w: u16 = if app.recent.is_empty() { 0 } else { 34 };
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(recent_w), Constraint::Min(0)])
        .split(inner);

    // ── Recent panel ──────────────────────────────────────────────────────────
    if !app.recent.is_empty() {
        let focused = app.focus == Focus::Recent;
        let items: Vec<ListItem> = app
            .recent
            .iter()
            .map(|r| {
                let host = trunc(&r.remote, 18);
                let cmd = format!(" {:7}", r.subcommand);
                let ts = format_ts_ago(&r.ts);
                ListItem::new(Line::from(vec![
                    Span::styled(host, style_white()),
                    Span::styled(cmd, Style::default().fg(C_ACCENT)),
                    Span::styled(ts, style_dim()),
                ]))
            })
            .collect();

        let list = List::new(items)
            .block(
                Block::default()
                    .title(Line::from(vec![
                        Span::raw(" "),
                        Span::styled("Recent", style_bold(C_ACCENT)),
                        Span::raw(" "),
                    ]))
                    .borders(Borders::ALL)
                    .border_style(border_style(focused)),
            )
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");

        f.render_stateful_widget(list, cols[0], &mut app.recent_state);
    }

    // ── Form (right column) ───────────────────────────────────────────────────
    let form = cols[1];
    let needs_param = app.needs_param();
    let param_h: u16 = if needs_param { 3 } else { 0 };
    let action_count = Action::ALL.len() as u16;
    // +1 for visual separator line, +2 for block borders
    let action_h: u16 = action_count + 3;
    let last_run_h = if app.last_run.is_some() { 1u16 } else { 0 };

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),          // host input
            Constraint::Length(1),          // spacer
            Constraint::Length(action_h),   // action list
            Constraint::Length(param_h),    // param input
            Constraint::Min(0),             // flex
            Constraint::Length(last_run_h), // last run
            Constraint::Length(1),          // command preview
            Constraint::Length(1),          // hint bar
        ])
        .split(form);

    // Host input
    {
        let focused = app.focus == Focus::Host;
        let w = render_input(&app.host, app.host_cursor, focused, "user@hostname").block(
            Block::default()
                .title(Line::from(vec![
                    Span::raw(" "),
                    Span::styled("Host", style_bold(C_ACCENT)),
                    Span::raw(" "),
                ]))
                .borders(Borders::ALL)
                .border_style(border_style(focused)),
        );
        f.render_widget(w, rows[0]);
    }

    // Action list
    {
        let focused = app.focus == Focus::Actions;
        let mut items: Vec<ListItem> = Vec::with_capacity(Action::ALL.len() + 1);

        for (i, a) in Action::ALL.iter().enumerate() {
            // Visual separator between built-in (0-8) and extra (9+)
            if i == 9 {
                items.push(ListItem::new(Line::from(vec![Span::styled(
                    "  ───────────────────────────────────────",
                    style_dim(),
                )])));
            }

            let selected = i == app.action_idx;
            let (key_style, icon_style, name_style, desc_style) = if selected && focused {
                (
                    Style::default()
                        .bg(C_HL_BG)
                        .fg(C_HL_FG)
                        .add_modifier(Modifier::BOLD),
                    Style::default().bg(C_HL_BG).fg(C_HL_FG),
                    Style::default()
                        .bg(C_HL_BG)
                        .fg(C_HL_FG)
                        .add_modifier(Modifier::BOLD),
                    Style::default().bg(C_HL_BG).fg(C_HL_FG),
                )
            } else if selected {
                (
                    Style::default().fg(C_ACCENT).add_modifier(Modifier::BOLD),
                    Style::default().fg(C_ACCENT),
                    Style::default().fg(C_WHITE).add_modifier(Modifier::BOLD),
                    Style::default().fg(C_GRAY),
                )
            } else {
                (
                    style_dim(),
                    style_dim(),
                    Style::default().fg(C_GRAY),
                    style_dim(),
                )
            };

            items.push(ListItem::new(Line::from(vec![
                Span::styled(format!(" [{}]", a.shortcut()), key_style),
                Span::styled(format!(" {} ", a.icon()), icon_style),
                Span::styled(format!("{:<8}", a.name()), name_style),
                Span::styled("  ", Style::default()),
                Span::styled(a.desc(), desc_style),
            ])));
        }

        // offset selection for the separator line
        let display_sel = if app.action_idx >= 9 {
            app.action_idx + 1
        } else {
            app.action_idx
        };
        let mut action_state = ListState::default();
        action_state.select(Some(display_sel));

        let shortcut_hint =
            Line::from(Span::styled(" [1-9·0·w·p·r·m] ", style_dim())).right_aligned();
        let list = List::new(items).block(
            Block::default()
                .title_top(Line::from(vec![
                    Span::raw(" "),
                    Span::styled("Action", style_bold(C_ACCENT)),
                    Span::raw(" "),
                ]))
                .title_top(shortcut_hint)
                .borders(Borders::ALL)
                .border_style(border_style(focused)),
        );

        f.render_stateful_widget(list, rows[2], &mut action_state);
    }

    // Param input
    if needs_param && rows[3].height > 0 {
        let focused = app.focus == Focus::Param;
        let label = app.action().param_label().unwrap_or("Param");
        let placeholder = app.action().param_placeholder();
        let w = render_input(&app.param, app.param_cursor, focused, placeholder).block(
            Block::default()
                .title(Line::from(vec![
                    Span::raw(" "),
                    Span::styled(label, style_bold(C_ACCENT)),
                    Span::raw(" "),
                ]))
                .borders(Borders::ALL)
                .border_style(border_style(focused)),
        );
        f.render_widget(w, rows[3]);
    }

    // Last run
    if let Some((ref cmd, code)) = app.last_run
        && rows[5].height > 0
    {
        let (icon, col) = if code == 0 {
            ("✓ ", C_GREEN)
        } else {
            ("✗ ", C_RED)
        };
        let suffix = if code == 0 {
            String::new()
        } else {
            format!("  exit {code}")
        };
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(icon, style_bold(col)),
                Span::styled(
                    cmd.clone(),
                    Style::default().fg(col).add_modifier(Modifier::BOLD),
                ),
                Span::styled(suffix, style_dim()),
            ])),
            rows[5],
        );
    }

    // Command preview / validation
    if rows[6].height > 0 {
        let line = if let Some(ref msg) = app.validation {
            Line::from(Span::styled(
                format!("  ⚠  {msg}"),
                Style::default().fg(C_YELLOW),
            ))
        } else if app.ready() {
            Line::from(vec![
                Span::styled("  $ ", style_bold(C_DIM)),
                Span::styled(app.preview_command(), style_bold(C_GREEN)),
            ])
        } else if app.host.trim().is_empty() {
            Line::from(Span::styled(
                "  enter a host above  (user@hostname)",
                style_dim(),
            ))
        } else if app.needs_param() && app.param.trim().is_empty() {
            Line::from(Span::styled(
                format!(
                    "  enter {} above  (e.g. {})",
                    app.action().param_label().unwrap_or("param"),
                    app.action().param_placeholder()
                ),
                style_dim(),
            ))
        } else {
            Line::from(Span::raw(""))
        };
        f.render_widget(Paragraph::new(line), rows[6]);
    }

    // Hint bar
    if rows[7].height > 0 {
        let sep = Span::styled("  ·  ", style_dim());
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(" ↑↓/jk", style_dim()),
                sep.clone(),
                Span::styled("Tab switch", style_dim()),
                sep.clone(),
                Span::styled("Enter run", style_dim()),
                sep.clone(),
                Span::styled("? help", style_dim()),
                sep.clone(),
                Span::styled("q quit", style_dim()),
            ])),
            rows[7],
        );
    }

    // ── Help overlay ──────────────────────────────────────────────────────────
    if app.show_help {
        let area = centered_rect(62, 75, full);
        f.render_widget(Clear, area);

        let help_text = vec![
            Line::from(vec![Span::styled(
                " Keyboard shortcuts",
                style_bold(C_ACCENT),
            )]),
            Line::from(""),
            Line::from(vec![Span::styled(" Navigation", style_bold(C_WHITE))]),
            Line::from(vec![
                Span::styled("  Tab / Shift-Tab  ", style_accent()),
                Span::styled("cycle focus panels", style_muted()),
            ]),
            Line::from(vec![
                Span::styled("  ↑ ↓  /  j k     ", style_accent()),
                Span::styled("move in list", style_muted()),
            ]),
            Line::from(vec![
                Span::styled("  ← →             ", style_accent()),
                Span::styled("move text cursor", style_muted()),
            ]),
            Line::from(""),
            Line::from(vec![Span::styled(" Action shortcuts", style_bold(C_WHITE))]),
            Line::from(vec![
                Span::styled("  1-9             ", style_accent()),
                Span::styled("Shell → Scan", style_muted()),
            ]),
            Line::from(vec![
                Span::styled("  0               ", style_accent()),
                Span::styled("Share", style_muted()),
            ]),
            Line::from(vec![
                Span::styled("  w p r m         ", style_accent()),
                Span::styled("Watch  Punch  Route  Mount", style_muted()),
            ]),
            Line::from(""),
            Line::from(vec![Span::styled(" Text editing", style_bold(C_WHITE))]),
            Line::from(vec![
                Span::styled("  Ctrl-A / Home   ", style_accent()),
                Span::styled("start of line", style_muted()),
            ]),
            Line::from(vec![
                Span::styled("  Ctrl-E / End    ", style_accent()),
                Span::styled("end of line", style_muted()),
            ]),
            Line::from(vec![
                Span::styled("  Ctrl-K          ", style_accent()),
                Span::styled("delete to end of line", style_muted()),
            ]),
            Line::from(vec![
                Span::styled("  Ctrl-W          ", style_accent()),
                Span::styled("delete word back", style_muted()),
            ]),
            Line::from(""),
            Line::from(vec![Span::styled(" General", style_bold(C_WHITE))]),
            Line::from(vec![
                Span::styled("  Enter           ", style_accent()),
                Span::styled("run command / select recent", style_muted()),
            ]),
            Line::from(vec![
                Span::styled("  ?               ", style_accent()),
                Span::styled("toggle this help", style_muted()),
            ]),
            Line::from(vec![
                Span::styled("  Esc / q         ", style_accent()),
                Span::styled("quit (outside text fields)", style_muted()),
            ]),
            Line::from(vec![
                Span::styled("  Ctrl-C          ", style_accent()),
                Span::styled("quit always", style_muted()),
            ]),
        ];

        let block = Block::default()
            .title(Line::from(vec![
                Span::raw(" "),
                Span::styled("Help", style_bold(C_ACCENT)),
                Span::raw("  "),
                Span::styled("press ? to close", style_dim()),
                Span::raw(" "),
            ]))
            .borders(Borders::ALL)
            .border_style(style_accent());

        let p = Paragraph::new(help_text)
            .block(block)
            .wrap(Wrap { trim: false });

        f.render_widget(p, area);
    }
}

fn trunc(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}

// ── Terminal lifecycle ────────────────────────────────────────────────────────

fn setup() -> Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    Ok(Terminal::new(CrosstermBackend::new(stdout))?)
}

fn teardown(term: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen)?;
    term.show_cursor()?;
    Ok(())
}

fn run_command(args: &[String]) -> i32 {
    let Ok(exe) = std::env::current_exe() else {
        return 1;
    };
    std::process::Command::new(exe)
        .args(args)
        .status()
        .map(|s| s.code().unwrap_or(1))
        .unwrap_or(1)
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub fn run() -> Result<()> {
    let mut terminal = setup()?;
    terminal.clear()?;
    let mut app = App::new();

    loop {
        terminal.draw(|f| draw(f, &mut app))?;

        if !event::poll(std::time::Duration::from_millis(200))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };

        let in_text = matches!(app.focus, Focus::Host | Focus::Param);

        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            break;
        }

        // Help overlay eats all keys except ? and Ctrl-C
        if app.show_help {
            if key.code == KeyCode::Char('?') || key.code == KeyCode::Esc {
                app.show_help = false;
            }
            continue;
        }

        // Ctrl-* shortcuts (work in text mode)
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            match key.code {
                KeyCode::Char('w') if in_text => {
                    app.delete_word();
                    continue;
                }
                KeyCode::Char('a') if in_text => {
                    app.cursor_home();
                    continue;
                }
                KeyCode::Char('e') if in_text => {
                    app.cursor_end();
                    continue;
                }
                KeyCode::Char('k') if in_text => {
                    app.kill_to_end();
                    continue;
                }
                _ => {}
            }
        }

        match key.code {
            KeyCode::Esc => break,
            KeyCode::Char('q') if !in_text => break,
            KeyCode::Char('?') if !in_text => {
                app.show_help = true;
                continue;
            }

            KeyCode::Tab => {
                if key.modifiers.contains(KeyModifiers::SHIFT) {
                    app.tab_prev();
                } else {
                    app.tab_next();
                }
            }

            // Action shortcuts — work when not in a text field
            KeyCode::Char(c) if !in_text => {
                if let Some(idx) = Action::from_shortcut(c) {
                    app.set_action(idx);
                    continue;
                }
                match c {
                    'j' => match app.focus {
                        Focus::Actions => app.action_down(),
                        Focus::Recent => app.recent_down(),
                        _ => {}
                    },
                    'k' => match app.focus {
                        Focus::Actions => app.action_up(),
                        Focus::Recent => app.recent_up(),
                        _ => {}
                    },
                    _ => {}
                }
            }

            KeyCode::Up => match app.focus {
                Focus::Actions => app.action_up(),
                Focus::Recent => app.recent_up(),
                _ => {}
            },
            KeyCode::Down => match app.focus {
                Focus::Actions => app.action_down(),
                Focus::Recent => app.recent_down(),
                _ => {}
            },
            KeyCode::Left => app.cursor_left(),
            KeyCode::Right => app.cursor_right(),
            KeyCode::Home => app.cursor_home(),
            KeyCode::End => app.cursor_end(),

            KeyCode::Backspace => {
                app.backspace();
                app.validation = None;
            }
            KeyCode::Delete => {
                app.cursor_right();
                app.backspace();
            }

            KeyCode::Enter => match app.focus {
                Focus::Recent => app.select_recent(),
                _ => {
                    if app.ready() {
                        let args = app.build_args();
                        let cmd_str = app.preview_command();
                        teardown(&mut terminal)?;
                        let exit_code = run_command(&args);
                        terminal = setup()?;
                        terminal.clear()?;
                        app.on_command_return(cmd_str, exit_code);
                    } else if app.host.trim().is_empty() {
                        app.validation = Some("enter a host first  (user@hostname)".into());
                        app.focus = Focus::Host;
                    } else if app.needs_param() && app.param.trim().is_empty() {
                        let label = app.action().param_label().unwrap_or("param");
                        app.validation = Some(format!(
                            "enter {label}  (e.g. {})",
                            app.action().param_placeholder()
                        ));
                        app.focus = Focus::Param;
                    }
                }
            },

            KeyCode::Char(c) if in_text => {
                app.validation = None;
                app.insert_char(c);
            }

            _ => {}
        }
    }

    teardown(&mut terminal)?;
    Ok(())
}
