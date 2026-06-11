/// Interactive TUI — launched when `seam` is run with no arguments.
///
/// Navigation:
///   Tab / Shift-Tab  — cycle focus between panels
///   ↑ ↓  /  j k     — move through action list or recent list
///   ← →              — move cursor in text inputs
///   Enter            — confirm selection (recent) or launch command
///   Esc / q          — quit (outside text fields)
///   Ctrl-C           — quit always
use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
};
use std::io;
use std::path::PathBuf;

const VERSION: &str = env!("CARGO_PKG_VERSION");

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
    ];

    fn name(self) -> &'static str {
        match self {
            Action::Shell => "Shell",
            Action::Forward => "Forward",
            Action::Tunnel => "Tunnel",
            Action::Fwd => "Fwd",
            Action::Copy => "Copy",
            Action::Sync => "Sync",
            Action::Ping => "Ping",
            Action::Proxy => "Proxy",
            Action::Scan => "Scan",
        }
    }

    fn desc(self) -> &'static str {
        match self {
            Action::Shell => "interactive remote terminal",
            Action::Forward => "local port → remote  (ssh -L)",
            Action::Tunnel => "expose local port to remote",
            Action::Fwd => "remote port → local  (ssh -R)",
            Action::Copy => "transfer files",
            Action::Sync => "mirror directory (rsync-style)",
            Action::Ping => "measure round-trip latency",
            Action::Proxy => "SOCKS5 proxy via remote host",
            Action::Scan => "TCP port scanner",
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
            Action::Shell | Action::Ping => None,
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
            _ => "",
        }
    }

    fn needs_param(self) -> bool {
        self.param_label().is_some()
    }

    // Build the argv that will be passed to `seam <args…>`.
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
                let (remote_port, local_port) = if parts.len() == 2 {
                    (parts[0], parts[1].parse::<u16>().unwrap_or(8080))
                } else {
                    (param.as_str(), 8080u16)
                };
                vec![
                    "fwd".into(),
                    format!("{host}:{remote_port}"),
                    local_port.to_string(),
                ]
            }
            Action::Copy => {
                if param.contains('@') || param.starts_with('/') && host.contains(':') {
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
                    a.push("--ports".into());
                    a.push(param);
                }
                a
            }
        }
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
            if subcommand.starts_with('_') || subcommand == "recv" || subcommand == "serve" {
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
                if out.len() >= 8 {
                    break;
                }
            }
        }
    }
    out
}

fn format_ts(ts: &str) -> String {
    if ts.len() >= 16 {
        format!("{} {}", &ts[5..10], &ts[11..16])
    } else {
        ts.to_string()
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
    // Result of the last command run (command string, exit code)
    last_run: Option<(String, i32)>,
    // Validation message to show in preview bar
    validation: Option<String>,
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
            Action::Proxy | Action::Scan => true,
            a if a.needs_param() => !self.param.trim().is_empty(),
            _ => true,
        }
    }

    fn build_args(&self) -> Vec<String> {
        self.action().to_args(self.host.trim(), self.param.trim())
    }

    fn preview_command(&self) -> String {
        let args = self.build_args();
        format!("seam {}", args.join(" "))
    }

    fn on_command_return(&mut self, cmd: String, exit_code: i32) {
        self.last_run = Some((cmd, exit_code));
        self.validation = None;
        // Reload recent — audit log has the new entry now
        let new_recent = load_recent();
        let had_recent = !self.recent.is_empty();
        let prev_sel = self.recent_state.selected().unwrap_or(0);
        self.recent = new_recent;
        if !self.recent.is_empty() {
            let sel = if had_recent {
                prev_sel.min(self.recent.len() - 1)
            } else {
                0
            };
            self.recent_state.select(Some(sel));
        }
    }

    // ── Text editing ─────────────────────────────────────────────────────────

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
                let prev = prev_char_boundary(&self.host, self.host_cursor);
                self.host.remove(prev);
                self.host_cursor = prev;
            }
            Focus::Param if self.param_cursor > 0 => {
                let prev = prev_char_boundary(&self.param, self.param_cursor);
                self.param.remove(prev);
                self.param_cursor = prev;
            }
            _ => {}
        }
    }

    fn cursor_left(&mut self) {
        match self.focus {
            Focus::Host => {
                self.host_cursor = prev_char_boundary(&self.host, self.host_cursor);
            }
            Focus::Param => {
                self.param_cursor = prev_char_boundary(&self.param, self.param_cursor);
            }
            _ => {}
        }
    }

    fn cursor_right(&mut self) {
        match self.focus {
            Focus::Host => {
                self.host_cursor = next_char_boundary(&self.host, self.host_cursor);
            }
            Focus::Param => {
                self.param_cursor = next_char_boundary(&self.param, self.param_cursor);
            }
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
            Focus::Host => delete_word_back(&mut self.host, &mut self.host_cursor),
            Focus::Param => delete_word_back(&mut self.param, &mut self.param_cursor),
            _ => {}
        }
    }

    // ── Navigation ───────────────────────────────────────────────────────────

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

fn prev_char_boundary(s: &str, pos: usize) -> usize {
    if pos == 0 {
        return 0;
    }
    let mut p = pos - 1;
    while p > 0 && !s.is_char_boundary(p) {
        p -= 1;
    }
    p
}

fn next_char_boundary(s: &str, pos: usize) -> usize {
    if pos >= s.len() {
        return s.len();
    }
    let mut p = pos + 1;
    while p < s.len() && !s.is_char_boundary(p) {
        p += 1;
    }
    p
}

fn delete_word_back(s: &mut String, cursor: &mut usize) {
    if *cursor == 0 {
        return;
    }
    let slice = &s[..*cursor];
    let new_end = slice
        .trim_end_matches(|c: char| c != ' ' && c != '/')
        .trim_end_matches([' ', '/'])
        .len();
    s.drain(new_end..*cursor);
    *cursor = new_end;
}

// ── Rendering ─────────────────────────────────────────────────────────────────

fn dim(focused: bool) -> Style {
    if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    }
}

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
            Span::raw(before),
            Span::styled(ch, Style::default().bg(Color::White).fg(Color::Black)),
            Span::raw(after),
        ])
    } else if text.is_empty() {
        Line::from(Span::styled(
            format!(" {placeholder}"),
            Style::default().fg(Color::DarkGray),
        ))
    } else {
        Line::from(vec![Span::raw(" "), Span::raw(text)])
    };
    Paragraph::new(line)
}

fn draw(f: &mut Frame, app: &mut App) {
    let full = f.area();

    let title_left = Line::from(vec![Span::styled(
        "  seam  ",
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )]);
    let title_right = Span::styled(
        format!(" v{VERSION}  "),
        Style::default().fg(Color::DarkGray),
    );
    let root_block = Block::default()
        .title(title_left)
        .title_bottom(title_right)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));
    let inner = root_block.inner(full);
    f.render_widget(root_block, full);

    // Horizontal split: recent (left) | form (right)
    let has_recent = !app.recent.is_empty();
    let recent_w = if has_recent { 30u16 } else { 0 };
    let hcols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(recent_w), Constraint::Min(0)])
        .split(inner);

    // ── Recent panel ─────────────────────────────────────────────────────────
    if has_recent {
        let focused = app.focus == Focus::Recent;
        let items: Vec<ListItem> = app
            .recent
            .iter()
            .map(|r| {
                let host = truncate(&r.remote, 18);
                let cmd = format!(" {:6} ", r.subcommand);
                let ts = format_ts(&r.ts);
                ListItem::new(Line::from(vec![
                    Span::styled(host, Style::default().fg(Color::White)),
                    Span::styled(cmd, Style::default().fg(Color::Blue)),
                    Span::styled(ts, Style::default().fg(Color::DarkGray)),
                ]))
            })
            .collect();

        let list = List::new(items)
            .block(
                Block::default()
                    .title(" Recent ")
                    .borders(Borders::ALL)
                    .border_style(dim(focused)),
            )
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");

        f.render_stateful_widget(list, hcols[0], &mut app.recent_state);
    }

    // ── Form (right column) — always hcols[1] ────────────────────────────────
    let form = hcols[1];

    let needs_param = app.needs_param();
    let param_h: u16 = if needs_param { 3 } else { 0 };
    let action_h: u16 = Action::ALL.len() as u16 + 2;
    let last_run_h: u16 = if app.last_run.is_some() { 1 } else { 0 };

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),          // host input
            Constraint::Length(1),          // spacer
            Constraint::Length(action_h),   // action list
            Constraint::Length(param_h),    // param input (0 if not needed)
            Constraint::Min(0),             // flex spacer
            Constraint::Length(last_run_h), // last run result
            Constraint::Length(1),          // command preview
            Constraint::Length(1),          // hint bar
        ])
        .split(form);

    // Host input
    {
        let focused = app.focus == Focus::Host;
        let w = render_input(&app.host, app.host_cursor, focused, "user@hostname").block(
            Block::default()
                .title(" Host ")
                .borders(Borders::ALL)
                .border_style(dim(focused)),
        );
        f.render_widget(w, rows[0]);
    }

    // Action list
    {
        let focused = app.focus == Focus::Actions;
        let items: Vec<ListItem> = Action::ALL
            .iter()
            .enumerate()
            .map(|(i, a)| {
                let name = format!(" {:<10}", a.name());
                let desc = a.desc();
                let selected = i == app.action_idx;
                let name_style = if selected && focused {
                    Style::default().fg(Color::Black)
                } else if selected {
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Gray)
                };
                let desc_style = if selected && focused {
                    Style::default().fg(Color::Black)
                } else {
                    Style::default().fg(Color::DarkGray)
                };
                ListItem::new(Line::from(vec![
                    Span::styled(name, name_style),
                    Span::styled(desc, desc_style),
                ]))
            })
            .collect();

        let mut action_state = ListState::default();
        action_state.select(Some(app.action_idx));

        let hl_bg = if focused {
            Color::Cyan
        } else {
            Color::DarkGray
        };
        let list = List::new(items)
            .block(
                Block::default()
                    .title(" Action ")
                    .borders(Borders::ALL)
                    .border_style(dim(focused)),
            )
            .highlight_style(
                Style::default()
                    .bg(hl_bg)
                    .fg(Color::Black)
                    .add_modifier(Modifier::BOLD),
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
                .title(format!(" {label} "))
                .borders(Borders::ALL)
                .border_style(dim(focused)),
        );
        f.render_widget(w, rows[3]);
    }

    // Last run result
    if let Some((ref cmd, code)) = app.last_run
        && rows[5].height > 0
    {
        let (icon, color) = if code == 0 {
            ("  ", Color::Green)
        } else {
            ("  ", Color::Red)
        };
        let suffix = if code == 0 {
            String::new()
        } else {
            format!("  (exit {code})")
        };
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(icon, Style::default().fg(color)),
                Span::styled(
                    cmd.clone(),
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(suffix, Style::default().fg(Color::DarkGray)),
            ])),
            rows[5],
        );
    }

    // Command preview / validation
    if rows[6].height > 0 {
        let line = if let Some(ref msg) = app.validation {
            Line::from(Span::styled(
                format!("  {msg}"),
                Style::default().fg(Color::Yellow),
            ))
        } else if app.ready() {
            let cmd = app.preview_command();
            Line::from(vec![
                Span::styled(
                    "  ",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(cmd, Style::default().fg(Color::Green)),
            ])
        } else if app.host.trim().is_empty() {
            Line::from(Span::styled(
                "  type a host above  (user@hostname)",
                Style::default().fg(Color::DarkGray),
            ))
        } else if app.needs_param() && app.param.trim().is_empty() {
            let placeholder = app.action().param_placeholder();
            Line::from(Span::styled(
                format!("  enter {placeholder} above to continue"),
                Style::default().fg(Color::DarkGray),
            ))
        } else {
            Line::from(Span::raw(""))
        };
        f.render_widget(Paragraph::new(line), rows[6]);
    }

    // Hint bar
    if rows[7].height > 0 {
        let hints = Line::from(vec![
            Span::styled(" ↑↓ navigate", Style::default().fg(Color::DarkGray)),
            Span::styled("  Tab switch panel", Style::default().fg(Color::DarkGray)),
            Span::styled("  Enter run", Style::default().fg(Color::DarkGray)),
            Span::styled("  q quit", Style::default().fg(Color::DarkGray)),
        ]);
        f.render_widget(Paragraph::new(hints), rows[7]);
    }
}

fn truncate(s: &str, max: usize) -> String {
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

fn teardown(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

// ── Run a seam subcommand and return to the TUI ───────────────────────────────

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

        if key.code == KeyCode::Char('w')
            && key.modifiers.contains(KeyModifiers::CONTROL)
            && in_text
        {
            app.delete_word();
            continue;
        }

        match key.code {
            KeyCode::Esc => break,
            KeyCode::Char('q') if !in_text => break,

            KeyCode::Tab => {
                if key.modifiers.contains(KeyModifiers::SHIFT) {
                    app.tab_prev();
                } else {
                    app.tab_next();
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

            KeyCode::Char('j') if !in_text => match app.focus {
                Focus::Actions => app.action_down(),
                Focus::Recent => app.recent_down(),
                _ => {}
            },
            KeyCode::Char('k') if !in_text => match app.focus {
                Focus::Actions => app.action_up(),
                Focus::Recent => app.recent_up(),
                _ => {}
            },

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
                        // Leave alternate screen so the command gets a normal terminal
                        teardown(&mut terminal)?;
                        let exit_code = run_command(&args);
                        // Re-enter TUI
                        terminal = setup()?;
                        terminal.clear()?;
                        app.on_command_return(cmd_str, exit_code);
                    } else if app.host.trim().is_empty() {
                        app.validation = Some("Enter a host first  (user@hostname)".into());
                        app.focus = Focus::Host;
                    } else if app.needs_param() && app.param.trim().is_empty() {
                        let label = app.action().param_label().unwrap_or("param");
                        app.validation = Some(format!(
                            "Enter {label}  (e.g. {})",
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
