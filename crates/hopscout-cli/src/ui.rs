//! Rendering for the CLI: a title line, the live hop table (or the alerts
//! pane), and a key hint.

use hopscout_core::{Alert, Engine, EngineConfig, Field, Hop, Session};

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, List, ListItem, Paragraph, Row, Table};

/// Display flags that drive how the live view renders.
pub struct DisplayOpts<'a> {
    /// Annotate hosts with their MPLS label stack (udp/tcp modes).
    pub show_mpls: bool,
    /// Show `name (ip)` instead of just the resolved name.
    pub show_ips: bool,
    /// Don't show resolved names (mirror `--no-dns`).
    pub no_dns: bool,
    /// Show the full alerts pane instead of the hop table.
    pub show_alerts: bool,
    /// Stat columns, in order.
    pub fields: &'a [Field],
}

#[allow(clippy::too_many_arguments)]
pub fn draw(
    frame: &mut Frame,
    session: &Session,
    engine: &Engine,
    target_label: &str,
    config: &EngineConfig,
    has_baseline: bool,
    alerts: &[Alert],
    opts: &DisplayOpts,
) {
    let chunks = Layout::vertical([
        Constraint::Length(1), // title
        Constraint::Min(0),    // table or alerts
        Constraint::Length(1), // footer
    ])
    .split(frame.area());

    frame.render_widget(title_line(engine, target_label, config), chunks[0]);
    if opts.show_alerts {
        frame.render_widget(alerts_pane(has_baseline, alerts), chunks[1]);
    } else {
        frame.render_widget(hop_table(session, config.first_ttl, opts), chunks[1]);
    }
    frame.render_widget(footer_line(session, has_baseline, alerts, opts.show_alerts), chunks[2]);
}

fn title_line<'a>(engine: &Engine, target_label: &'a str, config: &EngineConfig) -> Paragraph<'a> {
    let status = if engine.is_paused() {
        Span::styled("paused", Style::default().fg(Color::Yellow))
    } else {
        Span::styled("running", Style::default().fg(Color::Green))
    };
    let line = Line::from(vec![
        Span::styled(
            hopscout_core::brand::name_version(),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw("  →  "),
        Span::raw(format!("{target_label} ({})", config.target)),
        Span::raw("   ["),
        status,
        Span::raw(format!("]   {}ms interval", config.interval.as_millis())),
    ]);
    Paragraph::new(line)
}

/// The host cell: name, `name (ip)`, or bare IP depending on the flags.
fn host_label(hop: &Hop, show_ips: bool, no_dns: bool) -> String {
    let ip = hop.primary_addr().map(|a| a.to_string());
    let name = if no_dns { None } else { hop.meta.hostname.clone() };
    match (name, ip) {
        (Some(n), Some(ip)) if show_ips => format!("{n} ({ip})"),
        (Some(n), _) => n,
        (None, Some(ip)) => ip,
        (None, None) => "*".to_string(),
    }
}

/// Compact location string for the Loc column: city, else country, else blank.
fn geo_label(hop: &Hop) -> String {
    match (&hop.meta.city, &hop.meta.country) {
        (Some(c), _) if !c.is_empty() => c.clone(),
        (_, Some(c)) if !c.is_empty() => c.clone(),
        _ => String::new(),
    }
}

fn hop_table(session: &Session, first_ttl: u8, opts: &DisplayOpts) -> Table<'static> {
    let mut header_cells =
        vec!["Hop".to_string(), "Host".to_string(), "ASN".to_string(), "Loc".to_string()];
    header_cells.extend(opts.fields.iter().map(|f| f.header().to_string()));
    let header = Row::new(header_cells).style(Style::default().add_modifier(Modifier::BOLD));

    let start = (first_ttl as usize).saturating_sub(1);
    let rows: Vec<Row> = (start..session.visible_hops())
        .map(|i| {
            let hop = &session.hops[i];
            let ttl = i + 1;
            let mut host = host_label(hop, opts.show_ips, opts.no_dns);
            if opts.show_mpls && !hop.mpls.is_empty() {
                let labels: Vec<String> = hop.mpls.iter().map(|m| m.label.to_string()).collect();
                host = format!("{host} [MPLS {}]", labels.join(","));
            }
            let asn = hop.meta.asn.map(|n| format!("AS{n}")).unwrap_or_default();
            let st = &hop.stat;

            let mut cells = vec![
                Cell::from(format!("{ttl:>2}")),
                Cell::from(host),
                Cell::from(asn).style(Style::default().fg(Color::Cyan)),
                Cell::from(geo_label(hop)).style(Style::default().fg(Color::DarkGray)),
            ];
            for f in opts.fields {
                let mut cell = Cell::from(f.value(st));
                if f.is_loss() {
                    cell = cell.style(loss_style(st.loss_pct()));
                }
                cells.push(cell);
            }
            Row::new(cells)
        })
        .collect();

    let mut widths = vec![
        Constraint::Length(3),
        Constraint::Min(18),
        Constraint::Length(9),
        Constraint::Length(14),
    ];
    widths.extend(opts.fields.iter().map(|f| Constraint::Length(f.width() + 1)));

    Table::new(rows, widths)
        .header(header)
        .column_spacing(1)
        .block(Block::bordered().title(" hops "))
}

/// The full alerts pane (shown when toggled with `a`): every deviation, one per
/// line, instead of the single-line footer summary.
fn alerts_pane(has_baseline: bool, alerts: &[Alert]) -> List<'static> {
    let items: Vec<ListItem> = if !has_baseline {
        vec![ListItem::new(Line::from(Span::raw(
            "No baseline captured. Press 'b' to capture one, then watch for route changes, latency regressions, and loss here.",
        )))]
    } else if alerts.is_empty() {
        vec![ListItem::new(Line::from(Span::styled(
            "✓ path matches baseline",
            Style::default().fg(Color::Green),
        )))]
    } else {
        alerts
            .iter()
            .map(|a| {
                ListItem::new(Line::from(Span::styled(a.message(), alert_style(a))))
            })
            .collect()
    };

    List::new(items).block(Block::bordered().title(" alerts "))
}

fn alert_style(a: &Alert) -> Style {
    let color = match a {
        Alert::RouteChanged { .. } | Alert::HopAppeared { .. } | Alert::HopDisappeared { .. } => {
            Color::Yellow
        }
        Alert::LatencyRegression { .. } | Alert::LossOnset { .. } => Color::Red,
    };
    Style::default().fg(color)
}

fn footer_line(
    session: &Session,
    has_baseline: bool,
    alerts: &[Alert],
    show_alerts: bool,
) -> Paragraph<'static> {
    let bold = || Style::default().add_modifier(Modifier::BOLD);
    let mut spans = vec![
        Span::styled("q", bold()),
        Span::raw(" quit · "),
        Span::styled("p", bold()),
        Span::raw(" pause · "),
        Span::styled("r", bold()),
        Span::raw(" reset · "),
        Span::styled("b", bold()),
        Span::raw(" baseline · "),
        Span::styled("a", bold()),
        Span::raw(if show_alerts { " table   " } else { " alerts   " }),
    ];

    if has_baseline {
        if alerts.is_empty() {
            spans.push(Span::styled("✓ matches baseline", Style::default().fg(Color::Green)));
        } else {
            spans.push(Span::styled(
                format!("⚠ {} change(s): {}", alerts.len(), alerts[0].message()),
                Style::default().fg(Color::Yellow),
            ));
        }
    } else {
        let reached = match session.path_len {
            Some(p) => format!("destination at hop {p}"),
            None => "discovering path…".to_string(),
        };
        spans.push(Span::raw(reached));
    }

    Paragraph::new(Line::from(spans))
}

fn loss_style(loss: f64) -> Style {
    let color = if loss <= 0.0 {
        Color::Green
    } else if loss < 5.0 {
        Color::Yellow
    } else {
        Color::Red
    };
    Style::default().fg(color)
}
