//! Rendering for the CLI: a title line, the live hop table, and a key hint.

use hopscout_core::{Alert, Engine, EngineConfig, Session};

use crate::fields::Field;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Paragraph, Row, Table};

#[allow(clippy::too_many_arguments)]
pub fn draw(
    frame: &mut Frame,
    session: &Session,
    engine: &Engine,
    target_label: &str,
    config: &EngineConfig,
    has_baseline: bool,
    alerts: &[Alert],
    show_mpls: bool,
    fields: &[Field],
) {
    let chunks = Layout::vertical([
        Constraint::Length(1), // title
        Constraint::Min(0),    // table
        Constraint::Length(1), // footer
    ])
    .split(frame.area());

    frame.render_widget(title_line(engine, target_label, config), chunks[0]);
    frame.render_widget(hop_table(session, config.first_ttl, show_mpls, fields), chunks[1]);
    frame.render_widget(footer_line(session, has_baseline, alerts), chunks[2]);
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

fn hop_table(
    session: &Session,
    first_ttl: u8,
    show_mpls: bool,
    fields: &[Field],
) -> Table<'static> {
    let mut header_cells = vec!["Hop".to_string(), "Host".to_string(), "ASN".to_string()];
    header_cells.extend(fields.iter().map(|f| f.header().to_string()));
    let header = Row::new(header_cells).style(Style::default().add_modifier(Modifier::BOLD));

    let start = (first_ttl as usize).saturating_sub(1);
    let rows: Vec<Row> = (start..session.visible_hops())
        .map(|i| {
            let ttl = i + 1;
            let hop = &session.hops[i];
            let mut host = hop
                .meta
                .hostname
                .clone()
                .or_else(|| hop.primary_addr().map(|a| a.to_string()))
                .unwrap_or_else(|| "*".to_string());
            if show_mpls && !hop.mpls.is_empty() {
                let labels: Vec<String> = hop.mpls.iter().map(|m| m.label.to_string()).collect();
                host = format!("{host} [MPLS {}]", labels.join(","));
            }
            let asn = hop.meta.asn.map(|n| format!("AS{n}")).unwrap_or_default();
            let st = &hop.stat;

            let mut cells = vec![
                Cell::from(format!("{ttl:>2}")),
                Cell::from(host),
                Cell::from(asn).style(Style::default().fg(Color::Cyan)),
            ];
            for f in fields {
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
    ];
    widths.extend(fields.iter().map(|f| Constraint::Length(f.width() + 1)));

    Table::new(rows, widths)
        .header(header)
        .column_spacing(1)
        .block(Block::bordered().title(" hops "))
}

fn footer_line(session: &Session, has_baseline: bool, alerts: &[Alert]) -> Paragraph<'static> {
    let bold = || Style::default().add_modifier(Modifier::BOLD);
    let mut spans = vec![
        Span::styled("q", bold()),
        Span::raw(" quit · "),
        Span::styled("p", bold()),
        Span::raw(" pause · "),
        Span::styled("r", bold()),
        Span::raw(" reset · "),
        Span::styled("b", bold()),
        Span::raw(" baseline   "),
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
