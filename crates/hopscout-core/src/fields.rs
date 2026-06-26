//! MTR-style stat-field selection for the table columns and text report
//! (`-o`/`--order` on the CLI). Letters: L loss, S sent, R recv, D drop,
//! N last, A avg, B best, W worst, V stddev, P p95.

use crate::HopStat;

#[derive(Clone, Copy, PartialEq)]
pub enum Field {
    Loss,
    Snt,
    Recv,
    Drop,
    Last,
    Avg,
    Best,
    Wrst,
    StDev,
    P95,
}

impl Field {
    pub fn from_char(c: char) -> Option<Self> {
        Some(match c.to_ascii_uppercase() {
            'L' => Self::Loss,
            'S' => Self::Snt,
            'R' => Self::Recv,
            'D' => Self::Drop,
            'N' => Self::Last,
            'A' => Self::Avg,
            'B' => Self::Best,
            'W' => Self::Wrst,
            'V' => Self::StDev,
            'P' => Self::P95,
            _ => return None,
        })
    }

    pub fn header(self) -> &'static str {
        match self {
            Self::Loss => "Loss%",
            Self::Snt => "Snt",
            Self::Recv => "Recv",
            Self::Drop => "Drop",
            Self::Last => "Last",
            Self::Avg => "Avg",
            Self::Best => "Best",
            Self::Wrst => "Wrst",
            Self::StDev => "StDev",
            Self::P95 => "p95",
        }
    }

    /// Column width (characters) for both the TUI table and the text report.
    pub fn width(self) -> u16 {
        match self {
            Self::Loss | Self::Snt | Self::Recv | Self::Drop => 6,
            _ => 7,
        }
    }

    pub fn is_loss(self) -> bool {
        matches!(self, Self::Loss)
    }

    pub fn value(self, st: &HopStat) -> String {
        let ms = |v: Option<f64>| v.map(|x| format!("{x:.1}")).unwrap_or_else(|| "-".to_string());
        match self {
            Self::Loss => format!("{:.0}%", st.loss_pct()),
            Self::Snt => st.sent().to_string(),
            Self::Recv => st.recv().to_string(),
            Self::Drop => st.sent().saturating_sub(st.recv()).to_string(),
            Self::Last => ms(st.last_ms()),
            Self::Avg => ms(st.avg_ms()),
            Self::Best => ms(st.best_ms()),
            Self::Wrst => ms(st.worst_ms()),
            Self::StDev => ms(st.stddev_ms()),
            Self::P95 => ms(st.p95_ms()),
        }
    }
}

/// The default column set (matches the original fixed layout).
pub fn default() -> Vec<Field> {
    use Field::*;
    vec![Loss, Snt, Last, Avg, Best, Wrst, StDev, P95]
}

/// Parse an order string like `LSNABWV`; unknown letters are ignored, and an
/// empty result falls back to [`default`].
pub fn parse_order(s: &str) -> Vec<Field> {
    let v: Vec<Field> = s.chars().filter_map(Field::from_char).collect();
    if v.is_empty() { default() } else { v }
}
