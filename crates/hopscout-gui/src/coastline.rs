//! World coastline polylines for the map view, parsed from a compact embedded
//! asset (little-endian f32 `lon,lat` pairs, NaN/NaN separating polylines).
//! Source: Natural Earth 110m coastline; regenerate with `assets/make_coastline.py`.

use std::sync::OnceLock;

const RAW: &[u8] = include_bytes!("../../../assets/coastline.bin");
static COAST: OnceLock<Vec<Vec<(f32, f32)>>> = OnceLock::new();

fn parse() -> Vec<Vec<(f32, f32)>> {
    let mut polys = Vec::new();
    let mut cur: Vec<(f32, f32)> = Vec::new();
    let mut i = 0;
    while i + 8 <= RAW.len() {
        let lon = f32::from_le_bytes([RAW[i], RAW[i + 1], RAW[i + 2], RAW[i + 3]]);
        let lat = f32::from_le_bytes([RAW[i + 4], RAW[i + 5], RAW[i + 6], RAW[i + 7]]);
        i += 8;
        if lon.is_nan() || lat.is_nan() {
            if !cur.is_empty() {
                polys.push(std::mem::take(&mut cur));
            }
        } else {
            cur.push((lon, lat));
        }
    }
    if !cur.is_empty() {
        polys.push(cur);
    }
    polys
}

/// Iterate coastline polylines as `&[(lon, lat)]` segments.
pub fn polylines() -> impl Iterator<Item = &'static [(f32, f32)]> {
    COAST.get_or_init(parse).iter().map(Vec::as_slice)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_embedded_coastline() {
        let polys = parse();
        assert!(polys.len() >= 50, "only {} polylines", polys.len());
        for p in &polys {
            for &(lon, lat) in p {
                assert!((-181.0..=181.0).contains(&lon), "lon {lon}");
                assert!((-91.0..=91.0).contains(&lat), "lat {lat}");
            }
        }
    }
}
