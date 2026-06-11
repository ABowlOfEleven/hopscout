//! World coastline polylines for the map view (lon, lat degrees). Populated from
//! a compact embedded asset; empty until the asset is generated.

/// Iterate coastline polylines as `&[(lon, lat)]` segments.
pub fn polylines() -> impl Iterator<Item = &'static [(f32, f32)]> {
    std::iter::empty()
}
