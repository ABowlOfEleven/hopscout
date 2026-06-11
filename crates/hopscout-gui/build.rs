//! Embeds version/product metadata (and an icon, if present) into the .exe.
//! No-op on non-Windows.

fn main() {
    #[cfg(windows)]
    embed_resources();
}

#[cfg(windows)]
fn embed_resources() {
    let mut res = winresource::WindowsResource::new();
    res.set("ProductName", "hopscout");
    res.set("FileDescription", "HopScout — desktop traceroute monitor");
    res.set("CompanyName", "hopscout contributors");
    res.set("LegalCopyright", "MIT-licensed; (c) hopscout contributors");

    let icon = std::path::Path::new("../../assets/hopscout.ico");
    if icon.exists() {
        res.set_icon(icon.to_str().unwrap());
    }
    let _ = res.compile();
}
