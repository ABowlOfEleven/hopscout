# Releasing hopscout

This is the end-to-end process for cutting a release and getting it onto winget.
It captures the hard-won details so we do not rediscover them each time.

## How a release is built

Pushing a `v*` tag triggers `.github/workflows/release.yml`, which builds the
release binaries, the WiX MSI, and a portable zip, then publishes a GitHub
Release. Releases are **Windows-only** (the net/cli/gui/helper crates are Win32).

## Two build requirements that must never regress

1. **Static CRT** - `.cargo/config.toml` sets
   `target-feature=+crt-static`. Without it the binaries dynamically link
   `vcruntime140.dll` and fail to start with `STATUS_DLL_NOT_FOUND`
   (`0xC0000135`) on any clean Windows that never had the VC++ redist. winget's
   Sandbox validation catches this. Verify with
   `dumpbin /dependents target/release/hopscout.exe` - only OS DLLs should
   appear, no `vcruntime140`/`msvcp140`.
2. **`hopscout-helper` only serves with `--serve`** - the helper blocks forever
   on its named pipe, which is correct when the app launches it elevated. A bare
   invocation must exit immediately, otherwise an installer validator that runs
   each installed exe and waits for it to exit (winget does) hangs for hours.
   The app's elevated launcher passes `--serve`.

## Cutting a release

1. Land all the code on `main`.
2. Bump the version in **two** places (they must agree):
   - `Cargo.toml` -> `[workspace.package] version` (e.g. `0.1.1`). All member
     crates inherit it via `version.workspace = true`. Bump the inter-crate
     `path` dep specs too for consistency.
   - `installer/hopscout.wxs` -> `Version` (four-part, e.g. `0.1.1.0`).
3. Add a `CHANGELOG.md` entry.
4. Commit, then `git tag vX.Y.Z` and `git push origin main vX.Y.Z`.
5. Watch `gh run watch <id>` until the release publishes.

## Getting it onto winget

The manifests live in `packaging/winget/manifests/a/ABowlOfEleven/hopscout/<ver>/`
- three files: `*.yaml` (version), `*.installer.yaml`, `*.locale.en-US.yaml`.

Rules learned from the 0.1.0 submission (winget-pkgs#386694):

- **Schema**: use the latest (`1.12.0`) and add the
  `# yaml-language-server: $schema=https://aka.ms/winget-manifest.<type>.1.12.0.schema.json`
  header to each file, or `winget validate` warns.
- **Publisher must match the registry.** The locale `Publisher` has to equal the
  MSI's `Manufacturer` (`hopscout contributors`) so winget can correlate the
  installed package. A moderator will block the PR otherwise.
- **Hash + ProductCode come from the published MSI**, and the **ProductCode is
  regenerated on every build**, so it changes each release. The `UpgradeCode` is
  fixed in the wxs and stays constant.
  - SHA256: `Get-FileHash <msi> -Algorithm SHA256`.
  - ProductCode (needs Windows PowerShell 5.1; pwsh 7 COM `InvokeMember` throws
    `DISP_E_TYPEMISMATCH`):
    `$db = (New-Object -ComObject WindowsInstaller.Installer).OpenDatabase($msi,0);`
    `$v = $db.OpenView("SELECT Value FROM Property WHERE Property='ProductCode'");`
    `$v.Execute(); $v.Fetch().StringData(1)`.
- Validate locally before submitting: `winget validate --manifest <dir>`.
- **Submit**:
  - First time = a `New-Package` PR (needs a moderator to approve; slowest gate).
  - A version update is lighter. Easiest is
    `wingetcreate update ABowlOfEleven.hopscout --version X.Y.Z --urls <msi-url>`,
    which fetches the hash and opens the PR.
  - To amend an open PR's files without re-running wingetcreate, PUT the
    base64 content to the fork branch via the Contents API:
    `gh api -X PUT repos/<fork>/winget-pkgs/contents/<path> -f message=... -f content=<base64> -f sha=<file-sha-at-ref> -f branch=<pr-head-branch>`.
- **Diagnosing a stuck validation run**: the Azure DevOps build is public.
  `curl .../shine-oss/<projGuid>/_apis/build/builds/<id>/timeline` lists the
  in-progress records; `.../logs/<n>` is the raw log. The buildId is in the
  wingetbot PR comment.

## The immutability rule (do not break installed users)

Once a version's winget manifest is **merged**, that release is immutable:
the manifest's `InstallerUrl` points at the GitHub release asset by URL + hash.
**Never delete or re-cut that tag/release** - the URL would 404 and break the
package for anyone installing it. (Before a manifest is merged, re-cutting the
same version is fine - we did it for 0.1.0 while fixing the CRT and helper bugs.)

Always ship fixes as a **new version** once a version is live on winget.

## Indexing lag

A merged winget PR takes roughly 15 minutes to a few hours (sometimes longer for
a brand-new package) before it appears in `winget search`. Until then,
`winget install` reports "No package found". `winget search hopscout` is the
readiness test.
