# Security review — 2026-10-11

The application checks passed, but the release image is **not CVE-clean**.
The package findings below remain open. This review does not establish that a
public deployment is safe; keep access private or behind HTTPS and authentication.

## Scope and results

Reviewed PHProxy 1.4.0 using the pinned `php:8.5.11-apache` base, digest
`sha256:974e3a920309308e1690ed607e6cc3061d6906f90cc8d30fe519daa48bccf101`.
The application SHA-256 in both images scanned on this date was
`9ea21992427d62583590b1fe64eb3bfc4606422c84fd09e53592477334d2e73b`.

Docker Scout 1.23.1 scanned those earlier local AMD64 and ARM64 images separately.
Each scan reported **173 CVEs across 26 packages**, with no fixed package versions
reported for the selected Debian release:

| Scanner severity | Count per image |
| --- | ---: |
| Critical | 5 |
| High | 21 |
| Medium | 9 |
| Low | 137 |
| Unspecified | 1 |

These are scanner classifications, not confirmed application exploitability.
Raw SARIF reports and a machine-readable summary were saved with the review's
local artifacts. No vulnerability exploitation or reproduction was performed.

## Configuration and package triage

Apache is `2.4.68-1~deb13u1`. An actual `apache2ctl -M` inventory showed that
`rewrite`, `http2`, `ssl`, `auth_digest`, `heartmonitor`, `session_cookie`,
`charset_lite`, `proxy_html`, `proxy_ftp`, `proxy_uwsgi`, `vhost_alias`, `xml2enc`
and `dav_fs` are **not loaded**. All 15 Apache findings classified high/critical
by Scout name these absent modules. Enabled modules include PHP, prefork, basic
authentication, deflate, alias, status and the normal core modules. The application
implements its own HTTP fetcher; it does not enable Apache's proxy modules.

Apache lists fixes in **2.4.69**, while Debian still lists the trixie package as
vulnerable and the fixed version in forky/sid. The absent modules reduce exposure
in this configuration; they do not patch the installed package or justify clearing
the findings. [Apache advisories](https://httpd.apache.org/security/vulnerabilities_24.html),
[Debian tracking example](https://security-tracker.debian.org/tracker/CVE-2026-56154).

GnuTLS accounts for two critical and three high findings. PHProxy's HTTPS streams
use **OpenSSL 3.5.7**, not GnuTLS certificate verification. GnuTLS is nevertheless
present and transitively linked through other installed libraries. Debian's two
critical entries are unfixed and await upstream assessment:
[CVE-2026-88647](https://security-tracker.debian.org/tracker/CVE-2026-88647) and
[CVE-2026-95210](https://security-tracker.debian.org/tracker/CVE-2026-95210).

The remaining high findings affect libxml2 (2), Expat (2), Cyrus SASL (1) and
zlib (1). This script does not call DOM/SAX XML parsers or SASL authentication.
It does use zlib for bounded response decoding and output compression; the flagged
[zlib issue](https://security-tracker.debian.org/tracker/CVE-2026-85091) describes
nonblocking gzip-file writes, which the script does not call. These observations
limit identified call paths; they are not proof that every library finding is
unreachable, and no findings have been suppressed.

After refreshing apt metadata in a disposable ARM64 container, installed versions
equalled stable-repository candidates for Apache, GnuTLS, libxml2, Expat, zlib,
Cyrus SASL, OpenSSL and curl. No packages or repositories were changed in the
release images. Recheck Debian security updates and refresh the pinned base when
fixes are available; do not mix unstable packages into the image to lower a score.

## Validation and release status

PHP 8.1.34 and 8.5.11 passed lint and the transport, browser and UI regressions.
Both image architectures passed isolated Apache smoke checks with a read-only
filesystem: complete homepage, all three CSS/JS assets, required PHP extensions,
root-owned application files and no PHP errors or warnings in the smoke logs.
Compose configurations for ports 80/8080 and development/production validated;
the GitHub workflows passed actionlint 1.7.12.

The release configuration keeps application code read-only, sessions in temporary
storage and the published port on localhost. Publishing workflows and a Docker Hub
overview are prepared. **No image or overview was published during this review.**

## Follow-up runtime validation — 2026-10-11

After the toolbar, same-page settings and CLI regression fixes, the final
application SHA-256 is
`b2bc459a718ed62166047de2a72cec31f6ab4645f91b03c35b869867ebbbe757`.
PHP 8.1.34 and 8.5.11 passed syntax checks for every PHP file and all five suites:
transport, browser, UI, CLI and panel. These checks ran without network access.

Fresh local AMD64 and ARM64 builds contained that exact application hash. Both
passed isolated Apache checks with read-only filesystems: a complete homepage,
all three static assets, required extensions, root-owned application files and
no PHP errors or warnings in the smoke logs. Workflow lint passed again.

Interactive browser checks covered the fixed toolbar, single-frame navigation,
cross-page fragment forwarding, default script-blocked CSS/font rendering,
390-pixel layout, settings open/close/apply and session TTL saving while retaining
the current URL. The previous Git HEAD application remains available locally for
comparison; it is not the release candidate.

The PHP base digest and installed packages did not change. The package scan was
**not rerun** for these application-only fixes: the earlier scan identities and
counts above remain historical, and their open findings still apply to the
unchanged package base. The separate `runtime-revalidation.json` artifact records
the new application hash, image IDs and test results. No image was pushed.
