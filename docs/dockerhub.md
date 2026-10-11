# PHProxy

A small PHP web proxy with a browser interface and JSON fetch API. Fetch public
HTTP/HTTPS pages through your server, follow rewritten links, and manage upstream
cookies and request headers from the home page or browsing bar. Settings open
in place and preserve the current URL. No database or Composer required.

## Quick start

```sh
docker run -d --name phproxy --restart unless-stopped \
  -p 127.0.0.1:8080:80 \
  miglen/phproxy:latest
```

Open **http://localhost:8080/**.
For port **80**, replace the mapping with `-p 127.0.0.1:80:80` and open
http://localhost/. Port selection does not require rebuilding the image.

For the read-only production Compose configuration:

```sh
curl -fsSLO https://raw.githubusercontent.com/PHProxy/phproxy/master/docker-compose.yml
docker compose up -d
```

To use port **80** with Compose, run `PHPROXY_PORT=80 docker compose up -d`.
The default is **8080**. Save `PHPROXY_PORT=80` in a local `.env` file to keep
that choice for subsequent Compose commands.

Images support **linux/amd64** and **linux/arm64**. Choose a numbered release tag
for a fixed application version; `latest` follows the current stable release.

## Configuration

| Setting | Purpose |
| --- | --- |
| `PHPROXY_PORT` | Compose host port; defaults to `8080`. |
| `PHPROXY_PUBLIC_URL` | Full external script URL, such as `https://proxy.example/index.php`. |
| `PHPROXY_DIAGNOSTICS=1` | Enable optional port/certificate diagnostics; disabled by default. |

Keep the default localhost port binding. To share access, place an authenticated
HTTPS reverse proxy in front and set `PHPROXY_PUBLIC_URL` to its public URL.
**PHProxy does not provide authentication.**

Only public HTTP/HTTPS destinations are accepted. Upstream content is sandboxed
with scripts blocked by default, preserving stylesheet and font access.
Enabling scripts uses a separate, opaque origin; session-bound stylesheets and
fonts may then fail. Modern JavaScript applications, sign-in flows, CAPTCHAs and
WebSockets may not work. PHProxy is not a VPN or an anonymity guarantee.
Cookies are scoped to the exact upstream host, so cross-subdomain sessions may
need separate sign-ins.

Cookies, headers and encrypted-URL keys live in the server-side session. The
production Compose file uses temporary session storage: stopping/recreating the
container clears that state, and existing encrypted links may stop working.

## JSON API

```sh
curl 'http://localhost:8080/index.php?api=fetch' \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com/"}'
```

[Source and documentation](https://github.com/PHProxy/phproxy) ·
[Issues](https://github.com/PHProxy/phproxy/issues) ·
[GNU GPL v3](https://github.com/PHProxy/phproxy/blob/master/LICENSE.md)
