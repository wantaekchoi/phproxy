<?php

/**
 * PHProxy v1.4.0
 *
 * Single-file web HTTP/HTTPS proxy in PHP. Drop into any PHP 8.1+ web root
 * and open it — no dependencies, no build step, no `vendor/`, no `files/`
 * directory. Works under any filename (rename to proxy.php if you like).
 *
 * @version    v1.4.0
 * @author     Miglen Evlogiev (revive), PhoenixPeca, Biojet1, Quix0r, dacendo
 * @copyright  2002-2007 A.A. (whitefyre); 2015-2019 contributors; 2025-2026 revive
 * @license    GNU GPL v3
 * @repo       https://github.com/PHProxy/phproxy
 */

// Loading the pure helpers for tests does not dispatch an HTTP request.
if (defined('PHPROXY_LIBRARY_ONLY') && PHPROXY_LIBRARY_ONLY) return;

error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

// --- ASSET DISPATCHER --------------------------------------------------
// Serves the proxy's own CSS via ?asset=<name>. Keeps the script
// self-contained — no files/ directory needed.
if (isset($_GET['asset'])) {
    header('Cache-Control: public, max-age=3600');
    switch ((string) $_GET['asset']) {
        case 'index.css':   header('Content-Type: text/css; charset=utf-8');         echo phproxy_index_css(); exit;
        case 'panel.css':   header('Content-Type: text/css; charset=utf-8');         echo phproxy_panel_css(); exit;
        case 'netcheck.js': header('Content-Type: application/javascript; charset=utf-8'); echo phproxy_netcheck_js(); exit;
    }
    http_response_code(404);
    exit;
}

// --- JSON API DISPATCHER (?api=fetch) -----------------------------------
// POST with a JSON body — proxy makes the HTTP request and returns either
// JSON (default) or the raw upstream response.
//
// Body schema:
//   {
//     "url":              "https://example.com/" (required),
//     "method":           "GET" | "POST" | ...   (default: GET),
//     "headers":          { "Name": "value", ... },
//     "cookies":          { "name": "value", ... },
//     "body":             "string",
//     "timeout":          30,
//     "follow_redirects": false,
//     "max_redirects":    5,
//     "verify_ssl":       true,
//     "return":           "json" | "raw"         (default: json)
//   }
// Helper used by the new network-check APIs (dns / portcheck / cert).
$phproxy_api_validate_host = function (string $host): bool {
    try {
        $host = phproxy_normalize_host($host);
        return !filter_var($host, FILTER_VALIDATE_IP) || phproxy_is_public_ip($host);
    } catch (Throwable $e) {
        return false;
    }
};

// Socket diagnostics are operator-only features; public images start with them disabled.
if (in_array($_GET['api'] ?? '', ['portcheck', 'cert'], true) && getenv('PHPROXY_DIAGNOSTICS') !== '1') {
    http_response_code(403);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok' => false, 'error' => 'Socket diagnostics are disabled by the operator']);
    exit;
}

// --- DNS LOOKUP API (?api=dns&host=example.com&type=A) -----------------
if (isset($_GET['api']) && $_GET['api'] === 'dns') {
    header('Content-Type: application/json; charset=utf-8');
    $host = (string) ($_GET['host'] ?? '');
    $type = strtoupper((string) ($_GET['type'] ?? 'A'));
    if (!phproxy_valid_dns_name($host)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'Invalid or blacklisted host']);
        exit;
    }
    $types = [
        'A'     => DNS_A,     'AAAA'  => DNS_AAAA, 'MX'    => DNS_MX,
        'TXT'   => DNS_TXT,   'NS'    => DNS_NS,   'SOA'   => DNS_SOA,
        'CAA'   => DNS_CAA,   'CNAME' => DNS_CNAME,'PTR'   => DNS_PTR,
        'SRV'   => DNS_SRV,   'ANY'   => DNS_ANY,
    ];
    if (!isset($types[$type])) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'Unknown record type', 'supported' => array_keys($types)]);
        exit;
    }
    $started = microtime(true);
    $records = @dns_get_record(rtrim($host, '.') . '.', $types[$type]);
    $ms      = (int) ((microtime(true) - $started) * 1000);
    if ($records === false) {
        echo json_encode(['ok' => false, 'host' => $host, 'type' => $type, 'error' => 'Lookup failed', 'duration_ms' => $ms]);
        exit;
    }
    echo json_encode(['ok' => true, 'host' => $host, 'type' => $type, 'records' => $records, 'duration_ms' => $ms], JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    exit;
}

// --- PORT CHECK API (?api=portcheck&host=example.com&port=443) ---------
// `port` accepts a single port (443), an inclusive range (8000-8010) or a
// comma-separated mix (22,80,443,8000-8010). Hard cap is 128 ports per
// request; default per-port timeout is 1.0s, override with ?timeout=…
// (clamped 0.1–5.0). Response always carries a `results` array.
if (isset($_GET['api']) && $_GET['api'] === 'portcheck') {
    header('Content-Type: application/json; charset=utf-8');
    $host      = (string) ($_GET['host'] ?? '');
    $port_spec = (string) ($_GET['port'] ?? '');
    $timeout   = (float)  ($_GET['timeout'] ?? 1.0);
    if ($timeout < 0.1) $timeout = 0.1;
    if ($timeout > 5.0) $timeout = 5.0;
    if (!$phproxy_api_validate_host($host)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'Invalid or blacklisted host']);
        exit;
    }
    $ports = phproxy_parse_port_spec($port_spec);
    if ($ports === false) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'Invalid port spec. Examples: 443, 8000-8010, 22,80,443,8000-8010', 'received' => $port_spec]);
        exit;
    }
    if (count($ports) > 128) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'Too many ports requested (max 128)', 'requested' => count($ports)]);
        exit;
    }

    $scan_deadline = microtime(true) + 10;
    try {
        $host = phproxy_normalize_host($host);
        $scan_address = phproxy_resolve_public_host($host, $scan_deadline)[0];
    } catch (Throwable $e) {
        http_response_code($e instanceof InvalidArgumentException ? 400 : 502);
        echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
        exit;
    }

    // Streaming mode: emit NDJSON — one event per line, flushed immediately,
    // so the UI can show partial progress as each port comes back. Triggered
    // by ?stream=1. Default remains the batched JSON envelope so existing
    // CLI consumers don't break.
    $stream = !empty($_GET['stream']);
    if ($stream) {
        while (ob_get_level() > 0) @ob_end_clean();
        @ob_implicit_flush(true);
        header('Content-Type: application/x-ndjson; charset=utf-8');
        header('X-Accel-Buffering: no');   // nginx hint
        header('Cache-Control: no-cache, no-store');
        $emit = function (array $obj): void {
            echo json_encode($obj, JSON_UNESCAPED_SLASHES), "\n";
            @flush();
        };
        $emit([
            'event'     => 'start',
            'host'      => $host,
            'port_spec' => $port_spec,
            'count'     => count($ports),
            'ports'     => $ports,
            'timeout_s' => $timeout,
        ]);
        $scan_started = microtime(true);
        $open = $closed = 0;
        foreach ($ports as $p) {
            if (connection_aborted()) break;
            $t0   = microtime(true);
            if (microtime(true) >= $scan_deadline) break;
            $errno = 0; $errstr = '';
            try {
                $sock = phproxy_open_public_socket($host, $p, false, min($scan_deadline, microtime(true) + $timeout), [], false, $scan_address);
            } catch (Throwable $e) {
                $sock = false; $errstr = $e->getMessage();
            }
            $ms   = (int) ((microtime(true) - $t0) * 1000);
            if ($sock === false) {
                $closed++;
                $emit(['event' => 'result', 'port' => $p, 'reachable' => false, 'error' => $errstr ?: 'connect failed', 'errno' => (int) $errno, 'latency_ms' => $ms]);
            } else {
                fclose($sock);
                $open++;
                $emit(['event' => 'result', 'port' => $p, 'reachable' => true, 'latency_ms' => $ms]);
            }
        }
        $emit([
            'event'       => 'end',
            'complete'    => $open + $closed === count($ports),
            'open'        => $open,
            'closed'      => $closed,
            'duration_ms' => (int) ((microtime(true) - $scan_started) * 1000),
        ]);
        exit;
    }

    // Batched mode (default) — one JSON envelope at the end.
    $scan_started = microtime(true);
    $results = [];
    foreach ($ports as $p) {
        $t0   = microtime(true);
        if (microtime(true) >= $scan_deadline || connection_aborted()) break;
        $errno = 0; $errstr = '';
        try {
            $sock = phproxy_open_public_socket($host, $p, false, min($scan_deadline, microtime(true) + $timeout), [], false, $scan_address);
        } catch (Throwable $e) {
            $sock = false; $errstr = $e->getMessage();
        }
        $ms   = (int) ((microtime(true) - $t0) * 1000);
        if ($sock === false) {
            $results[] = ['port' => $p, 'reachable' => false, 'error' => $errstr ?: 'connect failed', 'errno' => (int) $errno, 'latency_ms' => $ms];
        } else {
            fclose($sock);
            $results[] = ['port' => $p, 'reachable' => true, 'latency_ms' => $ms];
        }
    }
    $duration = (int) ((microtime(true) - $scan_started) * 1000);
    $open     = 0;
    foreach ($results as $r) if (!empty($r['reachable'])) $open++;
    echo json_encode([
        'ok'           => true,
        'host'         => $host,
        'port_spec'    => $port_spec,
        'count'        => count($results),
        'complete'     => count($results) === count($ports),
        'open'         => $open,
        'closed'       => count($results) - $open,
        'timeout_s'    => $timeout,
        'duration_ms'  => $duration,
        'results'      => $results,
    ], JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    exit;
}

/**
 * Parse a port spec — single, range, or comma list — into a sorted,
 * deduped array of ints. Returns false on any syntax error or out-of-range.
 *   "443"            → [443]
 *   "8000-8010"         → [80, 81, …, 443]
 *   "22,80,443"      → [22, 80, 443]
 *   "80,8000-8010"   → [80, 8000, …, 8010]
 */
function phproxy_parse_port_spec(string $spec): array|false
{
    $spec = trim($spec);
    if ($spec === '') return false;
    $set = [];
    foreach (explode(',', $spec) as $chunk) {
        $chunk = trim($chunk);
        if ($chunk === '') continue;
        if (strpos($chunk, '-') !== false) {
            $parts = explode('-', $chunk, 2);
            if (!ctype_digit(trim($parts[0])) || !ctype_digit(trim($parts[1]))) return false;
            $a = (int) trim($parts[0]);
            $b = (int) trim($parts[1]);
            if ($a < 1 || $a > 65535 || $b < 1 || $b > 65535 || $b < $a) return false;
            if ($b - $a + 1 > 128) return false;
            for ($i = $a; $i <= $b; $i++) $set[$i] = true;
        } else {
            if (!ctype_digit($chunk)) return false;
            $p = (int) $chunk;
            if ($p < 1 || $p > 65535) return false;
            $set[$p] = true;
        }
        if (count($set) > 1024) return false;  // hard ceiling to prevent memory abuse; dispatcher rejects >128 with a clearer error
    }
    if (empty($set)) return false;
    ksort($set);
    return array_keys($set);
}

// --- SSL CERT INSPECTOR API (?api=cert&host=example.com&port=443) ------
if (isset($_GET['api']) && $_GET['api'] === 'cert') {
    header('Content-Type: application/json; charset=utf-8');
    $host = (string) ($_GET['host'] ?? '');
    $port = (int)    ($_GET['port'] ?? 443);
    if (!$phproxy_api_validate_host($host)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'Invalid or blacklisted host']);
        exit;
    }
    if ($port < 1 || $port > 65535) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'Invalid port (1–65535)']);
        exit;
    }
    $started = microtime(true);
    $cert_deadline = $started + 15;
    $sock = false; $errno = 0; $errstr = '';
    try {
        $host = phproxy_normalize_host($host);
        $cert_address = phproxy_resolve_public_host($host, $cert_deadline)[0];
        $sock = phproxy_open_public_socket($host, $port, true, min($cert_deadline, microtime(true) + 10),
            ['capture_peer_cert' => true, 'capture_peer_cert_chain' => true], true, $cert_address);
    } catch (Throwable $e) {
        $errstr = $e->getMessage();
    }
    $ms      = (int) ((microtime(true) - $started) * 1000);
    if ($sock === false) {
        echo json_encode(['ok' => false, 'host' => $host, 'port' => $port, 'error' => $errstr ?: 'SSL handshake failed', 'errno' => (int) $errno, 'latency_ms' => $ms]);
        exit;
    }
    $meta_main = stream_get_meta_data($sock);
    $params    = stream_context_get_params($sock);
    fclose($sock);
    $leaf  = $params['options']['ssl']['peer_certificate']       ?? null;
    $chain = $params['options']['ssl']['peer_certificate_chain'] ?? [];
    if (!$leaf) {
        echo json_encode(['ok' => false, 'host' => $host, 'port' => $port, 'error' => 'No peer certificate received']);
        exit;
    }
    $parse_cert = function ($cert) {
        $p = @openssl_x509_parse($cert);
        if (!is_array($p)) return null;

        // SAN entries — flatten DNS:/IP Address: prefixes for display
        $san = [];
        if (!empty($p['extensions']['subjectAltName'])) {
            foreach (explode(',', $p['extensions']['subjectAltName']) as $entry) {
                $entry = trim($entry);
                if (str_starts_with($entry, 'DNS:'))    $san[] = substr($entry, 4);
                elseif (str_starts_with($entry, 'IP Address:')) $san[] = substr($entry, 11);
                elseif ($entry !== '')                  $san[] = $entry;
            }
        }

        // Public key — type, size, curve (EC), and the public-key PEM block
        $key_type = ''; $key_bits = 0; $key_curve = ''; $pub_pem = '';
        $pub = @openssl_pkey_get_public($cert);
        if ($pub !== false) {
            $details = @openssl_pkey_get_details($pub);
            if (is_array($details)) {
                $key_bits = (int) ($details['bits'] ?? 0);
                $pub_pem  = (string) ($details['key'] ?? '');
                $type_const = $details['type'] ?? -1;
                if ($type_const === OPENSSL_KEYTYPE_RSA) $key_type = 'RSA';
                elseif ($type_const === OPENSSL_KEYTYPE_DSA) $key_type = 'DSA';
                elseif ($type_const === OPENSSL_KEYTYPE_DH)  $key_type = 'DH';
                elseif (defined('OPENSSL_KEYTYPE_EC') && $type_const === OPENSSL_KEYTYPE_EC) {
                    $key_type  = 'EC';
                    $key_curve = (string) ($details['ec']['curve_name'] ?? '');
                }
            }
        }

        // Fingerprints — colon-separated like every cert tool prints them
        $fmt_fp = function (string $hex): string {
            $hex = strtoupper($hex);
            return implode(':', str_split($hex, 2));
        };
        $fp_sha256 = @openssl_x509_fingerprint($cert, 'sha256') ?: '';
        $fp_sha1   = @openssl_x509_fingerprint($cert, 'sha1')   ?: '';
        $fp_md5    = @openssl_x509_fingerprint($cert, 'md5')    ?: '';

        // Cert in PEM form (raw, full)
        $pem = '';
        @openssl_x509_export($cert, $pem);

        $valid_from = $p['validFrom_time_t'] ?? 0;
        $valid_to   = $p['validTo_time_t']   ?? 0;
        return [
            'version'        => (int) ($p['version'] ?? 0) + 1,   // X.509 reports 0/1/2; humans say v1/v2/v3
            'serial_hex'     => $p['serialNumberHex'] ?? '',
            'serial_dec'     => (string) ($p['serialNumber'] ?? ''),
            'subject'        => $p['name']    ?? '',
            'subject_parts'  => $p['subject'] ?? [],   // full DN as keyed array (CN, O, OU, C, ST, L, …)
            'subject_cn'     => $p['subject']['CN'] ?? '',
            'subject_org'    => $p['subject']['O']  ?? '',
            'issuer_dn'      => isset($p['issuer']) ? phproxy_dn_join($p['issuer']) : '',
            'issuer_parts'   => $p['issuer'] ?? [],
            'issuer_cn'      => $p['issuer']['CN'] ?? '',
            'issuer_org'     => $p['issuer']['O']  ?? '',
            'valid_from'     => $valid_from ? gmdate('Y-m-d\TH:i:s\Z', $valid_from) : '',
            'valid_to'       => $valid_to   ? gmdate('Y-m-d\TH:i:s\Z', $valid_to)   : '',
            'days_left'      => $valid_to ? (int) floor(($valid_to - time()) / 86400) : 0,
            'san'            => $san,
            'sig_algorithm'  => $p['signatureTypeSN'] ?? '',
            'sig_algorithm_long' => $p['signatureTypeLN'] ?? '',
            'sig_oid'        => isset($p['signatureTypeNID']) ? (string) $p['signatureTypeNID'] : '',
            'purposes'       => $p['purposes'] ?? [],
            'extensions'     => $p['extensions'] ?? [],   // all extensions, raw text per OpenSSL
            'key_type'       => $key_type,
            'key_bits'       => $key_bits,
            'key_curve'      => $key_curve,
            'public_key_pem' => $pub_pem,
            'fingerprints'   => [
                'sha256' => $fp_sha256 ? $fmt_fp($fp_sha256) : '',
                'sha1'   => $fp_sha1   ? $fmt_fp($fp_sha1)   : '',
                'md5'    => $fp_md5    ? $fmt_fp($fp_md5)    : '',
            ],
            'pem'            => $pem,
        ];
    };
    $cert_info  = $parse_cert($leaf);
    $chain_info = [];
    foreach ($chain as $c) {
        $ci = $parse_cert($c);
        if ($ci !== null) $chain_info[] = $ci;
    }

    // Probe TLS versions individually. For each, force the version via
    // crypto_method and record which the server actually accepts plus
    // the cipher it negotiates. ~4 extra ~100-500ms handshakes.
    $tls_probes = [
        'TLSv1.3' => defined('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT') ? STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT : 0,
        'TLSv1.2' => defined('STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT') ? STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT : 0,
        'TLSv1.1' => defined('STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT') ? STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT : 0,
        'TLSv1.0' => defined('STREAM_CRYPTO_METHOD_TLSv1_CLIENT')   ? STREAM_CRYPTO_METHOD_TLSv1_CLIENT   : 0,
    ];
    $tls_results = [];
    foreach ($tls_probes as $label => $method) {
        if ($method === 0) {
            $tls_results[] = ['version' => $label, 'supported' => false, 'error' => 'OpenSSL on this PHP build cannot speak ' . $label];
            continue;
        }
        $pt0 = microtime(true);
        $psock = false; $en = 0; $es = '';
        try {
            $psock = phproxy_open_public_socket($host, $port, true, min($cert_deadline, $pt0 + 3),
                ['crypto_method' => $method], true, $cert_address);
        } catch (Throwable $e) {
            $es = $e->getMessage();
        }
        $pms = (int) ((microtime(true) - $pt0) * 1000);
        if ($psock === false) {
            $tls_results[] = ['version' => $label, 'supported' => false, 'error' => $es ?: 'handshake refused', 'latency_ms' => $pms];
            continue;
        }
        $pmeta  = stream_get_meta_data($psock);
        @fclose($psock);
        $crypto = $pmeta['crypto'] ?? [];
        $tls_results[] = [
            'version'        => $label,
            'supported'      => true,
            'cipher_name'    => (string) ($crypto['cipher_name']    ?? ''),
            'cipher_bits'    => (int)    ($crypto['cipher_bits']    ?? 0),
            'cipher_version' => (string) ($crypto['cipher_version'] ?? ''),
            'protocol'       => (string) ($crypto['protocol']       ?? ''),
            'latency_ms'     => $pms,
        ];
    }

    // Negotiated handshake summary (what the server picked when given free choice).
    $main_crypto = $meta_main['crypto'] ?? [];

    echo json_encode([
        'ok'           => true,
        'host'         => $host,
        'port'         => $port,
        'negotiated'   => [
            'protocol'       => (string) ($main_crypto['protocol']       ?? ''),
            'cipher_name'    => (string) ($main_crypto['cipher_name']    ?? ''),
            'cipher_bits'    => (int)    ($main_crypto['cipher_bits']    ?? 0),
            'cipher_version' => (string) ($main_crypto['cipher_version'] ?? ''),
        ],
        'tls_versions' => $tls_results,
        'leaf'         => $cert_info,
        'chain'        => $chain_info,
        'chain_length' => count($chain_info),
        'duration_ms'  => $ms,
    ], JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    exit;
}

// --- IP INFO API (?api=ipinfo[&ip=1.2.3.4]) ------------------------------
// Returns information about the client, the server, and the server's
// outgoing IP — plus reverse DNS, the X-Forwarded-For chain, request
// headers and host info. Pure local PHP — no external lookups, no
// library, no API key. Geo / ASN / city are intentionally not included.
if (isset($_GET['api']) && $_GET['api'] === 'ipinfo') {
    header('Content-Type: application/json; charset=utf-8');
    $started = microtime(true);

    // If the caller passed ?ip=…, that's the single IP we describe.
    $custom_ip = trim((string) ($_GET['ip'] ?? ''));
    if ($custom_ip !== '' && !filter_var($custom_ip, FILTER_VALIDATE_IP)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'Invalid IP address', 'received' => $custom_ip]);
        exit;
    }

    $remote  = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
    $xff_raw = (string) ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? '');
    $xff_chain = [];
    if ($xff_raw !== '') {
        foreach (explode(',', $xff_raw) as $h) {
            $h = trim($h);
            if ($h !== '' && filter_var($h, FILTER_VALIDATE_IP)) $xff_chain[] = $h;
            if (count($xff_chain) >= 16) break;
        }
    }
    // Forwarded entries are untrusted informational data, never client identity.
    $client_ip = $remote;

    // Server's own primary IP via gethostbyname(hostname). Often the
    // internal Docker IP — useful but not "what the internet sees".
    $hostname  = gethostname() ?: '';
    $server_ip = '';
    if ($hostname !== '') {
        $resolved = @gethostbyname($hostname);
        if ($resolved !== false && $resolved !== $hostname) $server_ip = $resolved;
    }

    // Local interface selected for outbound traffic; NAT can change the public IP.
    // UDP connect selects a route without sending a packet.
    $outgoing_ip = phproxy_outgoing_ip();

    $shape = function (string $ip, bool $reverse = false): array {
        if ($ip === '') return ['ip' => ''];
        $is_priv = !phproxy_is_public_ip($ip);
        return [
            'ip'         => $ip,
            'family'     => str_contains($ip, ':') ? 'IPv6' : 'IPv4',
            'is_private' => (bool) $is_priv,
            'reverse'    => !$reverse || $is_priv ? '' : (@gethostbyaddr($ip) ?: ''),
        ];
    };

    if ($custom_ip !== '') {
        echo json_encode([
            'ok'          => true,
            'lookup'      => $shape($custom_ip, true),
            'duration_ms' => (int) ((microtime(true) - $started) * 1000),
        ], JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
        exit;
    }

    echo json_encode([
        'ok'        => true,
        'client'    => $shape($client_ip, true),
        'server'    => $shape($server_ip),
        'outgoing'  => $shape($outgoing_ip),
        'forwarded' => array_map($shape, $xff_chain),
        'request'   => [
            'method'          => $_SERVER['REQUEST_METHOD']      ?? '',
            'protocol'        => (!empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off') || ($_SERVER['SERVER_PORT'] ?? '') == '443' ? 'HTTPS' : 'HTTP',
            'remote_addr'     => $remote,
            'host_header'     => $_SERVER['HTTP_HOST']            ?? '',
            'user_agent'      => $_SERVER['HTTP_USER_AGENT']      ?? '',
            'accept_language' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
            'accept'          => $_SERVER['HTTP_ACCEPT']          ?? '',
            'referer'         => $_SERVER['HTTP_REFERER']         ?? '',
            'dnt'             => $_SERVER['HTTP_DNT']             ?? '',
            'sec_gpc'         => $_SERVER['HTTP_SEC_GPC']         ?? '',
            'sec_ch_ua'       => $_SERVER['HTTP_SEC_CH_UA']       ?? '',
            'sec_ch_ua_mobile'=> $_SERVER['HTTP_SEC_CH_UA_MOBILE']?? '',
            'sec_ch_ua_platform' => $_SERVER['HTTP_SEC_CH_UA_PLATFORM'] ?? '',
        ],
        'host'      => [
            'hostname'        => $hostname,
            'php_version'     => PHP_VERSION,
            'php_os'          => PHP_OS,
            'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? '',
            'server_port'     => $_SERVER['SERVER_PORT']     ?? '',
        ],
        'duration_ms' => (int) ((microtime(true) - $started) * 1000),
    ], JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    exit;
}

/**
 * Build a single-line DN string from the keyed array openssl_x509_parse()
 * returns. Order matches what `openssl x509 -text` prints.
 */
function phproxy_dn_join(array $parts): string
{
    $order = ['C', 'ST', 'L', 'O', 'OU', 'CN', 'emailAddress', 'serialNumber'];
    $out = [];
    foreach ($order as $k) {
        if (isset($parts[$k]) && $parts[$k] !== '') $out[] = "$k=" . (is_array($parts[$k]) ? implode('+', $parts[$k]) : $parts[$k]);
    }
    foreach ($parts as $k => $v) {
        if (in_array($k, $order, true)) continue;
        if ($v === '' || $v === null) continue;
        $out[] = "$k=" . (is_array($v) ? implode('+', $v) : $v);
    }
    return implode(', ', $out);
}

/**
 * Determine the outgoing IPv4 address this server uses when reaching out
 * to the wider internet. UDP "connect" trick: no packets are actually
 * sent, but the kernel picks the outgoing interface so stream_socket_get_name
 * on the local side returns the right answer.
 */
function phproxy_outgoing_ip(): string
{
    $sock = @stream_socket_client('udp://1.1.1.1:53', $en, $es, 1);
    if ($sock === false) {
        $sock = @stream_socket_client('udp://8.8.8.8:53', $en, $es, 1);
    }
    if ($sock === false) return '';
    $name = @stream_socket_get_name($sock, false);  // local side
    @fclose($sock);
    if (!is_string($name) || $name === '') return '';
    // "1.2.3.4:54321" or "[::1]:54321" — strip port.
    if (preg_match('/^\[([^\]]+)\]:\d+$/', $name, $m)) return $m[1];
    if (preg_match('/^([0-9.]+):\d+$/', $name, $m))    return $m[1];
    return $name;
}

if (isset($_GET['api']) && $_GET['api'] === 'fetch') {
    // Helper for any JSON error response in this dispatcher
    $api_json_err = function (int $status, string $msg, array $extra = []): void {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['ok' => false, 'error' => $msg] + $extra, JSON_UNESCAPED_SLASHES);
        exit;
    };

    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        header('Allow: POST');
        $api_json_err(405, 'POST required');
    }
    if (strtolower(trim(explode(';', (string) ($_SERVER['CONTENT_TYPE'] ?? ''), 2)[0])) !== 'application/json') {
        $api_json_err(415, 'Content-Type application/json required');
    }
    try {
        $public_url = phproxy_public_script_url($_SERVER);
    } catch (Throwable $e) {
        $api_json_err(500, 'Invalid public URL configuration');
    }
    if (isset($_SERVER['HTTP_ORIGIN']) && !phproxy_api_origin_allowed((string) $_SERVER['HTTP_ORIGIN'], $public_url)) {
        $api_json_err(403, 'Cross-origin API requests are not permitted');
    }
    $raw_in = file_get_contents('php://input', false, null, 0, 3 * 1024 * 1024 + 1);
    if ($raw_in === false || strlen($raw_in) > 3 * 1024 * 1024) $api_json_err(413, 'JSON request exceeds 3 MiB');
    $req_in = json_decode($raw_in, true, 32);
    if (!is_array($req_in) || !is_string($req_in['url'] ?? null) || $req_in['url'] === '') $api_json_err(400, 'Invalid JSON body or missing "url"');
    if (($req_in['verify_ssl'] ?? true) !== true) $api_json_err(400, 'TLS certificate verification cannot be disabled');

    $api_result = phproxy_api_fetch($req_in);

    if (($req_in['return'] ?? 'json') === 'raw') {
        if (empty($api_result['ok'])) $api_json_err($api_result['http_status'] ?? 502, $api_result['error'] ?? 'Upstream request failed');
        http_response_code($api_result['status']);
        // Only representation headers belong on the proxy response. Never import
        // upstream origin policy, cookies, redirects or authentication challenges.
        foreach (['content-type', 'content-language', 'content-encoding'] as $name) {
            if (isset($api_result['headers'][$name])) header($name . ': ' . $api_result['headers'][$name]);
        }
        phproxy_untrusted_response_headers(false);
        echo $api_result['body_raw'];
        exit;
    }

    // JSON envelope. UTF-8 bodies go in directly, binary gets base64'd.
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    if (empty($api_result['ok'])) http_response_code($api_result['http_status'] ?? 502);
    $body_raw = $api_result['body_raw'] ?? '';
    if ($body_raw !== '' && preg_match('//u', $body_raw) === 1) {
        $api_result['body']          = $body_raw;
        $api_result['body_encoding'] = 'utf8';
    } else {
        $api_result['body']          = base64_encode($body_raw);
        $api_result['body_encoding'] = 'base64';
    }
    unset($api_result['body_raw']);
    echo json_encode($api_result, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

//
// CONFIGURABLE OPTIONS
//

$_config            =
                    [
                        'url_var_name'             => '_proxurl',
                        'flags_var_name'           => '_proxfl',
                        'get_form_name'            => '_proxgfn',
                        'basic_auth_var_name'      => '_proxba',
                        'site_name'                => 'PHProxy',
                        'max_file_size'            => 8388608,
                        'allow_hotlinking'         => 0,
                        'upon_hotlink'             => 1,
                        'compress_output'          => 0,
                    ];
// NOTE on order: new flags MUST be appended to the head of $_flags so the
// bitfield positions of existing flags stay stable (the cookie stores the
// flag bitfield as a left-padded binary string — adding to the tail would
// shift the existing flags and break every saved cookie).
$_flags             =
                    [
                        // new in v1.3.x — anonymity seed URL encryption (on by default)
                        'encrypt_url'     => 1,
                        // new in v1.3.0 (privacy / blocking)
                        'strip_tracking'  => 0,
                        'send_gpc'        => 0,
                        'send_dnt'        => 0,
                        'block_media'     => 0,
                        'block_fonts'     => 0,
                        'block_3p'        => 0,
                        'strip_iframes'   => 0,
                        // original flags (positions preserved)
                        'include_form'    => 1,
                        'remove_scripts'  => 1,
                        'accept_cookies'  => 1,
                        'show_images'     => 1,
                        'show_referer'    => 1,
                        'rotate13'        => 0,
                        'base64_encode'   => 1,
                        'strip_meta'      => 0,
                        'strip_title'     => 1,
                        'session_cookies' => 1,
                    ];
$_frozen_flags      =
                    [
                        'encrypt_url'     => 0,
                        'strip_tracking'  => 0,
                        'send_gpc'        => 0,
                        'send_dnt'        => 0,
                        'block_media'     => 0,
                        'block_fonts'     => 0,
                        'block_3p'        => 0,
                        'strip_iframes'   => 0,
                        'include_form'    => 0,
                        'remove_scripts'  => 0,
                        'accept_cookies'  => 0,
                        'show_images'     => 0,
                        'show_referer'    => 0,
                        'rotate13'        => 0,
                        'base64_encode'   => 0,
                        'strip_meta'      => 0,
                        'strip_title'     => 0,
                        'session_cookies' => 0,
                    ];
$_labels            =
                    [
                        'encrypt_url'     => ['Encrypted (rotating key)',  'AES-CTR encrypt URLs with a 1-hour session seed; old logs go unusable'],
                        'strip_tracking'  => ['Strip tracking params',     'Drop utm_*, fbclid, gclid and friends from URLs'],
                        'send_gpc'        => ['Send Sec-GPC: 1',           'Global Privacy Control signal'],
                        'send_dnt'        => ['Send DNT: 1',               'Do-Not-Track header'],
                        'block_media'     => ['Block media',               'Remove <video> and <audio> from proxied pages'],
                        'block_fonts'     => ['Block web fonts',           'Remove font CDN links and @font-face rules'],
                        'block_3p'        => ['Block 3rd-party resources', 'Don\'t proxy assets from a different host than the page'],
                        'strip_iframes'   => ['Strip iframes',             'Remove <iframe> elements from proxied pages'],
                        'include_form'    => ['Show top bar while browsing', 'Pin the URL bar to the top of every proxied page'],
                        'remove_scripts'  => ['Block JavaScript',          'Strip <script> tags from proxied HTML'],
                        'accept_cookies'  => ['Allow cookies',             'Store and forward cookies from proxied sites'],
                        'show_images'     => ['Load images',               'Show images on proxied pages'],
                        'show_referer'    => ['Send Referer header',       'Forward Referer to the target'],
                        'rotate13'        => ['ROT13',                     'ROT13 the URL in the address bar'],
                        'base64_encode'   => ['Base64',                    'Base64-encode the URL in the address bar'],
                        'strip_meta'      => ['Strip <meta> tags',         'Remove meta tags from proxied pages'],
                        'strip_title'     => ['Hide page title',           'Strip <title> so the browser tab is anonymous'],
                        'session_cookies' => ['Session-only cookies',      'Forget cookies when the browser closes'],
                    ];

$_hosts             =
                    [
                        '#^127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|localhost#i',
                    ];
$_hotlink_domains   = [];
$_insert            = [];

//
// END CONFIGURABLE OPTIONS. The ride for you ends here. Close the file.
//

$_iflags            = '';
$_system            =
                    [
                        'ssl'          => extension_loaded('openssl') && version_compare(PHP_VERSION, '4.3.0', '>='),
                        'uploads'      => ini_get('file_uploads'),
                        'gzip'         => extension_loaded('zlib') && !ini_get('zlib.output_compression'),
                        'stripslashes' => false,
                    ];
$_proxify           =
                    [
                        'text/html'             => 1,
                        'application/xml+xhtml' => 1,
                        'application/xhtml+xml' => 1,
                        'text/css'              => 1,
                    ];
$_version           = 'v1.4.0';
$_script_url        = phproxy_public_script_url($_SERVER);
$_http_host         = (string) parse_url($_script_url, PHP_URL_HOST);
$_script_base       = substr($_script_url, 0, strrpos($_script_url, '/')+1);
$_url               = '';
$_url_parts         = [];
$_base              = [];
$_socket            = null;
$_request_method    = $_SERVER['REQUEST_METHOD'];
$_request_headers   = '';
$_cookie            = '';
$_post_body         = '';
$_response_headers  = [];
$_response_keys     = [];
$_http_version      = '';
$_response_code     = 0;
$_content_type      = 'text/html';
$_content_length    = false;
$_content_disp      = '';
$_set_cookie        = [];
$_retry             = false;
$_quit              = false;
$_basic_auth_header = '';
$_basic_auth_realm  = '';
$_auth_creds        = [];
$_response_body     = '';
$pos = phproxy_user_agent_setting();
if(!isset($pos) || $pos == ""){ // empty means old method
  $_user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'PHProxy/'.$_version;
}else if($pos == '.'){ // dot means use the browsers UA
  $_user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'PHProxy/'.$_version;
}else if($pos == '-'){ // dash means dont set UA
  $_user_agent = null;
}else{
  $_user_agent = $pos;
}

# to bind to a specific ip set $_bindip to desired IP
# if you do not need to set a specific port use 0 as default
#   example:
#   $_bindip = '192.168.1.100:0';
# for default ip set value to default
#   $_bindip = 'default';
$_bindip           = 'default';

// Functions declaration
function show_report(array $data): void
{
    phproxy_render_entry_form($data);
    exit(0);
}

function add_cookie(string $name, mixed $value, int $expires = 0): string
{
    return rawurlencode(rawurlencode($name)) . '=' . rawurlencode(rawurlencode($value)) . (empty($expires) ? '' : '; expires=' . gmdate('D, d-M-Y H:i:s \G\M\T', $expires)) . '; Path=/; SameSite=Lax' . (phproxy_is_https() ? '; Secure' : '');
}

function set_post_vars(array $array, ?string $parent_key = null): array
{
    $temp = [];

    foreach ($array as $key => $value) {
        $key = isset($parent_key) ? sprintf('%s[%s]', $parent_key, urlencode($key)) : urlencode($key);
        if (is_array($value)) {
            $temp = array_merge($temp, set_post_vars($value, $key));
        } else {
            $temp[$key] = urlencode($value);
        }
    }

    return $temp;
}

function set_post_files(array $array, ?string $parent_key = null): array
{
    $temp = [];

    foreach ($array as $key => $value) {
        $key = isset($parent_key) ? sprintf('%s[%s]', $parent_key, urlencode($key)) : urlencode($key);
        if (is_array($value)) {
            $temp = array_merge_recursive($temp, set_post_files($value, $key));
        } else if (preg_match('#^([^\[\]]+)\[(name|type|tmp_name)\]#', $key, $m)) {
            $temp[str_replace($m[0], $m[1], $key)][$m[2]] = $value;
        }
    }

    return $temp;
}

function url_parse(string $url, array &$container): bool
{
    $temp = @parse_url($url);

    if (!empty($temp)) {
        $temp['port_ext'] = '';
        $temp['base']     = $temp['scheme'] . '://' . $temp['host'];

        if (isset($temp['port'])) {
            $temp['base'] .= $temp['port_ext'] = ':' . $temp['port'];
        } else {
            $temp['port'] = $temp['scheme'] === 'https' ? 443 : 80;
        }

        $temp['path'] = isset($temp['path']) ? $temp['path'] : '/';
        $path         = [];
        $temp['path'] = explode('/', $temp['path']);

        foreach ($temp['path'] as $dir) {
            if ($dir === '..') {
                array_pop($path);
            } else if ($dir !== '.') {
                for ($dir = rawurldecode($dir), $new_dir = '', $i = 0, $count_i = strlen($dir); $i < $count_i; $new_dir .= strspn($dir[$i], 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$-_.+!*\'(),?:@&;=') ? $dir[$i] : rawurlencode($dir[$i]), ++$i);
                $path[] = $new_dir;
            }
        }

        $temp['path'] = str_replace('/%7E', '/~', '/' . ltrim(implode('/', $path), '/'));
        $temp['file'] = substr($temp['path'], strrpos($temp['path'], '/') + 1);
        $temp['dir']  = substr($temp['path'], 0, strrpos($temp['path'], '/'));
        $temp['base'] .= $temp['dir'];
        $temp['prev_dir'] = substr_count($temp['path'], '/') > 1 ? substr($temp['base'], 0, strrpos($temp['base'], '/') + 1) : $temp['base'] . '/';
        $container        = $temp;

        return true;
    }

    return false;
}

/**
 * Parse the raw Cookie request header into wire-form (name, value) pairs.
 * Unlike $_COOKIE, this preserves the exact wire-form name as the browser
 * sent it — no URL decoding, no PHP dot→underscore mangling. We need this
 * to be able to expire proxy-stored cookies via setrawcookie() with the
 * matching name (PHP's setcookie() would URL-encode again and produce a
 * triple-encoded name that doesn't match the browser's stored cookie).
 */
function phproxy_raw_cookies(): array
{
    $out = [];
    $raw = isset($_SERVER['HTTP_COOKIE']) ? (string) $_SERVER['HTTP_COOKIE'] : '';
    if ($raw === '') return $out;
    foreach (explode(';', $raw) as $pair) {
        $pair = ltrim($pair);
        if ($pair === '') continue;
        $eq = strpos($pair, '=');
        if ($eq === false) {
            $out[$pair] = '';
        } else {
            $out[substr($pair, 0, $eq)] = substr($pair, $eq + 1);
        }
    }
    return $out;
}

/**
 * Decode a wire-form cookie name that follows the proxy's
 * COOKIE;<name>;<path>;<domain> format. Returns [name, path, domain] or
 * null if the wire form doesn't match. Walks back the double URL-encoding
 * that add_cookie() applies on the way out.
 */
function phproxy_decode_proxy_cookie_id(string $wire_name): ?array
{
    // Double-rawurldecode the wire form to get the human-readable id
    $decoded = rawurldecode(rawurldecode($wire_name));
    if (strpos($decoded, 'COOKIE;') !== 0) {
        return null;
    }
    $parts = explode(';', $decoded, 4);
    if (count($parts) !== 4) {
        return null;
    }
    return [
        'name'   => $parts[1],
        'path'   => $parts[2],
        'domain' => $parts[3],
    ];
}

/**
 * Decode the value half of a proxy-stored cookie (which has the format
 * "<value>;<secure_flag>" where secure_flag is "secure" or empty).
 * Walks back the double-rawurlencode applied on the way out.
 */
function phproxy_decode_proxy_cookie_value(string $wire_value): array
{
    $decoded = rawurldecode(rawurldecode($wire_value));
    $semi    = strrpos($decoded, ';');
    if ($semi === false) {
        return ['value' => $decoded, 'secure' => false];
    }
    return [
        'value'  => substr($decoded, 0, $semi),
        'secure' => strtolower(trim(substr($decoded, $semi + 1))) === 'secure',
    ];
}

/**
 * Shared User-Agent preset list used by both the entry form's Headers tab
 * and the inline panel injected onto proxied pages.
 */
function phproxy_ua_presets(): array
{
    return [
        ''  => '— Default browser User-Agent —',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36' => 'Chrome on Windows',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15' => 'Safari on macOS',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1' => 'Safari on iPhone',
        'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36' => 'Chrome on Android',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36' => 'Chrome on Linux',
        'Mozilla/5.0 (X11; CrOS x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36' => 'Chrome on ChromeOS',
        'curl/8.5.0'  => 'curl 8.5',
        'Wget/1.21.4' => 'wget 1.21',
        '.' => '★ Use my real browser User-Agent',
        '-' => '★ Send no User-Agent at all',
    ];
}

/**
 * Parse $_SERVER['HTTP_COOKIE'] and bucket the non-settings entries into
 * the structure the panel template expects. Used by both the entry form
 * and the inline panel injection.
 */
function phproxy_panel_buckets(): array
{
    $state = phproxy_state_snapshot();
    $visible = $headers = $origins = [];
    foreach ($state['phproxy_jar'] ?? [] as $id => $cookie) {
        if ($cookie['expires'] !== 0 && $cookie['expires'] <= time()) continue;
        $visible[$id] = $cookie + [
            'display_name' => $cookie['name'], 'host' => $cookie['domain'],
            'raw_name' => $id, 'raw_value' => $cookie['value'], 'is_proxy' => true,
        ];
    }
    foreach ($state['phproxy_headers'] ?? [] as $name => $entry) {
        $headers[$name] = $entry['value'];
        $origins[$name] = $entry['origin'];
    }
    return ['cookies' => $visible, 'headers' => $headers, 'header_origins' => $origins];
}

function phproxy_public_script_url(array $server, ?string $configured = null): string
{
    $configured ??= (string) (getenv('PHPROXY_PUBLIC_URL') ?: '');
    $script = (string) ($server['SCRIPT_NAME'] ?? '/index.php');
    if (!preg_match('~^/[A-Za-z0-9_./%-]+$~D', $script)) $script = '/index.php';
    if ($configured !== '') {
        $p = parse_url($configured);
        if ($p === false || !in_array(strtolower($p['scheme'] ?? ''), ['http', 'https'], true)
            || empty($p['host']) || isset($p['user']) || isset($p['pass'])
            || isset($p['query']) || isset($p['fragment']) || preg_match('/[\x00-\x20\x7f]/', $configured)) {
            throw new RuntimeException('PHPROXY_PUBLIC_URL must be an absolute HTTP(S) URL without credentials, query or fragment.');
        }
        if (!isset($p['path']) || $p['path'] === '') return $configured . '/' . basename($script);
        return $configured . (str_ends_with($p['path'], '/') ? basename($script) : '');
    }
    $authority = (string) ($server['HTTP_HOST'] ?? $server['SERVER_NAME'] ?? 'localhost');
    if (!preg_match('/^(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])(?::[0-9]{1,5})?$/D', $authority)) $authority = 'localhost';
    $https = (!empty($server['HTTPS']) && strtolower((string) $server['HTTPS']) !== 'off')
        || (int) ($server['SERVER_PORT'] ?? 80) === 443;
    return ($https ? 'https://' : 'http://') . $authority . $script;
}

function phproxy_is_https(): bool
{
    return strtolower((string) parse_url(phproxy_public_script_url($_SERVER), PHP_URL_SCHEME)) === 'https';
}

function phproxy_state_open(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) return;
    if (!session_start([
        'use_strict_mode' => 1, 'use_only_cookies' => 1, 'cookie_lifetime' => 0,
        'cookie_path' => '/', 'cookie_secure' => phproxy_is_https(),
        'cookie_httponly' => true, 'cookie_samesite' => 'Lax', 'cache_limiter' => 'nocache',
    ])) throw new RuntimeException('Unable to initialize private proxy session.');
}

function phproxy_state_close(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) session_write_close();
}

function phproxy_state_snapshot(): array
{
    phproxy_state_open();
    $state = $_SESSION;
    phproxy_state_close();
    return $state;
}

function phproxy_csrf_token(): string
{
    if (isset($GLOBALS['_phproxy_csrf_cache'])) return $GLOBALS['_phproxy_csrf_cache'];
    phproxy_state_open();
    if (!isset($_SESSION['phproxy_csrf'])) $_SESSION['phproxy_csrf'] = bin2hex(random_bytes(32));
    $token = $_SESSION['phproxy_csrf'];
    phproxy_state_close();
    $GLOBALS['_phproxy_csrf_cache'] = $token;
    return $token;
}

function phproxy_csrf_valid(): bool
{
    $supplied = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    $state = phproxy_state_snapshot();
    return is_string($supplied) && isset($state['phproxy_csrf'])
        && hash_equals($state['phproxy_csrf'], $supplied);
}

function phproxy_require_csrf(): void
{
    if (!phproxy_csrf_valid()) {
        http_response_code(403);
        header('Content-Type: text/plain; charset=utf-8');
        exit('The form expired. Open the proxy home page and submit it again.');
    }
}

function phproxy_user_agent_setting(): string
{
    return (string) (phproxy_state_snapshot()['phproxy_ua'] ?? '');
}

function phproxy_network_entries(): array
{
    return phproxy_state_snapshot()['phproxy_network'] ?? [];
}

function phproxy_trace_entries(): array
{
    return phproxy_state_snapshot()['phproxy_trace'] ?? [];
}

function phproxy_request_origin(string $url): string
{
    $p = parse_url($url);
    if ($p === false || !in_array(strtolower($p['scheme'] ?? ''), ['http', 'https'], true)
        || empty($p['host']) || isset($p['user']) || isset($p['pass'])
        || preg_match('/[\x00-\x20\x7f]/', $url)) return '';
    $scheme = strtolower($p['scheme']);
    return $scheme . '://' . strtolower(rtrim($p['host'], '.')) . ':' . ($p['port'] ?? ($scheme === 'https' ? 443 : 80));
}

function phproxy_cookie_id(array $cookie): string
{
    return hash('sha256', $cookie['name'] . "\n" . $cookie['domain'] . "\n" . $cookie['path']);
}

function phproxy_cookie_domain_matches(string $host, string $domain, bool $hostOnly): bool
{
    $host = strtolower(rtrim($host, '.'));
    $domain = strtolower(ltrim(rtrim($domain, '.'), '.'));
    return $host === $domain || (!$hostOnly && !filter_var($host, FILTER_VALIDATE_IP)
        && str_ends_with($host, '.' . $domain));
}

function phproxy_cookie_path_matches(string $path, string $cookiePath): bool
{
    return $path === $cookiePath || (str_starts_with($path, $cookiePath)
        && (str_ends_with($cookiePath, '/') || substr($path, strlen($cookiePath), 1) === '/'));
}

function phproxy_cookie_parse(string $line, string $url, bool $sessionOnly, ?int $now = null): ?array
{
    $now ??= time();
    $target = parse_url($url);
    $host = strtolower(rtrim($target['host'] ?? '', '.'));
    if ($host === '' || strlen($line) > 4096 || preg_match('/[\x00-\x1f\x7f]/', $line)) return null;
    $parts = explode(';', $line);
    $pair = explode('=', trim(array_shift($parts)), 2);
    if (count($pair) !== 2 || !preg_match("/^[!#$%&'*+.^_\x60|~0-9A-Za-z-]+$/D", $pair[0])) return null;
    $requestPath = $target['path'] ?? '/';
    $slash = strrpos($requestPath, '/');
    $defaultPath = $slash === false || $slash === 0 ? '/' : substr($requestPath, 0, $slash);
    $cookie = ['name' => $pair[0], 'value' => $pair[1], 'domain' => $host, 'host_only' => true,
        'path' => $defaultPath, 'secure' => false, 'httponly' => false, 'samesite' => '', 'expires' => 0];
    $maxAge = null;
    foreach ($parts as $part) {
        [$key, $value] = array_pad(explode('=', trim($part), 2), 2, '');
        $key = strtolower($key);
        if ($key === 'domain') {
            $domain = strtolower(ltrim(trim($value), '.'));
            // Preserve same-host sessions, but deliberately narrow valid
            // Domain cookies to their setting host without a suffix database.
            if (!phproxy_cookie_domain_matches($host, $domain, false)) return null;
            if (str_starts_with($cookie['name'], '__Host-')) return null;
        } elseif ($key === 'path' && str_starts_with($value, '/')) {
            $cookie['path'] = $value;
        } elseif ($key === 'secure') {
            $cookie['secure'] = true;
        } elseif ($key === 'httponly') {
            $cookie['httponly'] = true;
        } elseif ($key === 'samesite' && in_array(strtolower($value), ['lax', 'strict', 'none'], true)) {
            $cookie['samesite'] = ucfirst(strtolower($value));
        } elseif ($key === 'max-age' && preg_match('/^-?[0-9]+$/D', $value)) {
            $maxAge = (int) $value;
        } elseif ($key === 'expires') {
            $expires = strtotime($value);
            if ($expires !== false) $cookie['expires'] = $expires === 0 ? 1 : $expires;
        }
    }
    if ($maxAge !== null) $cookie['expires'] = $maxAge <= 0 ? 1 : $now + min($maxAge, 31536000);
    if ($sessionOnly && $cookie['expires'] > $now) $cookie['expires'] = 0;
    if ($cookie['secure'] && strtolower($target['scheme'] ?? '') !== 'https') return null;
    if (str_starts_with($cookie['name'], '__Secure-') && !$cookie['secure']) return null;
    if (str_starts_with($cookie['name'], '__Host-') && (!$cookie['secure'] || $cookie['path'] !== '/')) return null;
    return $cookie;
}

function phproxy_cookie_header(array $jar, string $url, bool $acceptCookies, ?int $now = null): string
{
    if (!$acceptCookies) return '';
    $now ??= time();
    $target = parse_url($url);
    $matching = [];
    foreach ($jar as $cookie) {
        if (($cookie['expires'] !== 0 && $cookie['expires'] <= $now)
            || ($cookie['secure'] && strtolower($target['scheme'] ?? '') !== 'https')
            || !phproxy_cookie_domain_matches($target['host'] ?? '', $cookie['domain'], $cookie['host_only'])
            || !phproxy_cookie_path_matches($target['path'] ?? '/', $cookie['path'])) continue;
        $matching[] = $cookie;
    }
    usort($matching, fn($a, $b) => strlen($b['path']) <=> strlen($a['path']));
    return implode('; ', array_map(fn($c) => $c['name'] . '=' . $c['value'], $matching));
}

function phproxy_store_cookies(array $lines, string $url, bool $acceptCookies, bool $sessionOnly): void
{
    if (!$acceptCookies) return;
    phproxy_state_open();
    $jar = $_SESSION['phproxy_jar'] ?? [];
    foreach ($jar as $id => $cookie) {
        if ($cookie['expires'] !== 0 && $cookie['expires'] <= time()) unset($jar[$id]);
    }
    foreach (array_slice($lines, 0, 100) as $line) {
        $cookie = phproxy_cookie_parse($line, $url, $sessionOnly);
        if ($cookie === null) continue;
        $id = phproxy_cookie_id($cookie);
        if ($cookie['expires'] !== 0 && $cookie['expires'] <= time()) unset($jar[$id]);
        else $jar[$id] = $cookie;
    }
    $_SESSION['phproxy_jar'] = array_slice($jar, -100, null, true);
    phproxy_state_close();
}

/**
 * Anonymity seed configuration — TTL (seconds) and key length (bytes).
 * Both adjustable from the Options tab; stored in long-lived settings
 * cookies that survive seed rotation.
 *
 *   phproxy-seed-ttl   3600 default, clamped to [60, 7 days]
 *   phproxy-seed-bits  256  default, accepts 128 / 192 / 256
 */
function phproxy_seed_ttl(): int
{
    $ttl = isset($_COOKIE['phproxy-seed-ttl']) ? (int) $_COOKIE['phproxy-seed-ttl'] : 3600;
    if ($ttl < 60)         $ttl = 60;
    if ($ttl > 86400 * 7)  $ttl = 86400 * 7;
    return $ttl;
}

function phproxy_seed_bits(): int
{
    $bits = isset($_COOKIE['phproxy-seed-bits']) ? (int) $_COOKIE['phproxy-seed-bits'] : 256;
    return in_array($bits, [128, 192, 256], true) ? $bits : 256;
}

function phproxy_seed_cipher(): string
{
    return 'aes-' . phproxy_seed_bits() . '-ctr';
}

/**
 * URL keys stay server-side. Expiration is enforced here, independently
 * of the browser; the per-request cache avoids session I/O per HTML link.
 */
function phproxy_seed(): string
{
    $want_bytes = intdiv(phproxy_seed_bits(), 8);
    $cached = $GLOBALS['_phproxy_seed_cache'] ?? null;
    if (is_array($cached) && strlen($cached['key']) === $want_bytes && $cached['expires'] > time()) return $cached['key'];
    phproxy_state_open();
    $entry = $_SESSION['phproxy_seed'] ?? null;
    if (!is_array($entry) || strlen($entry['key'] ?? '') !== $want_bytes || ($entry['expires'] ?? 0) <= time()) {
        $entry = ['key' => random_bytes($want_bytes), 'expires' => time() + phproxy_seed_ttl()];
        $_SESSION['phproxy_seed'] = $entry;
    }
    phproxy_state_close();
    $GLOBALS['_phproxy_seed_cache'] = $entry;
    return $entry['key'];
}

function phproxy_seed_present(): bool
{
    $entry = phproxy_state_snapshot()['phproxy_seed'] ?? null;
    return is_array($entry) && ($entry['expires'] ?? 0) > time()
        && strlen($entry['key'] ?? '') === intdiv(phproxy_seed_bits(), 8);
}

/**
 * AES-CTR (128/192/256-bit per phproxy-seed-bits) encrypt the URL with a
 * key derived from the session seed, then HMAC-SHA-256 the (iv||ciphertext)
 * and append a 128-bit tag. Result is base64-url-encoded (no padding) so
 * it goes into the address bar cleanly.
 */
function phproxy_encrypt_url(string $url): string
{
    $seed    = phproxy_seed();
    $cipher  = phproxy_seed_cipher();
    $klen    = phproxy_seed_bits() / 8;
    // SHA-256 derives a 32-byte stream; truncate to AES key length
    $key_enc = substr(hash('sha256', $seed . "\x01enc", true), 0, $klen);
    $key_mac = hash('sha256', $seed . "\x02mac", true);
    $iv      = random_bytes(16);
    $ct      = openssl_encrypt($url, $cipher, $key_enc, OPENSSL_RAW_DATA, $iv);
    if ($ct === false) return '';
    $mac     = substr(hash_hmac('sha256', $iv . $ct, $key_mac, true), 0, 16);
    return rtrim(strtr(base64_encode($iv . $ct . $mac), '+/', '-_'), '=');
}

/**
 * Reverse of phproxy_encrypt_url. Returns null when:
 *   - the seed cookie is missing or malformed (typically because it rotated)
 *   - the base64-url token is malformed
 *   - the HMAC tag doesn't verify (tampering or wrong key)
 *   - openssl_decrypt fails
 */
function phproxy_decrypt_url(string $token): ?string
{
    $bits = phproxy_seed_bits();
    $klen = intdiv($bits, 8);
    $entry = $GLOBALS['_phproxy_seed_cache'] ?? (phproxy_state_snapshot()['phproxy_seed'] ?? null);
    if (!is_array($entry) || ($entry['expires'] ?? 0) <= time() || strlen($entry['key'] ?? '') !== $klen) return null;
    $seed = $entry['key'];
    $GLOBALS['_phproxy_seed_cache'] = $entry;

    $b64 = strtr($token, '-_', '+/');
    $pad = strlen($b64) % 4;
    if ($pad) $b64 .= str_repeat('=', 4 - $pad);
    $blob = base64_decode($b64, true);
    if ($blob === false || strlen($blob) < 32) return null;

    $iv  = substr($blob, 0, 16);
    $ct  = substr($blob, 16, -16);
    $tag = substr($blob, -16);

    $key_enc  = substr(hash('sha256', $seed . "\x01enc", true), 0, $klen);
    $key_mac  = hash('sha256', $seed . "\x02mac", true);
    $expected = substr(hash_hmac('sha256', $iv . $ct, $key_mac, true), 0, 16);
    if (!hash_equals($expected, $tag)) return null;

    $pt = openssl_decrypt($ct, 'aes-' . $bits . '-ctr', $key_enc, OPENSSL_RAW_DATA, $iv);
    return $pt === false ? null : $pt;
}

/**
 * Drop tracking query parameters (utm_*, fbclid, gclid, ...) from a URL.
 * No-op unless the strip_tracking flag is on. Called both at dispatch
 * (clean the user-typed URL) and during in-page link rewriting.
 */
function strip_tracking_params(string $url): string
{
    if (empty($GLOBALS['_flags']['strip_tracking'])) {
        return $url;
    }
    $parts = @parse_url($url);
    if (empty($parts) || empty($parts['query'])) {
        return $url;
    }
    parse_str($parts['query'], $params);
    $tracking = [
        'utm_source', 'utm_medium', 'utm_campaign', 'utm_term',
        'utm_content', 'utm_id', 'utm_name', 'utm_referrer', 'utm_pubreferrer',
        'fbclid', 'gclid', 'gclsrc', 'msclkid', 'dclid', 'yclid',
        'mc_eid', 'mc_cid',
        '_ga', '_gid',
        'vero_id', 'vero_conv',
        'hsCtaTracking',
        'oly_anon_id', 'oly_enc_id',
        '__hstc', '__hssc', '__hsfp',
        'igshid', 'twclid', 'ttclid',
        'mkt_tok',
        'wickedid', 'wickedsource',
    ];
    foreach ($tracking as $k) {
        foreach ([$k, strtoupper($k)] as $variant) {
            unset($params[$variant]);
        }
    }
    $new_query = http_build_query($params);
    $rebuilt   = (isset($parts['scheme']) ? $parts['scheme'] . '://' : '')
               . (isset($parts['user']) ? $parts['user'] . (isset($parts['pass']) ? ':' . $parts['pass'] : '') . '@' : '')
               . ($parts['host'] ?? '')
               . (isset($parts['port']) ? ':' . $parts['port'] : '')
               . ($parts['path'] ?? '')
               . ($new_query !== '' ? '?' . $new_query : '')
               . (isset($parts['fragment']) ? '#' . $parts['fragment'] : '');
    return $rebuilt;
}

function complete_url(string $url, bool $proxify = true): string
{
    $url = html_entity_decode(trim($url));

    if ($url === '') {
        return '';
    }

    if (substr($url, 0, 5) == 'data:' ||
        substr($url, 0, 11) == 'javascript:' ||
        substr($url, 0, 6) == 'about:' ||
        substr($url, 0, 7) == 'magnet:' ||
        substr($url, 0, 4) == 'tel:' ||
        substr($url, 0, 8) == 'ios-app:' ||
        substr($url, 0, 12) == 'android-app:' ||
        substr($url, 0, 7) == 'mailto:' ||
        substr($url, 0, 6) == 'rms://') {
        return $url;
    }

    $hash_pos                   = strrpos($url, '#');
    $fragment                   = $hash_pos !== false ? substr($url, $hash_pos) : '';
    $sep_pos                    = strpos($url, '://');
    $BASE_ORIGIN                = parse_url($GLOBALS['_url']);
    $GLOBALS['_base']['scheme'] = empty($GLOBALS['_base']['scheme']) ? $BASE_ORIGIN['scheme'] : $GLOBALS['_base']['scheme'];
    $GLOBALS['_base']['host']   = empty($GLOBALS['_base']['host']) ? $BASE_ORIGIN['host'] : $GLOBALS['_base']['host'];

    if ($sep_pos === false || $sep_pos > 5) {
        switch ($url[0]) {
        case '/':
            $url = substr($url, 0, 2) === '//' ? $GLOBALS['_base']['scheme'] . ':' . $url : $GLOBALS['_base']['scheme'] . '://' . $GLOBALS['_base']['host'] . $GLOBALS['_base']['port_ext'] . $url;
            break;
        case '?':
            $url = $GLOBALS['_base']['base'] . '/' . $GLOBALS['_base']['file'] . $url;
            break;
        case '#':
            $proxify = false;
            break;
        default:
            $url = $GLOBALS['_base']['base'] . '/' . $url;
        }
    }

    // Block 3rd-party resources: if the resolved URL's host differs from the
    // page's host (modulo a leading "www."), neutralize the link so the proxy
    // never fetches the resource.
    if ($proxify && !empty($GLOBALS['_flags']['block_3p']) && !empty($GLOBALS['_url_parts']['host'])) {
        $resolved_host = strtolower((string) (@parse_url($url, PHP_URL_HOST) ?: ''));
        $page_host     = strtolower((string) $GLOBALS['_url_parts']['host']);
        if ($resolved_host !== '' && $page_host !== '') {
            $strip_www = function ($h) { return preg_replace('/^www\./', '', $h); };
            if ($strip_www($resolved_host) !== $strip_www($page_host)) {
                return 'about:blank';
            }
        }
    }

    // Drop tracking query parameters from links rendered in proxied pages
    $url = strip_tracking_params($url);

    return $proxify ? "{$GLOBALS['_script_url']}?{$GLOBALS['_config']['url_var_name']}=" . encode_url($url) . $fragment : $url;
}

function proxify_inline_css(string $css): string
{
    return preg_replace_callback(
        '~url\s*\(\s*((?:"[^"]*"|\'[^\']*\'|[^)]*))\s*\)~i',
        fn($m) => 'url(' . proxify_css_url(trim($m[1])) . ')',
        $css
    ) ?? $css;
}

function proxify_css(string $css): string
{
    $css = proxify_inline_css($css);
    return preg_replace_callback(
        '~(@import\s+)(["\'])([^"\']*)\2([^;]*)(;|$)~i',
        fn($m) => $m[1] . $m[2] . complete_url($m[3]) . $m[2] . $m[4] . $m[5],
        $css
    ) ?? $css;
}

function proxify_css_url(string $url): string
{
    $url   = trim($url);
    $delim = strpos($url, '"') === 0 ? '"' : (strpos($url, "'") === 0 ? "'" : '');
    if ($delim !== '') {
        $url = trim($url, $delim);
    }
    if (substr($url, 0, 5) == 'data:' ||
        substr($url, 0, 11) == 'javascript:' ||
        substr($url, 0, 6) == 'about:' ||
        substr($url, 0, 7) == 'magnet:' ||
        substr($url, 0, 4) == 'tel:' ||
        substr($url, 0, 8) == 'ios-app:' ||
        substr($url, 0, 12) == 'android-app:' ||
        substr($url, 0, 7) == 'mailto:' ||
        substr($url, 0, 6) == 'rms://') {
        return $delim . $url . $delim;
    }

    return $delim . preg_replace('#([\(\),\s\'"\\\])#', '\\$1', complete_url(trim(preg_replace('#\\\(.)#', '$1', $url)))) . $delim;
}

function encode_url(string $url): string
{
    global $_flags;

    // Encrypted mode produces a base64-url token already safe for the address
    // bar; skip the surrounding rawurlencode so the cipherblob isn't double
    // encoded.
    if (!empty($_flags['encrypt_url'])) {
        return phproxy_encrypt_url($url);
    }
    if ($_flags['rotate13']) {
        $url = str_rot13($url);
    } elseif ($_flags['base64_encode']) {
        $url = base64_encode($url);
    }

    return rawurlencode($url);
}

function decode_url(string $url): string
{
    global $_flags;

    if (!empty($_flags['encrypt_url'])) {
        $plain = phproxy_decrypt_url($url);
        // Null = seed rotated / tampered / malformed — surface as an empty
        // URL so the dispatcher renders the entry form instead of trying to
        // proxy garbage.
        return $plain === null ? '' : str_replace(['&amp;', '&#38;'], '&', $plain);
    }

    $url = rawurldecode($url);
    if ($_flags['rotate13']) {
        $url = str_rot13($url);
    } elseif ($_flags['base64_encode']) {
        $url = base64_decode($url);
    }

    return str_replace(['&amp;', '&#38;'], '&', $url);
}

// Settings and upstream credentials belong to the private server session.
function phproxy_setting_cookie(string $name, string $value, int $expires = 0): void
{
    setcookie($name, $value, ['expires' => $expires, 'path' => '/', 'secure' => phproxy_is_https(),
        'httponly' => true, 'samesite' => 'Lax']);
    if ($expires !== 0 && $expires < time()) unset($_COOKIE[$name]);
    else $_COOKIE[$name] = $value;
}

function phproxy_custom_header_allowed(string $name, string $value): bool
{
    return strlen($name) <= 128 && strlen($value) <= 8192
        && preg_match('/^[A-Za-z0-9-]+$/D', $name)
        && !preg_match('/[\x00-\x1f\x7f]/', $value)
        && !in_array(strtolower($name), ['host', 'connection', 'content-length', 'transfer-encoding',
            'cookie', 'expect', 'upgrade', 'trailer', 'te', 'proxy-authorization'], true);
}

// Retire v1.3 client-side credentials; they are intentionally not imported.
foreach (phproxy_raw_cookies() as $_old_name => $_old_value) {
    $_decoded_name = rawurldecode(rawurldecode($_old_name));
    if ($_old_name === 'phproxy-seed' || $_old_name === 'userAgent'
        || str_starts_with($_old_name, 'hdr_') || str_starts_with($_decoded_name, 'COOKIE;')
        || str_starts_with($_decoded_name, 'AUTH;')) {
        if (preg_match('/^[A-Za-z0-9_%.-]+$/D', $_old_name)) {
            foreach (['', $_http_host] as $_old_domain) {
                $options = ['expires' => 1, 'path' => '/', 'secure' => phproxy_is_https(), 'httponly' => true, 'samesite' => 'Lax'];
                if ($_old_domain !== '' && !filter_var($_old_domain, FILTER_VALIDATE_IP)) $options['domain'] = $_old_domain;
                setrawcookie($_old_name, '', $options);
            }
        }
    }
}

if (isset($_GET['action']) && $_SERVER['REQUEST_METHOD'] === 'POST') {
    phproxy_require_csrf();
    $_action = is_string($_GET['action']) ? $_GET['action'] : '';
    $_redirect_tab = '';
    phproxy_state_open();
    switch ($_action) {
        case 'clear-network':
            $_SESSION['phproxy_network'] = [];
            $_SESSION['phproxy_trace'] = [];
            $_redirect_tab = 'network';
            break;
        case 'clear-cookies':
            $_SESSION['phproxy_jar'] = [];
            $_SESSION['phproxy_auth'] = [];
            $_redirect_tab = 'cookies';
            break;
        case 'delete-cookie':
            unset($_SESSION['phproxy_jar'][(string) ($_POST['name'] ?? '')]);
            $_redirect_tab = 'cookies';
            break;
        case 'add-cookie':
        case 'edit-cookie':
            $_n = trim((string) ($_POST['cookieName'] ?? ''));
            $_v = (string) ($_POST['cookieValue'] ?? '');
            $_d = strtolower(ltrim(trim((string) ($_POST['cookieDomain'] ?? '')), '.'));
            $_p = (string) ($_POST['cookiePath'] ?? '/');
            $_days = max(0, min(3650, (int) ($_POST['cookieExpires'] ?? 0)));
            $_valid_host = filter_var($_d, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) || filter_var($_d, FILTER_VALIDATE_IP);
            if ($_valid_host && !str_contains($_v, ';') && !str_contains($_p, ';')
                && !preg_match('/[\x00-\x20\x7f]/', $_d . $_p) && str_starts_with($_p, '/')) {
                $_manual_url = 'https://' . (str_contains($_d, ':') ? '[' . $_d . ']' : $_d) . $_p;
                $_line = $_n . '=' . $_v . '; Path=' . $_p
                    . (!empty($_POST['cookieSecure']) ? '; Secure' : '')
                    . (!empty($_POST['cookieHttpOnly']) ? '; HttpOnly' : '')
                    . ($_days > 0 ? '; Max-Age=' . ($_days * 86400) : '');
                $_manual_cookie = phproxy_cookie_parse($_line, $_manual_url, false);
                if ($_manual_cookie !== null) {
                    $_ss = ucfirst(strtolower((string) ($_POST['cookieSameSite'] ?? '')));
                    $_manual_cookie['samesite'] = in_array($_ss, ['Lax', 'Strict', 'None'], true) ? $_ss : '';
                    if ($_action === 'edit-cookie') unset($_SESSION['phproxy_jar'][(string) ($_POST['name'] ?? '')]);
                    $_SESSION['phproxy_jar'][phproxy_cookie_id($_manual_cookie)] = $_manual_cookie;
                    $_SESSION['phproxy_jar'] = array_slice($_SESSION['phproxy_jar'], -100, null, true);
                }
            }
            $_redirect_tab = 'cookies';
            break;
        case 'add-header':
        case 'edit-header':
            $_name = trim((string) ($_POST[$_action === 'add-header' ? 'headerAddName' : 'headerName'] ?? ''));
            $_value = (string) ($_POST[$_action === 'add-header' ? 'headerAddValue' : 'headerValue'] ?? '');
            $_origin = phproxy_request_origin((string) ($_POST['headerOrigin'] ?? ''));
            if ($_origin !== '' && phproxy_custom_header_allowed($_name, $_value)) {
                $_old = strtolower((string) ($_POST['oldName'] ?? $_name));
                foreach (array_keys($_SESSION['phproxy_headers'] ?? []) as $_saved_name) {
                    if (in_array(strtolower($_saved_name), [$_old, strtolower($_name)], true)) unset($_SESSION['phproxy_headers'][$_saved_name]);
                }
                $_SESSION['phproxy_headers'][$_name] = ['value' => $_value, 'origin' => $_origin];
                $_SESSION['phproxy_headers'] = array_slice($_SESSION['phproxy_headers'], -40, null, true);
            }
            $_redirect_tab = 'headers';
            break;
        case 'delete-header':
            unset($_SESSION['phproxy_headers'][(string) ($_POST['name'] ?? '')]);
            $_redirect_tab = 'headers';
            break;
        case 'set-ua':
            $_ua = (string) ($_POST['userAgent'] ?? '');
            if (strlen($_ua) <= 2048 && !preg_match('/[\x00-\x1f\x7f]/', $_ua)) $_SESSION['phproxy_ua'] = $_ua;
            $_redirect_tab = 'headers';
            break;
        case 'toggle-raw':
            phproxy_setting_cookie('phproxy-show-raw', empty($_COOKIE['phproxy-show-raw']) ? '1' : '', time() + 31536000);
            $_redirect_tab = 'cookies';
            break;
        case 'rotate-seed':
            unset($_SESSION['phproxy_seed'], $GLOBALS['_phproxy_seed_cache']);
            $_redirect_tab = 'options';
            break;
        case 'set-seed-ttl':
            phproxy_setting_cookie('phproxy-seed-ttl', (string) max(60, min(604800, (int) ($_POST['seedTtl'] ?? 3600))), time() + 31536000);
            unset($_SESSION['phproxy_seed'], $GLOBALS['_phproxy_seed_cache']);
            $_redirect_tab = 'options';
            break;
        case 'set-seed-bits':
            $_bits = (int) ($_POST['seedBits'] ?? 256);
            phproxy_setting_cookie('phproxy-seed-bits', (string) (in_array($_bits, [128, 192, 256], true) ? $_bits : 256), time() + 31536000);
            unset($_SESSION['phproxy_seed'], $GLOBALS['_phproxy_seed_cache']);
            $_redirect_tab = 'options';
            break;
    }
    phproxy_state_close();
    // Return to the trusted browsing shell when its signed management form
    // supplied a local context. Always re-encode after seed changes.
    $_return_target = phproxy_browsing_return(
        is_string($_POST['return_to'] ?? null) ? $_POST['return_to'] : '',
        is_string($_POST['return_url'] ?? null) ? $_POST['return_url'] : '',
        $_redirect_tab
    );
    header('Location: ' . ($_return_target ?? ($_script_url . ($_redirect_tab !== '' ? '?tab=' . $_redirect_tab : ''))), true, 303);
    exit;
}

if (isset($_POST['action']) && $_POST['action'] === 'submit' && isset($_POST['userAgent']) && !isset($_GET['action'])) {
    phproxy_require_csrf();
    $_ua_legacy = (string) $_POST['userAgent'];
    if (strlen($_ua_legacy) <= 2048 && !preg_match('/[\x00-\x1f\x7f]/', $_ua_legacy)) {
        phproxy_state_open();
        $_SESSION['phproxy_ua'] = $_ua_legacy;
        phproxy_state_close();
    }
    header('Location: ' . $_script_url);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST[$_config['url_var_name']]) && !isset($_GET[$_config['url_var_name']])) {
    phproxy_require_csrf();
}

// URL encoding radio (Options tab) → maps a single radio value back onto
// the two underlying mutually-exclusive flag checkboxes.
//
if (isset($_POST[$_config['flags_var_name']]['__url_enc']))
{
    $_enc = $_POST[$_config['flags_var_name']]['__url_enc'];
    unset($_POST[$_config['flags_var_name']]['rotate13']);
    unset($_POST[$_config['flags_var_name']]['base64_encode']);
    unset($_POST[$_config['flags_var_name']]['encrypt_url']);
    if ($_enc === 'rot13')     $_POST[$_config['flags_var_name']]['rotate13']      = 1;
    if ($_enc === 'base64')    $_POST[$_config['flags_var_name']]['base64_encode'] = 1;
    if ($_enc === 'encrypted') $_POST[$_config['flags_var_name']]['encrypt_url']   = 1;
    unset($_POST[$_config['flags_var_name']]['__url_enc']);
}

//
// SET FLAGS
//

if (isset($_POST[$_config['url_var_name']]) && !isset($_GET[$_config['url_var_name']]) && isset($_POST[$_config['flags_var_name']]))
{
    foreach ($_flags as $flag_name => $flag_value)
    {
        $_iflags .= isset($_POST[$_config['flags_var_name']][$flag_name]) ? (string)(int)(bool)$_POST[$_config['flags_var_name']][$flag_name] : ($_frozen_flags[$flag_name] ? $flag_value : '0');

    }

    $_iflags = base_convert(($_iflags != '' ? $_iflags : '0'), 2, 16);
    phproxy_setting_cookie('flags', $_iflags, time() + 2419200);
}
else if (isset($_COOKIE['flags']) && is_string($_COOKIE['flags']) && preg_match('/^[a-f0-9]{1,5}$/iD', $_COOKIE['flags']))
{
    $_iflags = $_COOKIE['flags'];
}

if ($_iflags !== '')
{
    $_iflags = substr(str_pad(base_convert($_iflags, 16, 2), count($_flags), '0', STR_PAD_LEFT), -count($_flags));
    $i = 0;

    foreach ($_flags as $flag_name => $flag_value)
    {
        $_flags[$flag_name] = $_frozen_flags[$flag_name] ? $flag_value : (int)(bool)$_iflags[$i];
        $i++;
    }
}

//
// COMPRESS OUTPUT IF INSTRUCTED
//

if ($_config['compress_output'] && $_system['gzip'])
{
    ob_start('ob_gzhandler');
}

//
// STRIP SLASHES FROM GPC IF NECESSARY
//

if ($_system['stripslashes'])
{
    function _stripslashes(mixed $value): mixed
    {
        return is_array($value) ? array_map('_stripslashes', $value) : (is_string($value) ? stripslashes($value) : $value);
    }

    $_GET    = _stripslashes($_GET);
    $_POST   = _stripslashes($_POST);
    $_COOKIE = _stripslashes($_COOKIE);
}

//
// PATH-STYLE ROUTING (#24): phproxy.example/https://target/path
// Apache collapses consecutive slashes in URL paths, so we accept
// "http:/target" (single slash) and restore "http://target".
//

// Browsing-bar navigation has its own token: upstream HTML never receives
// the CSRF token that authorizes cookie, credential or settings changes.
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['phproxy_browse_url'])
    && !isset($_GET[$_config['url_var_name']])) {
    if (!is_string($_POST['phproxy_navigation_token'] ?? null)
        || !hash_equals(phproxy_navigation_token(), $_POST['phproxy_navigation_token'])) {
        http_response_code(403);
        header('Content-Type: text/plain; charset=utf-8');
        exit('Navigation expired. Open PHProxy home and try again.');
    }
    $_browse_url = is_string($_POST['phproxy_browse_url']) ? trim($_POST['phproxy_browse_url']) : '';
    header('Location: ' . $_script_url . ($_browse_url !== '' ? '?' . $_config['url_var_name'] . '=' . encode_url($_browse_url) : ''), true, 303);
    exit;
}

if (!isset($_POST[$_config['url_var_name']])
    && !isset($_GET[$_config['url_var_name']])
    && !isset($_GET[$_config['get_form_name']])
    && !empty($_SERVER['PATH_INFO'])
    && preg_match('#^/(https?):/+(.*)$#i', $_SERVER['PATH_INFO'], $_path_match))
{
    $_path_target = $_path_match[1] . '://' . $_path_match[2];
    if (!empty($_SERVER['QUERY_STRING'])) {
        $_path_target .= (strpos($_path_target, '?') === false ? '?' : '&') . $_SERVER['QUERY_STRING'];
    }
    $_GET[$_config['url_var_name']] = encode_url($_path_target);
}

//
// FIGURE OUT WHAT TO DO (POST URL-form submit, GET form request, regular request, basic auth, cookie manager, show URL-form)
//

if (isset($_POST[$_config['url_var_name']]) && !isset($_GET[$_config['url_var_name']]))
{
    $_submitted_url = trim((string) $_POST[$_config['url_var_name']]);
    $_panel_hint = ($_POST['phproxy_panel_context'] ?? '') === '1' && $_submitted_url !== '' ? '&panel=options' : '';
    header('Location: ' . $_script_url . ($_submitted_url !== '' ? '?' . $_config['url_var_name'] . '=' . encode_url($_submitted_url) : '') . $_panel_hint, true, 303);
    exit(0);
}

if (isset($_GET[$_config['get_form_name']]))
{
    $_url  = decode_url($_GET[$_config['get_form_name']]);
    $qstr = strpos($_url, '?') !== false ? (strpos($_url, '?') === strlen($_url)-1 ? '' : '&') : '?';
    $arr  = explode('&', $_SERVER['QUERY_STRING']);

    if (preg_match('#^\Q' . $_config['get_form_name'] . '\E#', $arr[0]))
    {
        array_shift($arr);
    }

    $_url .= $qstr . implode('&', $arr);
}
else if (isset($_GET[$_config['url_var_name']]))
{
    $_url = decode_url($_GET[$_config['url_var_name']]);
}
else
{
    show_report(['which' => 'index', 'category' => 'entry_form']);
}

// Clean tracking params from the user-typed/incoming URL too, before we visit it
$_url = strip_tracking_params($_url);

if (isset($_GET[$_config['url_var_name']], $_POST[$_config['basic_auth_var_name']], $_POST['username'], $_POST['password']))
{
    phproxy_require_csrf();
    $_request_method    = 'GET';
    $_basic_auth_realm  = base64_decode($_POST[$_config['basic_auth_var_name']]);
    $_basic_auth_header = base64_encode($_POST['username'] . ':' . $_POST['password']);
}

//
// SET URL — the shared parser and transport own destination validation.
//
if (strpos($_url, '://') === false) $_url = 'http://' . $_url;
try {
    $_target = phproxy_parse_http_url($_url);
    $_url = $_target['scheme'] . '://' . $_target['authority'] . $_target['path'];
    if (!url_parse($_url, $_url_parts)) throw new InvalidArgumentException('Invalid URL');
    $_base = $_url_parts;
} catch (Throwable $e) {
    show_report(['which' => 'index', 'category' => 'error', 'group' => 'url', 'type' => 'external', 'error' => 2]);
}

//
// HOTLINKING PREVENTION
//

if (!$_config['allow_hotlinking'] && isset($_SERVER['HTTP_REFERER']))
{
    $_hotlink_domains[] = $_http_host;
    $is_hotlinking      = true;

    foreach ($_hotlink_domains as $host)
    {
        if (preg_match('#^https?\:\/\/(www)?\Q' . $host  . '\E(\/|\:|$)#i', trim((string) $_SERVER['HTTP_REFERER'])))
        {
            $is_hotlinking = false;
            break;
        }
    }

    if ($is_hotlinking)
    {
        switch ($_config['upon_hotlink'])
        {
            case 1:
                show_report(['which' => 'index', 'category' => 'error', 'group' => 'resource', 'type' => 'hotlinking']);
                break;
            case 2:
                header('HTTP/1.0 404 Not Found');
                exit(0);
            default:
                header('Location: ' . $_config['upon_hotlink']);
                exit(0);
        }
    }
}

/**
 * Build a bounded browser form upload. File bodies are never read beyond
 * the common transport's 2 MiB request limit.
 */
function phproxy_browser_body(array $post, array $files, string $contentType, string $raw = ''): array
{
    $limit = 2 * 1024 * 1024;
    if ($files === []) {
        if (str_starts_with(strtolower($contentType), 'application/x-www-form-urlencoded')
            || str_starts_with(strtolower($contentType), 'multipart/form-data') || $contentType === '') {
            $body = http_build_query($post);
            $contentType = 'application/x-www-form-urlencoded';
        } else {
            $body = $raw;
        }
        if (strlen($body) > $limit) throw new RuntimeException('Request body exceeds 2 MiB.');
        return ['body' => $body, 'content_type' => $contentType];
    }
    $boundary = '----phproxy' . bin2hex(random_bytes(18));
    $quote = static fn(string $s): string => str_replace(["\\", '"', "\r", "\n"], ['\\\\', '%22', '', ''], $s);
    $body = '';
    foreach (set_post_vars($post) as $name => $value) {
        $body .= '--' . $boundary . "\r\nContent-Disposition: form-data; name=\"" . $quote(urldecode($name)) . "\"\r\n\r\n" . urldecode($value) . "\r\n";
        if (strlen($body) > $limit) throw new RuntimeException('Request body exceeds 2 MiB.');
    }
    foreach (set_post_files($files) as $name => $file) {
        $tmp = (string) ($file['tmp_name'] ?? '');
        if ($tmp === '' || !is_uploaded_file($tmp)) continue;
        $remaining = $limit - strlen($body);
        if ($remaining <= 0 || filesize($tmp) > $remaining) throw new RuntimeException('Request body exceeds 2 MiB.');
        $type = (string) ($file['type'] ?? '');
        if (!preg_match('~^[A-Za-z0-9.+-]+/[A-Za-z0-9.+-]+$~D', $type)) $type = 'application/octet-stream';
        $body .= '--' . $boundary . "\r\nContent-Disposition: form-data; name=\"" . $quote(urldecode($name))
            . '"; filename="' . $quote((string) ($file['name'] ?? 'upload')) . "\"\r\nContent-Type: " . $type . "\r\n\r\n";
        $data = file_get_contents($tmp, false, null, 0, $remaining + 1);
        if ($data === false) throw new RuntimeException('Unable to read uploaded file.');
        $body .= $data . "\r\n";
        if (strlen($body) > $limit) throw new RuntimeException('Request body exceeds 2 MiB.');
    }
    $body .= '--' . $boundary . "--\r\n";
    if (strlen($body) > $limit) throw new RuntimeException('Request body exceeds 2 MiB.');
    return ['body' => $body, 'content_type' => 'multipart/form-data; boundary=' . $boundary];
}

function phproxy_trace_store(string $url, string $method, array $headers, array $response): void
{
    $pairs = [];
    foreach (array_slice($headers, 0, 40, true) as $name => $value) {
        $sensitive = preg_match('/authorization|cookie|token|secret|key/i', $name);
        $pairs[] = [substr($name, 0, 128), $sensitive ? '[redacted]' : substr((string) $value, 0, 1024)];
    }
    $responsePairs = [];
    foreach (array_slice($response['header_lines'] ?? [], 0, 40) as $entry) {
        $sensitive = preg_match('/authorization|cookie|token|secret|key/i', $entry['name']);
        $responsePairs[] = [substr($entry['name'], 0, 128), $sensitive ? '[redacted]' : substr($entry['value'], 0, 1024)];
    }
    $path = parse_url($url, PHP_URL_PATH) ?: '/';
    phproxy_state_open();
    $_SESSION['phproxy_trace'] = [
        'url' => substr($url, 0, 2048), 'method' => $method,
        'request_line' => $method . ' ' . substr($path, 0, 2048) . ' HTTP/1.1',
        'request_pairs' => $pairs, 'response_pairs' => $responsePairs,
    ];
    phproxy_state_close();
}

// Browser requests use exactly the same destination policy, HTTP framing,
// certificate verification, byte limits and deadline as the JSON API.
$_state = phproxy_state_snapshot();
$_origin = phproxy_request_origin($_url);
$_out_headers = [
    'user-agent' => (string) ($_user_agent ?? ''),
    'accept' => (string) ($_SERVER['HTTP_ACCEPT'] ?? '*/*'),
];
if ($_flags['send_dnt']) $_out_headers['dnt'] = '1';
if ($_flags['send_gpc']) $_out_headers['sec-gpc'] = '1';
if ($_flags['show_referer'] && isset($_SERVER['HTTP_REFERER'])) {
    $_referer_prefix = $_script_url . '?' . $_config['url_var_name'] . '=';
    if (str_starts_with($_SERVER['HTTP_REFERER'], $_referer_prefix)) {
        $_referer_token = explode('&', substr($_SERVER['HTTP_REFERER'], strlen($_referer_prefix)), 2)[0];
        $_referer = decode_url($_referer_token);
        if ($_referer !== '' && !preg_match('/[\x00-\x1f\x7f]/', $_referer)) {
            // Do not send another site's sensitive path/query across origins.
            $_out_headers['referer'] = phproxy_request_origin($_referer) === $_origin
                ? $_referer : (phproxy_request_origin($_referer) . '/');
        }
    }
}
foreach ($_state['phproxy_headers'] ?? [] as $_name => $_entry) {
    if ($_entry['origin'] === $_origin && phproxy_custom_header_allowed($_name, $_entry['value'])) {
        $_out_headers[strtolower($_name)] = $_entry['value'];
    }
}
$_cookie = phproxy_cookie_header($_state['phproxy_jar'] ?? [], $_url, (bool) $_flags['accept_cookies']);
if ($_cookie !== '') $_out_headers['cookie'] = $_cookie;
if ($_basic_auth_header === '') {
    foreach ($_state['phproxy_auth'][$_origin] ?? [] as $_realm => $_saved_auth) {
        if (phproxy_cookie_path_matches($_url_parts['path'], $_saved_auth['path'])) {
            $_basic_auth_realm = $_realm;
            $_basic_auth_header = $_saved_auth['header'];
            break;
        }
    }
}
if ($_basic_auth_header !== '') $_out_headers['authorization'] = 'Basic ' . $_basic_auth_header;

$_post_body = '';
try {
    if (in_array($_request_method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
        if ((int) ($_SERVER['CONTENT_LENGTH'] ?? 0) > 2 * 1024 * 1024) {
            throw new RuntimeException('Request body exceeds 2 MiB.');
        }
        $_body_content_type = (string) ($_SERVER['CONTENT_TYPE'] ?? '');
        $_raw_body = '';
        if ($_FILES === [] && !str_starts_with(strtolower($_body_content_type), 'application/x-www-form-urlencoded')
            && !str_starts_with(strtolower($_body_content_type), 'multipart/form-data')) {
            $_raw_body = (string) file_get_contents('php://input', false, null, 0, 2 * 1024 * 1024 + 1);
        }
        $_built_body = phproxy_browser_body($_POST, $_FILES, $_body_content_type, $_raw_body);
        $_post_body = $_built_body['body'];
        $_out_headers['content-type'] = $_built_body['content_type'];
    }
} catch (Throwable $e) {
    http_response_code(413);
    header('Content-Type: text/plain; charset=utf-8');
    exit('The request body could not be forwarded. The maximum size is 2 MiB.');
}
$_net_start = microtime(true);
phproxy_state_close();
$_result = phproxy_api_fetch([
    'url' => $_url, 'method' => $_request_method, 'headers' => $_out_headers,
    'body' => $_post_body, 'follow_redirects' => false, 'timeout' => 30,
    'max_response_bytes' => $_config['max_file_size'] > 0 ? $_config['max_file_size'] : 8388608,
]);
$_net_end = microtime(true);
$_net_ttfb = isset($_result['ttfb_ms']) ? $_net_start + $_result['ttfb_ms'] / 1000 : null;
if (empty($_result['ok'])) {
    http_response_code((int) ($_result['http_status'] ?? 502));
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store');
    exit('Unable to fetch the destination: ' . ($_result['error'] ?? 'upstream request failed'));
}

$_response_code = (int) $_result['status'];
$_response_body = $_result['body_raw'];
$_response_keys = ['status' => 'HTTP/1.1 ' . $_response_code . ' ' . $_result['status_text']];
$_response_headers = ['status' => []];
foreach ($_result['header_lines'] as $_entry) {
    $_lower_name = strtolower($_entry['name']);
    $_response_keys[$_lower_name] = $_entry['name'];
    $_response_headers[$_lower_name][] = $_entry['value'];
}
$_content_type = strtolower(trim(explode(';', $_result['headers']['content-type'] ?? 'application/octet-stream', 2)[0]));
$_content_disp = $_result['headers']['content-disposition'] ?? '';
phproxy_store_cookies($_result['set_cookie_headers'], $_url, (bool) $_flags['accept_cookies'], (bool) $_flags['session_cookies']);
phproxy_trace_store($_url, $_request_method, $_out_headers, $_result);
phproxy_net_log($_url, $_request_method, $_response_code, $_content_type, strlen($_response_body), $_net_start, $_net_ttfb, $_net_end);

if ($_response_code === 401 && isset($_result['headers']['www-authenticate'])
    && preg_match('/basic\s+(?:realm="([^"]*)")?/i', $_result['headers']['www-authenticate'], $_challenge)) {
    $_basic_auth_realm = substr($_challenge[1] ?? '', 0, 256);
    show_report(['which' => 'index', 'category' => 'auth', 'realm' => $_basic_auth_realm]);
}
if ($_basic_auth_header !== '' && $_response_code < 400) {
    phproxy_state_open();
    $_SESSION['phproxy_auth'][$_origin][$_basic_auth_realm] = [
        'header' => $_basic_auth_header,
        'path' => ($_url_parts['dir'] ?: '') . '/',
    ];
    $_SESSION['phproxy_auth'][$_origin] = array_slice($_SESSION['phproxy_auth'][$_origin], -10, null, true);
    $_SESSION['phproxy_auth'] = array_slice($_SESSION['phproxy_auth'], -20, null, true);
    phproxy_state_close();
}
foreach (['location', 'uri', 'content-location'] as $_location_header) {
    if (isset($_response_headers[$_location_header][0])) {
        $_response_headers[$_location_header][0] = complete_url($_response_headers[$_location_header][0]);
    }
}
unset($_response_headers['www-authenticate'], $_response_keys['www-authenticate']);

// Unknown content encodings cannot be rewritten safely.
if (!isset($_proxify[$_content_type]) || isset($_result['headers']['content-encoding'])) {
    $_response_headers['content-length'] = [(string) strlen($_response_body)];
    $_response_keys['content-length'] = 'Content-Length';
    header(array_shift($_response_keys));
    array_shift($_response_headers);
    foreach ($_response_headers as $_name => $_values) {
        foreach ($_values as $_value) header($_response_keys[$_name] . ': ' . $_value, false);
    }
    phproxy_untrusted_response_headers(empty($_flags['remove_scripts']));
    if ($_request_method !== 'HEAD') echo $_response_body;
    exit;
}

//
// MODIFY AND DUMP RESOURCE
//

$_browsing_shell = false;
if ($_content_type === 'text/css') {
    $_response_body = proxify_css($_response_body);
} else {
    $_browsing_shell = $_flags['include_form'] && !isset($_GET['nf'])
        && ($_SERVER['HTTP_SEC_FETCH_DEST'] ?? '') !== 'iframe';
    if ($_browsing_shell) {
        $_response_body = phproxy_html_utf8($_response_body, $_result['headers']['content-type'] ?? '');
    }
    $_response_body = phproxy_rewrite_html($_response_body, (bool) $_browsing_shell);
    if ($_browsing_shell) {
        $_current_proxy_url = $_script_url . '?' . $_config['url_var_name'] . '=' . encode_url($_url);
        $_response_body = phproxy_browsing_bar($_response_body, $_script_url, $_url,
            phproxy_navigation_token(), phproxy_browsing_panel($_current_proxy_url, $_url),
            empty($_flags['remove_scripts']));
    }
}
$_response_headers['content-length'] = [(string) strlen($_response_body)];
$_response_keys['content-length'] = 'Content-Length';
header(array_shift($_response_keys));
array_shift($_response_headers);
foreach ($_response_headers as $name => $values) {
    foreach ((array) $values as $value) header($_response_keys[$name] . ': ' . $value, false);
}
if ($_browsing_shell) phproxy_browsing_shell_headers();
else phproxy_untrusted_response_headers(empty($_flags['remove_scripts']));
echo $_response_body;

/** Rebuild each matched tag once, without rescanning the document per tag. */
function phproxy_rewrite_html(string $_response_body, bool $framed = false): string
{
    global $_flags, $_base, $_url_parts, $_config, $_url, $_script_url, $_iflags;
    if ($_flags['strip_title'])
    {
        $_response_body = preg_replace('#(<\s*title[^>]*>)(.*?)(<\s*/title[^>]*>)#is', '$1$3', $_response_body);
    }
    if ($_flags['remove_scripts'])
    {
        $_response_body = preg_replace('#<\s*script[^>]*?><\s*\/\s*script\s*>#si', '', $_response_body);
        $_response_body = preg_replace('#<\s*script[^>]*?>(.+?(?=<\/script>))?<\s*\/\s*script\s*>#si', '', $_response_body);
        $_response_body = preg_replace("#([\s])?(onload|onsubmit|onclick|onmouseover|onmouseout|onkeydown|onload)=\"([^\"]*)\"([\s])?#i", ' ', $_response_body);
        $_response_body = preg_replace("/([\s])?href=\"javascript:.+?(?=\")\"([\s])?/", ' ', $_response_body);
        $_response_body = preg_replace('#<noscript>(.*?)</noscript>#si', "$1", $_response_body);
    }
    if (!$_flags['show_images'])
    {
        $_response_body = preg_replace('#<(img|image)[^>]*?>#si', '', $_response_body);
    }
    if ($_flags['strip_iframes'])
    {
        $_response_body = preg_replace('#<\s*iframe\b[^>]*>.*?<\s*/\s*iframe\s*>#si', '', $_response_body);
        $_response_body = preg_replace('#<\s*iframe\b[^>]*/?>#si', '', $_response_body);
    }
    if ($_flags['block_media'])
    {
        $_response_body = preg_replace('#<\s*(video|audio)\b[^>]*>.*?<\s*/\s*\1\s*>#si', '', $_response_body);
        $_response_body = preg_replace('#<\s*(video|audio|source|track)\b[^>]*/?>#si', '', $_response_body);
    }
    if ($_flags['block_fonts'])
    {
        // <link> tags pointing at known font CDNs, or declaring as="font"
        $_response_body = preg_replace('#<\s*link\b[^>]*\b(?:fonts\.googleapis\.com|fonts\.gstatic\.com|use\.typekit\.net|use\.fontawesome\.com|fonts\.cdnfonts\.com|fonts\.bunny\.net|fonts\.adobe\.com)[^>]*/?>#si', '', $_response_body);
        $_response_body = preg_replace('#<\s*link\b[^>]*\bas\s*=\s*["\']?font["\']?[^>]*/?>#si', '', $_response_body);
        // @font-face blocks inside any inline CSS
        $_response_body = preg_replace('#@font-face\s*\{[^}]*\}#si', '', $_response_body);
    }

    //
    // PROXIFY HTML RESOURCE
    //

    $tags = array
    (
        'a'          => ['href', 'data-inbound-url', 'data-href-url'],
        'img'        => ['src', 'longdesc', 'srcset', 'data-src'],
        'image'      => ['src', 'longdesc'],
        'body'       => ['background'],
        'base'       => ['href'],
        'frame'      => ['src', 'longdesc'],
        'iframe'     => ['src', 'longdesc'],
        'head'       => ['profile'],
        'layer'      => ['src'],
        'input'      => ['src', 'usemap'],
        'form'       => ['action'],
        'area'       => ['href'],
        'link'       => ['href', 'src', 'urn', 'integrity'],
        'meta'       => ['content'],
        'param'      => ['value'],
        'applet'     => ['codebase', 'code', 'object', 'archive'],
        'object'     => ['usermap', 'codebase', 'classid', 'archive', 'data'],
        'script'     => ['src'],
        'select'     => ['src'],
        'hr'         => ['src'],
        'table'      => ['background'],
        'tr'         => ['background'],
        'th'         => ['background'],
        'td'         => ['background'],
        'bgsound'    => ['src'],
        'blockquote' => ['cite'],
        'del'        => ['cite'],
        'embed'      => ['src'],
        'fig'        => ['src', 'imagemap'],
        'ilayer'     => ['src'],
        'ins'        => ['cite'],
        'note'       => ['src'],
        'overlay'    => ['src', 'imagemap'],
        'q'          => ['cite'],
        'ul'         => ['src'],
        'use'        => ['xlink:href'],
        'source'     => ['srcset'],
    );

    $_response_body = preg_replace_callback(
        '#(<\s*style[^>]*>)(.*?)(<\s*/\s*style[^>]*>)#is',
        static fn(array $match): string => $match[1] . proxify_css($match[2]) . $match[3],
        $_response_body
    ) ?? $_response_body;

    $rewritten = preg_replace_callback("#<\s*([a-zA-Z0-9\?-]+)(((?:\s+[a-zA-Z0-9:\-\/]+(?:\s*=\s*(?:(?:\"[^\"]*\")|(?:'[^']*')|[^>\s]+))?)*)\s*(>|\/>))#s", static function (array $match) use ($tags, $framed): string {
        global $_flags, $_base, $_url_parts, $_config, $_url, $_script_url, $_iflags;
        $tag = strtolower($match[1]);
        if (!preg_match_all("#([a-zA-Z0-9:\-\/]+)\s*(?:=\s*(?:\"([^\"]*)\"?|'([^']*)'?|([^'\"\s>]*)))?#s", $match[2], $m, PREG_SET_ORDER))
        {
            if (!$framed || $tag !== 'form') return $match[0];
        }

        $rebuild    = false;
        $drop_tag   = false;
        $extra_html = $temp = '';
        $attrs      = [];

        for ($j = 0, $count_j = count($m); $j < $count_j; $attrs[strtolower($m[$j][1])] = (isset($m[$j][4]) ? $m[$j][4] : (isset($m[$j][3]) ? $m[$j][3] : (isset($m[$j][2]) ? $m[$j][2] : false))), ++$j);
        $original_href = isset($attrs['href']) ? html_entity_decode(trim((string) $attrs['href']), ENT_QUOTES | ENT_HTML5, 'UTF-8') : '';

        if (isset($attrs['style']))
        {
            $rebuild = true;
            $attrs['style'] = proxify_inline_css($attrs['style']);
        }

        $tag = strtolower($match[1]);

        if (isset($tags[$tag]))
        {
            switch ($tag)
            {
                case 'a':
                    if (isset($attrs['href']))
                    {
                        $rebuild = true;
                        $attrs['href'] = complete_url($attrs['href']);
                    }
                    if (isset($attrs['data-inbound-url']))
                    {
                        $rebuild = true;
                        $attrs['data-inbound-url'] = complete_url($attrs['data-inbound-url']);
                    }
                    if (isset($attrs['data-href-url']))
                    {
                        $rebuild = true;
                        $attrs['data-href-url'] = complete_url($attrs['data-href-url']);
                    }
                    break;
                case 'link':
                    if (isset($attrs['href']))
                    {
                        $rebuild = true;
                        $attrs['href'] = complete_url($attrs['href']);
                    }
                    if (isset($attrs['src']))
                    {
                        $rebuild = true;
                        $attrs['src'] = complete_url($attrs['src']);
                    }
                    if (isset($attrs['urn']))
                    {
                        $rebuild = true;
                        $attrs['urn'] = complete_url($attrs['urn']);
                    }
                    if (isset($attrs['integrity']))
                    {
                        $rebuild = true;
                        $attrs['integrity'] = '';
                    }
                    break;
                case 'img':
                    if (isset($attrs['src']))
                    {
                        $rebuild = true;
                        $attrs['src'] = complete_url($attrs['src']);
                    }
                    if (isset($attrs['longdesc']))
                    {
                        $rebuild = true;
                        $attrs['longdesc'] = complete_url($attrs['longdesc']);
                    }
                    if (isset($attrs['srcset']))
                    {
                        $rebuild = true;
                        $str = preg_replace('/\s+/', ' ', $attrs['srcset']);
                        $final = '';
                        $src_set_data_2 = [];
                        $src_set_data = explode(',', $attrs['srcset']);
                        foreach($src_set_data as $item) {
                            $item = trim($item);
                            $_data_ = explode(' ', $item);
                            $src_set_data_2[] = $_data_;
                        }
                        foreach($src_set_data_2 as $item) {
                            foreach($item as $item_2) {
                                if($item_2 == $item[0]) {
                                    $final .= complete_url($item_2);
                                } else {
                                    $final .= ' '.$item_2;
                                }
                            }
                            $final = trim($final).', ';
                        }
                        $attrs['srcset'] = trim(trim($final), ',');
                        unset($final, $src_set_data_2);
                    }
                    if (isset($attrs['data-srcset']))
                    {
                        $rebuild = true;
                        $str = preg_replace('/\s+/', ' ', $attrs['data-srcset']);
                        $final = '';
                        $src_set_data_2 = [];
                        $src_set_data = explode(',', $attrs['data-srcset']);
                        foreach($src_set_data as $item) {
                            $item = trim($item);
                            $_data_ = explode(' ', $item);
                            $src_set_data_2[] = $_data_;
                        }
                        foreach($src_set_data_2 as $item) {
                            foreach($item as $item_2) {
                                if($item_2 == $item[0]) {
                                    $final .= complete_url($item_2);
                                } else {
                                    $final .= ' '.$item_2;
                                }
                            }
                            $final = trim($final).', ';
                        }
                        $attrs['data-srcset'] = trim(trim($final), ',');
                        unset($final, $src_set_data_2);
                    }
                    if (isset($attrs['data-src']))
                    {
                        $rebuild = true;
                        $attrs['data-src'] = complete_url($attrs['data-src']);
                    }
                    if (isset($attrs['data-cfsrc']))
                    {
                        $rebuild = true;
                        $attrs['data-cfsrc'] = complete_url($attrs['data-cfsrc']);
                    }
                    if (!isset($attrs['src']) && isset($attrs['data-src']))
                    {
                        $rebuild = true;
                        $attrs['src'] = $attrs['data-src'];
                    }
                    break;
                case 'form':
                    if (isset($attrs['action']))
                    {
                        $rebuild = true;

                        if (trim($attrs['action']) === '' || trim($attrs['action'])[0] === '#')
                        {
                            $attrs['action'] = $_url_parts['path'];
                        }
                        if (!isset($attrs['method']) || strtolower(trim($attrs['method'])) === 'get')
                        {
                            $extra_html = '<input type="hidden" name="' . $_config['get_form_name'] . '" value="' . encode_url(complete_url($attrs['action'], false)) . '" />';
                            $attrs['action'] = complete_url($_url);
                            break;
                        }

                        $attrs['action'] = complete_url($attrs['action']);
                    } else {
                        $rebuild = true;
                        if (!isset($attrs['method']) || strtolower(trim($attrs['method'])) === 'get')
                        {
                            $extra_html = '<input type="hidden" name="' . $_config['get_form_name'] . '" value="' . encode_url(complete_url($_url_parts['path'], false)) . '" />';
                            $attrs['action'] = complete_url($_url);
                            break;
                        }
                    }
                    break;
                case 'base':
                    if (isset($attrs['href']))
                    {
                        $rebuild = true;
                        $base_url = complete_url($attrs['href'], false);
                        $base_parts = parse_url($base_url);
                        if (isset($base_parts['scheme'], $base_parts['host'])
                            && in_array(strtolower($base_parts['scheme']), ['http', 'https'], true)) {
                            url_parse($base_url, $_base);
                        }
                        $attrs['href'] = complete_url($base_url);
                    }
                    // All supported references are explicit after rewriting.
                    // Do not let a srcdoc base element change fragment targets.
                    if ($framed) $drop_tag = true;
                    break;
                case 'meta':
                    // The proxy supplies the document policy after rewriting.
                    // Upstream policies refer to its original origin and can
                    // otherwise block rewritten styles and the browsing bar.
                    if (isset($attrs['http-equiv'])
                        && strtolower(trim($attrs['http-equiv'])) === 'content-security-policy') {
                        $drop_tag = true;
                    }
                    if ($_flags['strip_meta'] && isset($attrs['name']))
                    {
                        $drop_tag = true;
                    }
                    if (isset($attrs['http-equiv'], $attrs['content']) && preg_match('#\s*refresh\s*#i', $attrs['http-equiv']))
                    {
                        if (preg_match('#^(\s*[0-9]*\s*;\s*url=)(.*)#i', $attrs['content'], $content))
                        {
                            $rebuild = true;
                            $attrs['content'] =  $content[1] . complete_url(trim($content[2], '"\''));
                        }
                    }
                    break;
                case 'head':
                    if (isset($attrs['profile']))
                    {
                        $rebuild = true;
                        $attrs['profile'] = implode(' ', array_map('complete_url', explode(' ', $attrs['profile'])));
                    }
                    break;
                case 'applet':
                    if (isset($attrs['codebase']))
                    {
                        $rebuild = true;
                        $temp = $_base;
                        url_parse(complete_url(rtrim($attrs['codebase'], '/') . '/', false), $_base);
                        unset($attrs['codebase']);
                    }
                    if (isset($attrs['code']) && strpos($attrs['code'], '/') !== false)
                    {
                        $rebuild = true;
                        $attrs['code'] = complete_url($attrs['code']);
                    }
                    if (isset($attrs['object']))
                    {
                        $rebuild = true;
                        $attrs['object'] = complete_url($attrs['object']);
                    }
                    if (isset($attrs['archive']))
                    {
                        $rebuild = true;
                        $attrs['archive'] = implode(',', array_map('complete_url', preg_split('#\s*,\s*#', $attrs['archive'])));
                    }
                    if (!empty($temp))
                    {
                        $_base = $temp;
                    }
                    break;
                case 'object':
                    if (isset($attrs['usemap']))
                    {
                        $rebuild = true;
                        $attrs['usemap'] = complete_url($attrs['usemap']);
                    }
                    if (isset($attrs['codebase']))
                    {
                        $rebuild = true;
                        $temp = $_base;
                        url_parse(complete_url(rtrim($attrs['codebase'], '/') . '/', false), $_base);
                        unset($attrs['codebase']);
                    }
                    if (isset($attrs['data']))
                    {
                        $rebuild = true;
                        $attrs['data'] = complete_url($attrs['data']);
                    }
                    if (isset($attrs['classid']) && !preg_match('#^clsid:#i', $attrs['classid']))
                    {
                        $rebuild = true;
                        $attrs['classid'] = complete_url($attrs['classid']);
                    }
                    if (isset($attrs['archive']))
                    {
                        $rebuild = true;
                        $attrs['archive'] = implode(' ', array_map('complete_url', explode(' ', $attrs['archive'])));
                    }
                    if (!empty($temp))
                    {
                        $_base = $temp;
                    }
                    break;
                case 'param':
                    if (isset($attrs['valuetype'], $attrs['value']) && strtolower($attrs['valuetype']) == 'ref' && preg_match('#^[\w.+-]+://#', $attrs['value']))
                    {
                        $rebuild = true;
                        $attrs['value'] = complete_url($attrs['value']);
                    }
                    break;
                case 'frame':
                case 'iframe':
                    if (isset($attrs['src']))
                    {
                        $rebuild = true;
                        $attrs['src'] = complete_url($attrs['src']) . '&nf=1';
                    }
                    if (isset($attrs['longdesc']))
                    {
                        $rebuild = true;
                        $attrs['longdesc'] = complete_url($attrs['longdesc']);
                    }
                    break;
                case 'source':
                    if (isset($attrs['srcset']))
                    {
                        $rebuild = true;
                        $str = preg_replace('/\s+/', ' ', $attrs['srcset']);
                        $final = '';
                        $src_set_data_2 = [];
                        $src_set_data = explode(',', $attrs['srcset']);
                        foreach($src_set_data as $item) {
                            $item = trim($item);
                            $_data_ = explode(' ', $item);
                            $src_set_data_2[] = $_data_;
                        }
                        foreach($src_set_data_2 as $item) {
                            foreach($item as $item_2) {
                                if($item_2 == $item[0]) {
                                    $final .= complete_url($item_2);
                                } else {
                                    $final .= ' '.$item_2;
                                }
                            }
                            $final = trim($final).', ';
                        }
                        $attrs['srcset'] = trim(trim($final), ',');
                        unset($final, $src_set_data_2);
                    }
                    break;
                default:
                    foreach ($tags[$tag] as $attr)
                    {
                        if (isset($attrs[$attr]))
                        {
                            $rebuild = true;
                            $attrs[$attr] = complete_url($attrs[$attr]);
                        }
                    }
                    break;
            }
        }

        if ($framed) {
            if (in_array($tag, ['a', 'area'], true) && isset($attrs['href'])) {
                $rebuild = true;
                if (str_starts_with($original_href, '#')) {
                    // A bare fragment in srcdoc otherwise resolves against
                    // the outer proxy URL and can reload it inside the frame.
                    $attrs['href'] = 'about:srcdoc' . $original_href;
                    $attrs['target'] = '_self';
                } else {
                    $attrs['target'] = strtolower(trim((string) ($attrs['target'] ?? ''))) === '_blank' ? '_blank' : '_top';
                }
            } elseif ($tag === 'form') {
                $rebuild = true;
                $attrs['target'] = strtolower(trim((string) ($attrs['target'] ?? ''))) === '_blank' ? '_blank' : '_top';
                // POST forms with no action must not submit to about:srcdoc.
                if (!isset($attrs['action'])) $attrs['action'] = complete_url($_url);
            } elseif (in_array($tag, ['button', 'input'], true) && isset($attrs['formtarget'])) {
                $rebuild = true;
                $attrs['formtarget'] = strtolower(trim((string) $attrs['formtarget'])) === '_blank' ? '_blank' : '_top';
            }
        }

        if (!$rebuild && !$drop_tag) return $match[0];
        if ($drop_tag) return '';
        $new_tag = "<$tag";
        $unpaired_slash = array_key_exists('/', $attrs);
        foreach ($attrs as $name => $value) {
            if ($name === '/') continue;
            $escaped = htmlspecialchars(html_entity_decode((string) $value, ENT_QUOTES | ENT_HTML5, 'UTF-8'), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
            $new_tag .= ' ' . $name . ($value !== false ? '="' . $escaped . '"' : '');
        }
        return $new_tag . ($unpaired_slash ? '/>' : '>') . $extra_html;
    }, $_response_body);
    if ($rewritten === null) throw new RuntimeException('Unable to rewrite upstream document');
    return $rewritten;
}

/** A browsing-only token cannot authorize any management action. */
function phproxy_navigation_token(): string
{
    return hash_hmac('sha256', 'phproxy-browse-url', phproxy_csrf_token());
}

/** Decode the fetched document before placing it in a UTF-8 srcdoc attribute. */
function phproxy_html_utf8(string $html, string $content_type): string
{
    $charset = '';
    // HTML gives a Unicode BOM precedence over HTTP and meta declarations.
    // Strip it before converting so the srcdoc string starts with its markup.
    if (str_starts_with($html, "\xEF\xBB\xBF")) {
        $charset = 'UTF-8';
        $html = substr($html, 3);
    } elseif (str_starts_with($html, "\xFF\xFE")) {
        $charset = 'UTF-16LE';
        $html = substr($html, 2);
    } elseif (str_starts_with($html, "\xFE\xFF")) {
        $charset = 'UTF-16BE';
        $html = substr($html, 2);
    } elseif (preg_match('/charset\s*=\s*["\']?([a-z0-9._-]+)/i', $content_type, $match)) {
        $charset = $match[1];
    } elseif (preg_match('/<meta\b[^>]*charset\s*=\s*["\']?([a-z0-9._-]+)/i', substr($html, 0, 4096), $match)) {
        $charset = $match[1];
    }
    if ($charset === '') $charset = mb_check_encoding($html, 'UTF-8') ? 'UTF-8' : 'Windows-1252';
    try {
        return mb_convert_encoding($html, 'UTF-8', $charset);
    } catch (ValueError $e) {
        return mb_convert_encoding($html, 'UTF-8', 'UTF-8');
    }
}

/** The trusted controls and upstream document occupy separate browsing contexts. */
function phproxy_browsing_bar(string $html, string $settings_url, string $current_url, ?string $navigation_token = null,
    string $panel_html = '', bool $allow_scripts = false): string
{
    $escape = static fn(string $value): string => htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $home = $escape($settings_url);
    $current = $escape($current_url);
    $edit = $escape($settings_url . '?__iv=' . rawurlencode($current_url));
    $panel_css = $escape($settings_url . '?asset=panel.css');
    $netcheck_js = $escape($settings_url . '?asset=netcheck.js');
    $sandbox = 'allow-forms allow-popups allow-popups-to-escape-sandbox allow-top-navigation-by-user-activation'
        . ($allow_scripts ? ' allow-scripts' : ' allow-same-origin');
    $open = isset($_GET['panel']) && in_array($_GET['panel'], ['options', 'cookies', 'headers', 'network', 'response', 'cli', 'ip', 'dns', 'port', 'cert'], true);
    $title = '';
    if (preg_match('#<title\b[^>]*>(.*?)</title>#is', $html, $match)) {
        $title = trim(html_entity_decode(strip_tags($match[1]), ENT_QUOTES | ENT_HTML5, 'UTF-8'));
    }
    $document = '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
        . '<meta name="viewport" content="width=device-width,initial-scale=1">'
        . '<title>' . $escape($title !== '' ? $title : 'PHProxy') . '</title>'
        . '<link rel="stylesheet" href="' . $panel_css . '">'
        . '<script src="' . $netcheck_js . '" defer></script>';
    $document .= <<<'HTML'
<style>
html,body{width:100%;height:100%;margin:0;overflow:hidden;}
body{display:grid;grid-template-rows:auto minmax(0,1fr);height:100vh;height:100dvh;}
#phproxy-navigation{box-sizing:border-box;width:100%;margin:0;padding:8px 12px;background:#fff;color:#172033;border-bottom:1px solid #dbe2ea;font:14px/1.4 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;}
#phproxy-navigation .phproxy-row{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin:0;padding:0;}
#phproxy-navigation .phproxy-url{box-sizing:border-box;flex:1 1 220px;min-width:0;padding:7px 10px;border:1px solid #cbd5e1;border-radius:6px;background:#f8fafc;color:#172033;font:inherit;}
#phproxy-navigation .phproxy-link{display:inline-block;cursor:pointer;padding:7px 6px;color:#1d4ed8;background:none;border:0;font:inherit;text-decoration:none;white-space:nowrap;}
#phproxy-navigation .phproxy-go{cursor:pointer;padding:8px 14px;border:0;border-radius:6px;background:#2563eb;color:#fff;font:inherit;}
#phproxy-navigation :focus-visible{outline:2px solid #2563eb;outline-offset:2px;}
#phproxy-viewport{position:relative;min-height:0;min-width:0;overflow:hidden;}
#phproxy-page{display:block;border:0;width:100%;height:100%;background:#fff;}
#phproxy-panel-toggle{display:none;}
#phproxy-panel{position:absolute;inset:0;display:none;}
#phproxy-panel-toggle:checked ~ #phproxy-viewport #phproxy-panel{display:block;}
</style></head><body>
HTML;
    $document .= '<input type="checkbox" id="phproxy-panel-toggle"' . ($open ? ' checked' : '') . '>'
        . '<header id="phproxy-navigation" aria-label="PHProxy browsing bar">';
    $document .= $navigation_token !== null
        ? '<form class="phproxy-row" method="post" action="' . $home . '">'
        : '<div class="phproxy-row">';
    $document .= '<a class="phproxy-link" href="' . $edit . '" aria-label="PHProxy home">PHProxy</a>'
        . '<input class="phproxy-url" type="text" aria-label="Current page URL" name="phproxy_browse_url" value="' . $current . '" autocomplete="off"'
        . ($navigation_token !== null ? ' required' : ' readonly') . '>';
    if ($navigation_token !== null) {
        $document .= '<input type="hidden" name="phproxy_navigation_token" value="' . $escape($navigation_token) . '">'
            . '<button class="phproxy-go" type="submit">Go</button>';
    } else {
        $document .= '<a class="phproxy-link" href="' . $edit . '">Change URL</a>';
    }
    $document .= '<button class="phproxy-link" id="phproxy-settings-button" type="button" aria-controls="phproxy-panel" aria-expanded="' . ($open ? 'true' : 'false') . '">Settings</button>'
        . ($navigation_token !== null ? '</form>' : '</div>') . '</header>'
        . '<main id="phproxy-viewport"><iframe id="phproxy-page" title="Proxied page" sandbox="' . $sandbox . '" referrerpolicy="no-referrer" srcdoc="' . $escape($html) . '"></iframe>'
        . '<section id="phproxy-panel" role="region" aria-label="PHProxy settings"><div class="panel-inner">'
        . '<div class="panel-head"><h2>Settings</h2><button type="button" class="close" id="phproxy-settings-close">Close</button></div>'
        . $panel_html . '</div></section></main>'
        . '<script>' . phproxy_ui_js() . '</script></body></html>';
    return $document;
}

/** Only trusted proxy controls live in the outer document; the page is sandboxed separately. */
function phproxy_browsing_shell_headers(): void
{
    phproxy_untrusted_response_headers(false);
    header('Content-Type: text/html; charset=UTF-8');
    header('Content-Security-Policy: ' . phproxy_browsing_shell_policy());
}

function phproxy_browsing_shell_policy(): string
{
    return "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; media-src 'self' data:; frame-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";
}

function phproxy_content_policy(bool $allow_scripts = false): string
{
    // Session-bound encrypted stylesheet/font URLs need same-origin cookies.
    // Preserve that origin only while both CSP and the sandbox block scripts.
    // Script opt-in always gets an opaque origin; never combine both grants.
    return 'sandbox allow-forms allow-popups allow-popups-to-escape-sandbox allow-top-navigation-by-user-activation'
        . ($allow_scripts ? ' allow-scripts' : ' allow-same-origin')
        . "; object-src 'none'; base-uri 'none'"
        . ($allow_scripts ? '' : "; script-src 'none'");
}

function phproxy_untrusted_response_headers(bool $allow_scripts = false): void
{
    foreach (['Access-Control-Allow-Origin', 'Access-Control-Allow-Credentials', 'Access-Control-Allow-Headers',
              'Access-Control-Allow-Methods', 'Content-Security-Policy-Report-Only', 'Refresh', 'Link',
              'Clear-Site-Data', 'Service-Worker-Allowed', 'Report-To', 'Reporting-Endpoints', 'NEL',
              'Strict-Transport-Security', 'Alt-Svc', 'Proxx-Orig-URL',
              'Cross-Origin-Resource-Policy', 'Cross-Origin-Embedder-Policy'] as $name) header_remove($name);
    header('Content-Security-Policy: ' . phproxy_content_policy($allow_scripts));
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    header('Cache-Control: private, no-store');
    header('Cross-Origin-Opener-Policy: same-origin');
}

// --- TEMPLATES (formerly files/php/index.inc.php and _panel_tabs.inc.php) ---

function phproxy_csrf_field(): string
{
    return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars(phproxy_csrf_token(), ENT_QUOTES, 'UTF-8') . '"/>';
}

/** Shared bindings for the trusted home page and browsing shell. */
function phproxy_ui_js(): string
{
    return <<<'JAVASCRIPT'
(function () {

    // Cross-page fragments arrive on the outer proxy URL. Forward them to
    // the already loaded document without adding another history entry.
    var pageFrame = document.getElementById('phproxy-page');
    if (pageFrame) {
        var syncPageFragment = function () {
            if (!window.location.hash) return;
            try {
                var pageDocument = pageFrame.contentDocument;
                if (pageDocument && pageDocument.URL.split('#')[0] === 'about:srcdoc') {
                    pageFrame.contentWindow.location.replace('about:srcdoc' + window.location.hash);
                }
            } catch (_) {
                // Script opt-in intentionally isolates the page's origin.
            }
        };
        pageFrame.addEventListener('load', syncPageFragment);
        window.addEventListener('hashchange', syncPageFragment);
        syncPageFragment();
    }

    // The trusted shell uses a checkbox for its settings panel layout.
    var settingsButton = document.getElementById('phproxy-settings-button');
    var settingsToggle = document.getElementById('phproxy-panel-toggle');
    var settingsClose = document.getElementById('phproxy-settings-close');
    if (settingsButton && settingsToggle) {
        var syncSettings = function () {
            settingsButton.setAttribute('aria-expanded', settingsToggle.checked ? 'true' : 'false');
        };
        settingsButton.addEventListener('click', function (ev) {
            ev.preventDefault();
            settingsToggle.checked = !settingsToggle.checked;
            syncSettings();
        });
        if (settingsClose) {
            settingsClose.addEventListener('click', function (ev) {
                ev.preventDefault();
                settingsToggle.checked = false;
                syncSettings();
                settingsButton.focus();
            });
        }
        settingsToggle.addEventListener('change', syncSettings);
        syncSettings();
    }
    var root = document.documentElement;
    var btn = document.querySelector('.theme-toggle');
    if (btn) {
        btn.addEventListener('click', function () {
            var cur = root.getAttribute('data-theme');
            if (!cur) cur = matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
            var next = cur === 'dark' ? 'light' : 'dark';
            root.setAttribute('data-theme', next);
            try { localStorage.setItem('phproxy-theme', next); } catch (e) {}
        });
    }

    // User-Agent picker: select preset auto-fills the text input
    var sel = document.getElementById('ua-preset');
    var inp = document.getElementById('ua-input');
    if (sel && inp) {
        sel.addEventListener('change', function () {
            if (sel.value === '__custom__') {
                inp.focus();
                inp.select();
            } else {
                inp.value = sel.value;
            }
        });
    }

    // CLI tab — clipboard copy buttons (mirrors the inline-panel handler)
    document.querySelectorAll('.cli-copy').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var t = document.getElementById(btn.dataset.target);
            if (!t) return;
            var text = t.textContent;
            var done = function () {
                var orig = btn.textContent;
                btn.textContent = 'Copied!';
                setTimeout(function () { btn.textContent = orig; }, 1500);
            };
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(done, done);
            } else {
                var ta = document.createElement('textarea');
                ta.value = text;
                document.body.appendChild(ta);
                ta.select();
                try { document.execCommand('copy'); done(); } catch (e) {}
                document.body.removeChild(ta);
            }
        });
    });

    // Network-check cards (Port / DNS / SSL) — fetch the API and render
    function fmtPortcheck(j) {
        var results = j.results || [];
        if (!results.length) return 'No ports scanned';
        var header = j.host + '   ' + j.count + ' port' + (j.count === 1 ? '' : 's') +
                     '   open: ' + j.open + '   closed: ' + j.closed +
                     '   (' + (j.duration_ms || 0) + ' ms)';
        // Sequential -> show one line per port, aligned
        var maxPort = 0;
        results.forEach(function (r) { if (String(r.port).length > maxPort) maxPort = String(r.port).length; });
        var lines = [header, ''];
        results.forEach(function (r) {
            var portStr = String(r.port);
            while (portStr.length < maxPort) portStr = ' ' + portStr;
            if (r.reachable) {
                lines.push(portStr + '  OPEN    ' + r.latency_ms + ' ms');
            } else {
                lines.push(portStr + '  CLOSED  ' + (r.error || 'unreachable') + '   ' + (r.latency_ms || 0) + ' ms');
            }
        });
        return lines.join('\n');
    }
    function fmtDns(j) {
        if (!j.records || !j.records.length) {
            return 'No ' + j.type + ' records for ' + j.host + '  (' + j.duration_ms + ' ms)';
        }
        var lines = [j.host + '  ' + j.type + '  ' + j.records.length + ' record(s)  (' + j.duration_ms + ' ms)', ''];
        j.records.forEach(function (r) {
            var key = r.type || j.type;
            var val = '';
            if (r.ip)          val = r.ip;
            else if (r.ipv6)   val = r.ipv6;
            else if (r.target) val = r.target + (r.pri != null ? '  (pri ' + r.pri + ')' : '');
            else if (r.txt)    val = r.txt;
            else if (r.value)  val = r.value;
            else if (r.mname)  val = r.mname + ' / ' + (r.rname || '') + ' (serial ' + (r.serial || '') + ')';
            else if (r.tag)    val = r.tag + ' "' + (r.value || '') + '"';
            else               val = JSON.stringify(r);
            lines.push(key + '  ' + val + (r.ttl != null ? '   ttl ' + r.ttl : ''));
        });
        return lines.join('\n');
    }
    // Rich cert renderer (window.phproxyFmtCertHtml + phproxyBindCertCopy)
    // is loaded from ?asset=netcheck.js and shared with the inline panel.
    // Render the port-check result panel from the current scan state.
    function renderPortRunning(out, state) {
        var lines = [
            state.host + '   ' + state.results.length + '/' + state.count + ' port' + (state.count === 1 ? '' : 's') +
            '   open: ' + state.open + '   closed: ' + state.closed +
            (state.done ? '   (' + (state.duration_ms || 0) + ' ms)' : '   …scanning'),
            '',
        ];
        state.results.forEach(function (r) {
            var ps = String(r.port);
            while (ps.length < state.maxPort) ps = ' ' + ps;
            if (r.reachable) lines.push(ps + '  OPEN    ' + r.latency_ms + ' ms');
            else             lines.push(ps + '  CLOSED  ' + (r.error || 'unreachable') + '   ' + (r.latency_ms || 0) + ' ms');
        });
        out.textContent = lines.join('\n');
    }

    // Streaming port-check via NDJSON. Updates the result pre on every line.
    async function streamPortcheck(form, out) {
        var fd = new FormData(form);
        var params = new URLSearchParams();
        params.set('api', 'portcheck');
        params.set('stream', '1');
        fd.forEach(function (v, k) { params.set(k, v); });
        out.hidden = false;
        out.className = 'netcheck-result busy';
        out.textContent = 'Connecting…';
        var resp = await fetch('?' + params.toString(), { headers: { 'Accept': 'application/x-ndjson' } });
        if (!resp.ok) {
            // Try to surface the JSON error envelope the dispatcher sends.
            var msg = 'HTTP ' + resp.status;
            try { var j = await resp.json(); if (j && j.error) msg = 'ERROR  ' + j.error; } catch (e) {}
            out.className = 'netcheck-result err';
            out.textContent = msg;
            return;
        }
        var reader  = resp.body.getReader();
        var decoder = new TextDecoder();
        var buf = '';
        var state = { host: '', count: 0, open: 0, closed: 0, results: [], maxPort: 0, done: false, duration_ms: 0 };
        while (true) {
            var chunk = await reader.read();
            if (chunk.done) break;
            buf += decoder.decode(chunk.value, { stream: true });
            var nl;
            while ((nl = buf.indexOf('\n')) >= 0) {
                var line = buf.slice(0, nl); buf = buf.slice(nl + 1);
                if (!line.trim()) continue;
                var ev;
                try { ev = JSON.parse(line); } catch (e) { continue; }
                if (ev.event === 'start') {
                    state.host  = ev.host;
                    state.count = ev.count;
                    (ev.ports || []).forEach(function (p) { var l = String(p).length; if (l > state.maxPort) state.maxPort = l; });
                    renderPortRunning(out, state);
                } else if (ev.event === 'result') {
                    state.results.push(ev);
                    if (ev.reachable) state.open++; else state.closed++;
                    renderPortRunning(out, state);
                } else if (ev.event === 'end') {
                    state.done        = true;
                    state.duration_ms = ev.duration_ms;
                    var anyOpen = state.open > 0, anyClosed = state.closed > 0;
                    out.className = 'netcheck-result ' + (anyOpen && !anyClosed ? 'ok' : (anyOpen ? 'warn' : 'err'));
                    renderPortRunning(out, state);
                }
            }
        }
    }

    function bindNetcheck(form) {
        var kind = form.getAttribute('data-netcheck');
        var out  = form.querySelector('.netcheck-result');
        var btn  = form.querySelector('button[type="submit"]');
        form.addEventListener('submit', async function (ev) {
            ev.preventDefault();
            btn.disabled = true;
            try {
                if (kind === 'portcheck') {
                    await streamPortcheck(form, out);
                    return;
                }
                var fd = new FormData(form);
                var params = new URLSearchParams();
                params.set('api', kind);
                fd.forEach(function (v, k) { params.set(k, v); });
                out.hidden = false;
                out.className = 'netcheck-result busy';
                out.textContent = 'Running…';
                var r = await fetch('?' + params.toString(), { headers: { 'Accept': 'application/json' } });
                var j = await r.json();
                if (j.ok === false) {
                    out.className = 'netcheck-result err';
                    out.textContent = 'ERROR  ' + (j.error || 'request failed') + (j.host ? '\nhost: ' + j.host : '');
                    return;
                }
                if (kind === 'dns') {
                    out.className = 'netcheck-result ' + (j.records && j.records.length ? 'ok' : 'warn');
                    out.textContent = fmtDns(j);
                } else if (kind === 'cert') {
                    var d = j.leaf && j.leaf.days_left;
                    out.className = 'netcheck-result cert-result ' + (d != null && d < 0 ? 'err' : (d != null && d < 30 ? 'warn' : 'ok'));
                    out.innerHTML = window.phproxyFmtCertHtml(j);
                    if (window.phproxyBindCertCopy) window.phproxyBindCertCopy(out);
                } else {
                    out.className = 'netcheck-result ok';
                    out.textContent = JSON.stringify(j, null, 2);
                }
            } catch (e) {
                out.className = 'netcheck-result err';
                out.textContent = 'Network error: ' + (e && e.message ? e.message : e);
            } finally {
                btn.disabled = false;
            }
        });
    }
    document.querySelectorAll('form[data-netcheck]').forEach(bindNetcheck);

    // IP tab — render the three identity cards plus the request / host sections.
    function renderIpinfoCard(role, data) {
        if (!data || !data.ip) {
            return '<div class="ipinfo-card"><div class="ipinfo-card-title">' + role + '</div>' +
                   '<div class="ipinfo-row"><span class="k">(not available)</span></div></div>';
        }
        var fam  = data.family ? '<span class="ipinfo-family">' + data.family + '</span>' : '';
        var priv = data.is_private ? '<span class="ipinfo-private">private</span>' : '';
        var rev  = data.reverse ? '<div class="ipinfo-row"><span class="k">Reverse</span><span class="v">' + escHtml(data.reverse) + '</span></div>' : '';
        return '<div class="ipinfo-card">' +
                 '<div class="ipinfo-card-title">' + role + (priv ? '  ' + priv : '') + '</div>' +
                 '<div class="ipinfo-ip">' + escHtml(data.ip) + fam + '</div>' +
                 rev +
               '</div>';
    }
    function renderIpinfoKv(title, obj) {
        if (!obj) return '';
        var rows = '';
        Object.keys(obj).forEach(function (k) {
            var v = obj[k];
            if (v === null || v === undefined) return;
            var label = k.replace(/_/g, ' ');
            if (v === '') {
                rows += '<div class="k">' + label + '</div><div class="v empty">—</div>';
            } else {
                rows += '<div class="k">' + label + '</div><div class="v">' + String(v).replace(/[&<>]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]; }) + '</div>';
            }
        });
        if (!rows) return '';
        return '<div class="ipinfo-section"><h4>' + title + '</h4><div class="ipinfo-grid">' + rows + '</div></div>';
    }
    function escHtml(s) {
        return String(s == null ? '' : s).replace(/[&<>]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]; });
    }
    async function loadIpinfo(target) {
        try {
            var r = await fetch('?api=ipinfo', { headers: { 'Accept': 'application/json' } });
            var j = await r.json();
            if (j.ok === false) {
                target.innerHTML = '<div class="ipinfo-loading">Failed: ' + escHtml(j.error || 'unknown') + '</div>';
                return;
            }
            var html  = renderIpinfoCard('Client',   j.client);
            html     += renderIpinfoCard('Server',   j.server);
            html     += renderIpinfoCard('Outgoing', j.outgoing);
            target.innerHTML = html;
            var extra = '';
            if (j.forwarded && j.forwarded.length) {
                var hops = j.forwarded.map(function (h) { return h.ip; }).join(' → ');
                extra += '<div class="ipinfo-section"><h4>X-Forwarded-For chain</h4><div class="ipinfo-grid"><div class="k">hops</div><div class="v">' + escHtml(hops) + '</div></div></div>';
            }
            extra += renderIpinfoKv('Request', j.request);
            extra += renderIpinfoKv('Host',    j.host);
            target.insertAdjacentHTML('afterend', extra);
        } catch (e) {
            target.innerHTML = '<div class="ipinfo-loading">Network error: ' + escHtml(e && e.message ? e.message : e) + '</div>';
        }
    }
    var ipTarget = document.querySelector('[data-ipinfo-target]');
    var ipTab = document.getElementById('tab-ip');
    var ipLoaded = false;
    function activateIpinfo() {
        if (!ipTarget || !ipTab || !ipTab.checked || ipLoaded) return;
        ipLoaded = true;
        loadIpinfo(ipTarget);
    }
    // Bind only: opening a page or settings panel must not issue diagnostics.
    if (ipTab) ipTab.addEventListener('change', activateIpinfo);
    document.querySelectorAll('label[for="tab-ip"]').forEach(function (label) {
        label.addEventListener('click', function () {
            // Run after the label's default radio-button selection.
            setTimeout(activateIpinfo, 0);
        });
    });

    // Custom IP lookup form inside the IP tab
    document.querySelectorAll('form[data-ipinfo-lookup]').forEach(function (form) {
        var out = form.querySelector('.netcheck-result');
        var btn = form.querySelector('button[type="submit"]');
        form.addEventListener('submit', async function (ev) {
            ev.preventDefault();
            var ip = form.querySelector('input[name="ip"]').value.trim();
            if (!ip) return;
            out.hidden = false;
            out.className = 'netcheck-result busy';
            out.textContent = 'Looking up ' + ip + '…';
            btn.disabled = true;
            try {
                var r = await fetch('?api=ipinfo&ip=' + encodeURIComponent(ip));
                var j = await r.json();
                if (j.ok === false) {
                    out.className = 'netcheck-result err';
                    out.textContent = 'ERROR  ' + (j.error || 'request failed');
                    return;
                }
                var L = j.lookup || {};
                var lines = [L.ip + '   ' + L.family + (L.is_private ? '   (private)' : '')];
                if (L.reverse) lines.push('reverse:    ' + L.reverse);
                lines.push('');
                lines.push('lookup time: ' + (j.duration_ms || 0) + ' ms');
                out.className = 'netcheck-result ok';
                out.textContent = lines.join('\n');
            } catch (e) {
                out.className = 'netcheck-result err';
                out.textContent = 'Network error: ' + (e && e.message ? e.message : e);
            } finally {
                btn.disabled = false;
            }
        });
    });
})();
JAVASCRIPT;
}

function phproxy_render_entry_form(array $data): void {
// Finish session reads and form tokens before any HTML reaches the client.
ob_start();
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
header('Cache-Control: private, no-store');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('Cross-Origin-Opener-Policy: same-origin');

$_show_raw_values = !empty($_COOKIE['phproxy-show-raw']);
$_panel_buckets   = phproxy_panel_buckets();
$_visible_cookies = $_panel_buckets['cookies'];
$_custom_headers  = $_panel_buckets['headers'];
$_header_origins  = $_panel_buckets['header_origins'] ?? [];
$_last_trace      = phproxy_trace_entries();
$_current_ua      = phproxy_user_agent_setting();
$_ua_presets      = phproxy_ua_presets();

$_active_tab = isset($_GET['tab']) ? (string) $_GET['tab'] : 'options';
$_valid_tabs = ['network' => 1, 'response' => 1, 'options' => 1, 'cookies' => 1, 'headers' => 1, 'ip' => 1, 'port' => 1, 'dns' => 1, 'cert' => 1, 'cli' => 1];
if (!isset($_valid_tabs[$_active_tab])) $_active_tab = 'options';
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <title><?php echo htmlspecialchars($GLOBALS['_config']['site_name']); ?></title>
    <link rel="stylesheet" href="?asset=index.css&amp;v=<?php echo htmlspecialchars($GLOBALS['_version']); ?>"/>
    <script src="?asset=netcheck.js&amp;v=<?php echo htmlspecialchars($GLOBALS['_version']); ?>" defer></script>
    <script>
    (function () {
        var s = null;
        try { s = localStorage.getItem('phproxy-theme'); } catch (e) {}
        if (s === 'dark' || s === 'light') {
            document.documentElement.setAttribute('data-theme', s);
        }
    })();
    </script>
</head>
<body>
<div class="page">
    <header class="appbar">
        <h1><?php echo htmlspecialchars($GLOBALS['_config']['site_name']); ?><span class="dot">.</span></h1>
        <button type="button" class="theme-toggle" aria-label="Toggle colour theme" title="Toggle colour theme">
            <svg class="icon-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <circle cx="12" cy="12" r="4"/>
                <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/>
            </svg>
            <svg class="icon-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
            </svg>
        </button>
    </header>

<?php if ($data['category'] != 'auth'): ?>
    <form id="proxy-main-form" method="post" action="<?php echo htmlspecialchars($GLOBALS['_script_url']); ?>">
        <?php echo phproxy_csrf_field(); ?>
        <div class="card">
            <div class="form-row url-row">
                <input class="url-input" type="text" name="<?php echo htmlspecialchars($GLOBALS['_config']['url_var_name']) ?>" value="<?php echo isset($_GET[$GLOBALS['_config']['url_var_name']]) ? htmlspecialchars(decode_url($_GET[$GLOBALS['_config']['url_var_name']])) : (isset($_GET['__iv']) ? htmlspecialchars($_GET['__iv']) : ''); ?>" placeholder="https://www.example.com/" required autofocus autocomplete="off"/>
                <button class="button-submit" type="submit">Go</button>
            </div>
<?php
switch ($data['category']) {
    case 'error':
        echo '            <p class="error">';

        switch ($data['group']) {
            case 'url':
                echo '<b>URL Error (' . htmlspecialchars($data['error']) . ')</b>: ';
                switch ($data['type']) {
                    case 'internal':
                        $message = 'Failed to connect to the specified host. '
                            . 'Possible problems are that the server was not found, the connection timed out, or the connection refused by the host. '
                            . 'Try connecting again and check if the address is correct.';
                        break;
                    case 'external':
                        switch ($data['error']) {
                            case 1:
                                $message = 'The URL you\'re attempting to access is blacklisted by this server. Please select another URL.';
                                break;
                            case 2:
                                $message = 'The URL you entered is malformed. Please check whether you entered the correct URL or not.';
                                break;
                        }
                        break;
                }
                break;
            case 'resource':
                echo '<b>Resource Error:</b> ';
                switch ($data['type']) {
                    case 'file_size':
                        $message = 'The file your are attempting to download is too large.<br/>'
                        . 'Maxiumum permissible file size is <b>' . number_format($GLOBALS['_config']['max_file_size'] / 1048576, 2) . ' MB</b><br/>'
                        . 'Requested file size is <b>' . number_format($GLOBALS['_content_length'] / 1048576, 2) . ' MB</b>';
                        break;
                    case 'hotlinking':
                        $message = 'It appears that you are trying to access a resource through this proxy from a remote Website.<br/>'
                            . 'For security reasons, please use the form below to do so.';
                        break;
                }
                break;
        }

        echo 'An error has occured while trying to browse through the proxy. <br/>' . $message . '</p>';
        break;
}
?>
        </div>
    </form>
    <?php /* Main URL form ends here. Tabs below have their own per-row forms;
             Options-tab inputs use form="proxy-main-form" so they ride along
             on URL submission and persist as the 'flags' cookie. */ ?>

    <?php if (in_array(0, $GLOBALS['_frozen_flags'])): ?>
    <div class="card">
<?php
$GLOBALS['_show_raw_values']  = $_show_raw_values;
$GLOBALS['_visible_cookies']  = $_visible_cookies;
$GLOBALS['_custom_headers']   = $_custom_headers;
$GLOBALS['_header_origins']   = $_header_origins;
$GLOBALS['_ua_presets']       = $_ua_presets;
phproxy_render_panel_tabs(
    return_to:     '',
    show_response: !empty($_last_trace),
    request_pairs: $_last_trace['request_pairs'] ?? [],
    response_pairs: $_last_trace['response_pairs'] ?? [],
    request_line: $_last_trace['request_line'] ?? '',
    cli_url: $_last_trace['url'] ?? '',
    cli_method: $_last_trace['method'] ?? 'GET',
    cli_headers: $_last_trace['request_pairs'] ?? [],
    active_tab:    $_active_tab,
    form_id:       'proxy-main-form',
    show_network:  true,
    network_entries: phproxy_network_entries(),
    show_cert: getenv('PHPROXY_DIAGNOSTICS') === '1'
);
?>
    </div>
    <?php endif; ?>
<?php elseif ($data['category'] == 'auth'): ?>
    <form class="auth" method="post" action="<?php echo htmlspecialchars($_SERVER['REQUEST_URI']); ?>">
        <?php echo phproxy_csrf_field(); ?>
        <div class="card main-auth-box">
            <div class="form-title-row">
                <h2 class="auth-header">Authentication Required</h2>
            </div>
            <input type="hidden" name="<?php echo htmlspecialchars($GLOBALS['_config']['basic_auth_var_name']) ?>" value="<?php echo base64_encode($data['realm']) ?>"/>
            <div class="form-row">
                <label>
                    <span>Username</span>
                    <input type="text" name="username" placeholder="Username" autocomplete="username"/>
                </label>
            </div>
            <div class="form-row">
                <label>
                    <span>Password</span>
                    <input type="password" name="password" placeholder="Password" autocomplete="current-password"/>
                </label>
            </div>
            <div class="tab-actions">
                <button class="button-submit" type="submit">Login</button>
                <a class="button-cancel" href="<?php echo htmlspecialchars($GLOBALS['_script_url']); ?><?php echo '?__iv=' . rawurlencode($GLOBALS['_url']); ?>">Cancel</a>
            </div>
            <?php if (!empty($_POST['username']) || !empty($_POST['password'])): ?>
            <p class="error"><b>Authentication Required: </b>The supplied credentials were unauthorized to access the specified content.</p>
            <?php else: ?>
            <p class="info"><b>Authentication Required: </b>Enter your username and password for &quot;<?php echo htmlspecialchars($data['realm']); ?>&quot; on <?php echo htmlspecialchars($GLOBALS['_url_parts']['host']); ?></p>
            <?php endif; ?>
        </div>
    </form>
<?php endif; ?>

    <p class="footer"><a href="https://github.com/PHProxy/phproxy">PHProxy</a> <?= $GLOBALS['_version']; ?></p>
</div>

<script><?php echo phproxy_ui_js(); ?></script>
</body>
</html>

<?php
echo ob_get_clean();
}

function phproxy_render_panel_tabs(
    string $return_to = '',
    bool $show_response = false,
    array $response_pairs = [],
    array $request_pairs = [],
    string $request_line = '',
    string $active_tab = 'options',
    string $form_id = '',
    bool $show_cli = false,
    string $cli_url = '',
    string $cli_method = 'GET',
    array $cli_headers = [],
    string $cli_body = '',
    string $cli_api_url = '',
    bool $show_network = false,
    array $network_entries = [],
    string $network_current_url = '',
    bool $show_netchecks = true,  // IP / Port / DNS — entry page only
    bool $show_cert = true,       // SSL tab — shown on entry + HTTPS proxied pages
    string $cert_host = '',       // Pre-fill the SSL form for the current page
    int $cert_port = 0,
    bool $cert_autorun = false,   // Auto-run the cert check when the SSL tab opens
    string $return_url = ''       // Current upstream URL, for fresh encoding after settings changes
): void {
    // Local aliases keep the existing template body unchanged
    $_panel_return_to      = $return_to;
    $_panel_return_url     = $return_url;
    $_panel_show_response  = $show_response;
    $_panel_response_pairs = $response_pairs;
    $_panel_request_pairs  = $request_pairs;
    $_panel_request_line   = $request_line;
    $_panel_active_tab     = $active_tab;
    $_panel_form_id        = $form_id;
    $_panel_show_cli       = $show_cli;
    $_panel_cli_url        = $cli_url;
    $_panel_cli_method     = $cli_method;
    $_panel_cli_headers    = $cli_headers;
    $_panel_cli_body       = $cli_body;
    $_panel_cli_api_url    = $cli_api_url;
    $_panel_show_network   = $show_network;
    $_panel_network        = $network_entries;
    $_panel_net_current    = $network_current_url;
    $_panel_show_netchecks = $show_netchecks;
    $_panel_show_cert      = $show_cert && getenv('PHPROXY_DIAGNOSTICS') === '1';
    $_panel_diagnostics    = getenv('PHPROXY_DIAGNOSTICS') === '1';
    $_panel_cert_host      = $cert_host;
    $_panel_cert_port      = $cert_port > 0 ? $cert_port : 443;
    $_panel_cert_autorun   = $cert_autorun;

$_panel_return_html = phproxy_csrf_field() . ($_panel_return_to !== ''
    ? '<input type="hidden" name="return_to" value="' . htmlspecialchars($_panel_return_to, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '"/>'
      . '<input type="hidden" name="return_url" value="' . htmlspecialchars($_panel_return_url, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '"/>'
    : '');
$_form_attr = $_panel_form_id !== '' ? ' form="' . htmlspecialchars($_panel_form_id) . '"' : '';

$_cfg          = $GLOBALS['_config'];
$_flags_local  = $GLOBALS['_flags'];
$_frozen       = $GLOBALS['_frozen_flags'];
$_labels_local = $GLOBALS['_labels'];
$_v_cookies    = $GLOBALS['_visible_cookies'] ?? [];
$_c_headers    = $GLOBALS['_custom_headers']  ?? [];
$_h_origins    = $GLOBALS['_header_origins'] ?? [];
$_show_raw     = !empty($GLOBALS['_show_raw_values']);
$_current_ua_local = phproxy_user_agent_setting();
$_ua_presets_local = $GLOBALS['_ua_presets'] ?? [];
?>
<div class="tabs-wrap">
    <input type="radio" name="tab" id="tab-options"<?php echo $_panel_active_tab === 'options' ? ' checked' : ''; ?>/>
    <input type="radio" name="tab" id="tab-cookies"<?php echo $_panel_active_tab === 'cookies' ? ' checked' : ''; ?>/>
    <input type="radio" name="tab" id="tab-headers"<?php echo $_panel_active_tab === 'headers' ? ' checked' : ''; ?>/>
    <?php if ($_panel_show_netchecks): ?>
    <input type="radio" name="tab" id="tab-ip"<?php echo $_panel_active_tab === 'ip' ? ' checked' : ''; ?>/>
    <?php if ($_panel_diagnostics): ?><input type="radio" name="tab" id="tab-port"<?php echo $_panel_active_tab === 'port' ? ' checked' : ''; ?>/><?php endif; ?>
    <input type="radio" name="tab" id="tab-dns"<?php echo $_panel_active_tab === 'dns' ? ' checked' : ''; ?>/>
    <?php endif; ?>
    <?php if ($_panel_show_cert): ?>
    <input type="radio" name="tab" id="tab-cert"<?php echo $_panel_active_tab === 'cert' ? ' checked' : ''; ?>/>
    <?php endif; ?>
    <?php if ($_panel_show_response): ?>
    <input type="radio" name="tab" id="tab-response"<?php echo $_panel_active_tab === 'response' ? ' checked' : ''; ?>/>
    <?php endif; ?>
    <input type="radio" name="tab" id="tab-cli"<?php echo $_panel_active_tab === 'cli' ? ' checked' : ''; ?>/>
    <?php if ($_panel_show_network): ?>
    <input type="radio" name="tab" id="tab-network"<?php echo $_panel_active_tab === 'network' ? ' checked' : ''; ?>/>
    <?php endif; ?>

    <nav class="tabs">
        <label for="tab-options">Options</label>
        <label for="tab-cookies">Cookies <span class="tab-count"><?php echo count($_v_cookies); ?></span></label>
        <label for="tab-headers">Headers <span class="tab-count"><?php echo count($_c_headers); ?></span></label>
        <?php if ($_panel_show_netchecks): ?>
        <label for="tab-ip">IP</label>
        <?php if ($_panel_diagnostics): ?><label for="tab-port">Port</label><?php endif; ?>
        <label for="tab-dns">DNS</label>
        <?php endif; ?>
        <?php if ($_panel_show_cert): ?>
        <label for="tab-cert">SSL</label>
        <?php endif; ?>
        <?php if ($_panel_show_response): ?>
        <label for="tab-response">Trace <span class="tab-count"><?php echo count($_panel_request_pairs) + count($_panel_response_pairs); ?></span></label>
        <?php endif; ?>
        <label for="tab-cli">CLI</label>
        <?php if ($_panel_show_network): ?>
        <label for="tab-network">Network <span class="tab-count"><?php echo count($_panel_network); ?></span></label>
        <?php endif; ?>
    </nav>

    <section class="tab-panel" data-tab="options">
<?php
$_option_groups = [
    'Browsing' => ['include_form', 'remove_scripts', 'show_images', 'strip_iframes', 'block_3p', 'block_fonts', 'block_media'],
    'Privacy'  => ['show_referer', 'send_dnt', 'send_gpc', 'strip_title', 'strip_meta', 'strip_tracking'],
    'Cookies'  => ['accept_cookies', 'session_cookies'],
];
foreach ($_option_groups as $_group_name => $_group_flags):
    $_visible = false;
    foreach ($_group_flags as $_f) {
        if (!$_frozen[$_f]) { $_visible = true; break; }
    }
    if (!$_visible) continue;
?>
        <fieldset class="option-group">
            <legend><?php echo htmlspecialchars($_group_name); ?></legend>
            <ul class="prx-opt-menu">
<?php foreach ($_group_flags as $_f): ?>
<?php if (!$_frozen[$_f]): ?>
                <li class="option"><label><input<?php echo $_form_attr; ?> type="checkbox" name="<?php echo $_cfg['flags_var_name']; ?>[<?php echo $_f; ?>]"<?php echo $_flags_local[$_f] ? ' checked' : ''; ?>/><span><?php echo htmlspecialchars($_labels_local[$_f][0]); ?></span></label></li>
<?php endif; ?>
<?php endforeach; ?>
            </ul>
        </fieldset>
<?php endforeach; ?>
<?php
$_url_encoding = 'none';
if (!empty($_flags_local['encrypt_url']))   $_url_encoding = 'encrypted';
elseif ($_flags_local['rotate13'])          $_url_encoding = 'rot13';
elseif ($_flags_local['base64_encode'])     $_url_encoding = 'base64';
$_seed_ttl  = phproxy_seed_ttl();
$_seed_bits = phproxy_seed_bits();
$_seed_present = phproxy_seed_present();
?>
        <fieldset class="option-group">
            <legend>Address bar</legend>
            <div class="radio-row">
                <span class="radio-row-label">URL encoding</span>
                <label><input<?php echo $_form_attr; ?> type="radio" name="<?php echo $_cfg['flags_var_name']; ?>[__url_enc]" value="none"<?php echo $_url_encoding === 'none' ? ' checked' : ''; ?>/> None</label>
                <label><input<?php echo $_form_attr; ?> type="radio" name="<?php echo $_cfg['flags_var_name']; ?>[__url_enc]" value="rot13"<?php echo $_url_encoding === 'rot13' ? ' checked' : ''; ?>/> ROT13</label>
                <label><input<?php echo $_form_attr; ?> type="radio" name="<?php echo $_cfg['flags_var_name']; ?>[__url_enc]" value="base64"<?php echo $_url_encoding === 'base64' ? ' checked' : ''; ?>/> Base64</label>
                <label><input<?php echo $_form_attr; ?> type="radio" name="<?php echo $_cfg['flags_var_name']; ?>[__url_enc]" value="encrypted"<?php echo $_url_encoding === 'encrypted' ? ' checked' : ''; ?>/> Encrypted <span class="hint">(rotating key)</span></label>
            </div>
            <div class="seed-config">
                <p class="tab-help">Encrypted mode hides destination URLs in the address bar using a server-side session key. Rotation invalidates old links. It does not erase browsing history or the Network log.</p>
                <div class="seed-row">
                    <form class="seed-mini" method="post" action="?action=set-seed-ttl">
                        <?php echo $_panel_return_html; ?>
                        <label class="seed-mini-label">Seed lifetime <span class="hint">(seconds)</span></label>
                        <input type="number" name="seedTtl" min="60" max="604800" step="60" value="<?php echo (int) $_seed_ttl; ?>"/>
                        <button class="button-cancel" type="submit">Save</button>
                    </form>
                    <form class="seed-mini" method="post" action="?action=set-seed-bits">
                        <?php echo $_panel_return_html; ?>
                        <label class="seed-mini-label">Key length</label>
                        <select name="seedBits">
                            <option value="128"<?php echo $_seed_bits === 128 ? ' selected' : ''; ?>>AES-128</option>
                            <option value="192"<?php echo $_seed_bits === 192 ? ' selected' : ''; ?>>AES-192</option>
                            <option value="256"<?php echo $_seed_bits === 256 ? ' selected' : ''; ?>>AES-256</option>
                        </select>
                        <button class="button-cancel" type="submit">Save</button>
                    </form>
                    <form class="seed-mini" method="post" action="?action=rotate-seed">
                        <?php echo $_panel_return_html; ?>
                        <label class="seed-mini-label">Seed <span class="hint"><?php echo $_seed_present ? 'live' : 'not set'; ?></span></label>
                        <button class="button-ghost" type="submit" title="Generate a new random seed now">Rotate now</button>
                    </form>
                </div>
            </div>
        </fieldset>
    </section>

    <section class="tab-panel" data-tab="cookies">
        <div class="tab-toolbar">
            <p class="tab-help">Cookies stored on this server for each exact upstream host. Click a row to edit.</p>
            <form class="toolbar-toggle" method="post" action="?action=toggle-raw">
                <?php echo $_panel_return_html; ?>
                <button type="submit" class="button-cancel" title="Switch between URL-decoded and raw wire-form values"><?php echo $_show_raw ? 'Showing: raw' : 'Showing: decoded'; ?></button>
            </form>
        </div>
<?php if (empty($_v_cookies)): ?>
        <ul class="kv-list"><li class="empty">No cookies yet</li></ul>
<?php else: ?>
        <ul class="kv-list">
<?php
foreach ($_v_cookies as $_wire => $_c):
    $_disp_value = $_show_raw ? $_c['raw_value'] : $_c['value'];
    $_disp_name  = $_show_raw ? $_c['raw_name']  : $_c['display_name'];
?>
            <li class="kv-row">
                <details class="kv-card">
                    <summary>
                        <span class="kv-display">
                            <?php if ($_c['is_proxy']): ?><span class="kv-host"><?php echo htmlspecialchars($_c['host']); ?></span><span class="kv-sep">·</span><?php endif; ?>
                            <span class="kv-name"><?php echo htmlspecialchars($_disp_name); ?></span><span class="kv-sep">=</span><span class="kv-val"><?php echo htmlspecialchars(mb_strimwidth($_disp_value, 0, 72, '…')); ?></span>
                        </span>
                        <span class="kv-chevron" aria-hidden="true">▾</span>
                    </summary>
                    <form class="kv-edit kv-edit-cookie" method="post" action="?action=edit-cookie">
                        <?php echo $_panel_return_html; ?>
                        <input type="hidden" name="name" value="<?php echo htmlspecialchars($_wire); ?>"/>
                        <label class="kv-edit-field"><span>Name</span><input type="text" name="cookieName" value="<?php echo htmlspecialchars($_c['display_name']); ?>" autocomplete="off"/></label>
                        <label class="kv-edit-field kv-edit-wide"><span>Value</span><input type="text" name="cookieValue" value="<?php echo htmlspecialchars($_c['value']); ?>" autocomplete="off"/></label>
                        <label class="kv-edit-field"><span>Host</span><input type="text" name="cookieDomain" value="<?php echo htmlspecialchars(ltrim($_c['domain'], '.')); ?>" placeholder="example.com" autocomplete="off"/></label>
                        <label class="kv-edit-field"><span>Path</span><input type="text" name="cookiePath" value="<?php echo htmlspecialchars($_c['path'] ?: '/'); ?>" placeholder="/" autocomplete="off"/></label>
                        <label class="kv-edit-field"><span>Expires <span class="hint">(days, 0 = session)</span></span><input type="number" name="cookieExpires" value="<?php echo empty($_c['expires']) ? 0 : max(1, (int) ceil(($_c['expires'] - time()) / 86400)); ?>" min="0" max="3650"/></label>
                        <label class="kv-edit-field"><span>SameSite</span>
                            <select name="cookieSameSite">
                                <option value="">(default)</option>
                                <option value="Lax">Lax</option>
                                <option value="Strict">Strict</option>
                                <option value="None">None</option>
                            </select>
                        </label>
                        <div class="kv-edit-checks">
                            <label class="kv-edit-check"><input type="checkbox" name="cookieSecure"<?php echo $_c['secure'] ? ' checked' : ''; ?>/> Secure</label>
                            <label class="kv-edit-check"><input type="checkbox" name="cookieHttpOnly"<?php echo !empty($_c['httponly']) ? ' checked' : ''; ?>/> HttpOnly</label>
                        </div>
                        <div class="kv-edit-actions">
                            <button class="button-submit" type="submit">Save</button>
                        </div>
                    </form>
                </details>
                <form class="kv-delete" method="post" action="?action=delete-cookie">
                    <?php echo $_panel_return_html; ?>
                    <input type="hidden" name="name" value="<?php echo htmlspecialchars($_wire); ?>"/>
                    <button class="button-icon" type="submit" title="Delete cookie" aria-label="Delete <?php echo htmlspecialchars($_c['display_name']); ?>">&times;</button>
                </form>
            </li>
<?php endforeach; ?>
        </ul>
<?php endif; ?>
        <details class="kv-card kv-card-add">
            <summary><span class="kv-display"><span class="kv-name">+ Add a cookie</span></span><span class="kv-chevron" aria-hidden="true">▾</span></summary>
            <form class="kv-edit kv-edit-cookie" method="post" action="?action=add-cookie">
                <?php echo $_panel_return_html; ?>
                <label class="kv-edit-field"><span>Name</span><input type="text" name="cookieName" placeholder="session_id" autocomplete="off" required/></label>
                <label class="kv-edit-field kv-edit-wide"><span>Value</span><input type="text" name="cookieValue" placeholder="abc123" autocomplete="off"/></label>
                <label class="kv-edit-field"><span>Host <span class="hint">(exact match)</span></span><input type="text" name="cookieDomain" placeholder="example.com" autocomplete="off" required/></label>
                <label class="kv-edit-field"><span>Path</span><input type="text" name="cookiePath" value="/" placeholder="/" autocomplete="off"/></label>
                <label class="kv-edit-field"><span>Expires <span class="hint">(days, 0 = session)</span></span><input type="number" name="cookieExpires" value="30" min="0" max="3650"/></label>
                <label class="kv-edit-field"><span>SameSite</span>
                    <select name="cookieSameSite">
                        <option value="">(default)</option>
                        <option value="Lax" selected>Lax</option>
                        <option value="Strict">Strict</option>
                        <option value="None">None</option>
                    </select>
                </label>
                <div class="kv-edit-checks">
                    <label class="kv-edit-check"><input type="checkbox" name="cookieSecure"/> Secure</label>
                    <label class="kv-edit-check"><input type="checkbox" name="cookieHttpOnly"/> HttpOnly</label>
                </div>
                <div class="kv-edit-actions">
                    <button class="button-submit" type="submit">Add cookie</button>
                </div>
            </form>
        </details>
        <form class="tab-actions" method="post" action="?action=clear-cookies">
            <?php echo $_panel_return_html; ?>
            <button class="button-ghost" type="submit">Clear all cookies</button>
        </form>
    </section>

    <section class="tab-panel" data-tab="headers">
        <p class="section-label">User-Agent</p>
        <p class="tab-help">Sent on every proxied request. <code>.</code> means use my real browser's User-Agent, <code>-</code> means send none.</p>
        <form class="ua-form" method="post" action="?action=set-ua">
            <?php echo $_panel_return_html; ?>
            <div class="ua-picker">
                <select id="ua-preset" aria-label="User-Agent preset">
<?php foreach ($_ua_presets_local as $_val => $_lbl): ?>
                    <option value="<?php echo htmlspecialchars($_val); ?>"<?php echo $_current_ua_local === $_val ? ' selected' : ''; ?>><?php echo htmlspecialchars($_lbl); ?></option>
<?php endforeach; ?>
                    <option value="__custom__"<?php echo (!array_key_exists($_current_ua_local, $_ua_presets_local) && $_current_ua_local !== '') ? ' selected' : ''; ?>>Custom…</option>
                </select>
                <input type="text" id="ua-input" name="userAgent" value="<?php echo htmlspecialchars($_current_ua_local); ?>" placeholder="Custom User-Agent string" autocomplete="off"/>
            </div>
            <div class="tab-actions" style="margin-top:12px">
                <button class="button-submit" type="submit">Save User-Agent</button>
            </div>
        </form>

        <hr class="divider"/>

<?php
// Auto-populated list of headers that PHProxy sent on the last request.
// Skip auto-managed and non-overridable rows. Only render on proxied pages
// (i.e. when the trace pairs are available).
$_replay_skip = ['host' => 1, 'cookie' => 1, 'content-length' => 1, 'content-type' => 1];
$_replay_pairs = [];
foreach ($_panel_request_pairs as $_rh) {
    [$_rh_name, $_rh_value] = $_rh;
    if ($_rh_name === '' || $_rh_name[0] === ':' || $_rh_value === '[redacted]') continue;
    if (isset($_replay_skip[strtolower($_rh_name)])) continue;
    $_replay_pairs[] = [$_rh_name, $_rh_value];
}
?>
<?php if (!empty($_replay_pairs)): ?>
        <p class="section-label">Request headers</p>
        <p class="tab-help">Headers from the latest request. Sensitive values are redacted. Save an override to use it on future requests to this site.</p>
        <ul class="kv-list">
<?php foreach ($_replay_pairs as $_rh): list($_rh_name, $_rh_value) = $_rh;
    $_is_overridden = isset($_c_headers[$_rh_name]);
?>
            <li class="kv-row">
                <details class="kv-card<?php echo $_is_overridden ? ' kv-card-overridden' : ''; ?>">
                    <summary>
                        <span class="kv-display">
                            <span class="kv-name"><?php echo htmlspecialchars($_rh_name); ?></span><span class="kv-sep">:</span><span class="kv-val"><?php echo htmlspecialchars(mb_strimwidth($_rh_value, 0, 72, '…')); ?></span>
                            <?php if ($_is_overridden): ?><span class="kv-badge">overridden</span><?php endif; ?>
                        </span>
                        <span class="kv-chevron" aria-hidden="true">▾</span>
                    </summary>
                    <form class="kv-edit" method="post" action="?action=add-header">
                        <?php echo $_panel_return_html; ?>
                        <input type="hidden" name="headerOrigin" value="<?php echo htmlspecialchars($_panel_cli_url); ?>"/>
                        <input type="hidden" name="headerAddName" value="<?php echo htmlspecialchars($_rh_name); ?>"/>
                        <label class="kv-edit-field kv-edit-wide"><span>Value</span><input type="text" name="headerAddValue" value="<?php echo htmlspecialchars($_rh_value); ?>" autocomplete="off"/></label>
                        <div class="kv-edit-actions">
                            <button class="button-submit" type="submit">Save override</button>
                        </div>
                    </form>
                </details>
<?php if ($_is_overridden): ?>
                <form class="kv-delete" method="post" action="?action=delete-header">
                    <?php echo $_panel_return_html; ?>
                    <input type="hidden" name="name" value="<?php echo htmlspecialchars($_rh_name); ?>"/>
                    <button class="button-icon" type="submit" title="Drop override (return to PHProxy default)" aria-label="Drop override for <?php echo htmlspecialchars($_rh_name); ?>">&times;</button>
                </form>
<?php endif; ?>
            </li>
<?php endforeach; ?>
        </ul>

        <hr class="divider"/>
<?php endif; ?>

        <p class="section-label">Custom headers</p>
        <p class="tab-help">Extra HTTP headers sent only to the specified site origin (scheme, host and port). Header names: ASCII letters, digits, hyphens.</p>
<?php if (empty($_c_headers)): ?>
        <ul class="kv-list"><li class="empty">No custom headers</li></ul>
<?php else: ?>
        <ul class="kv-list">
<?php foreach ($_c_headers as $_h_name => $_h_value): ?>
            <li class="kv-row">
                <details class="kv-card">
                    <summary>
                        <span class="kv-display">
                            <span class="kv-name"><?php echo htmlspecialchars($_h_name); ?></span><span class="kv-sep">:</span><span class="kv-val"><?php echo htmlspecialchars(mb_strimwidth($_h_value, 0, 72, '…')); ?></span>
                        </span>
                        <span class="kv-chevron" aria-hidden="true">▾</span>
                    </summary>
                    <form class="kv-edit" method="post" action="?action=edit-header">
                        <?php echo $_panel_return_html; ?>
                        <input type="hidden" name="oldName" value="<?php echo htmlspecialchars($_h_name); ?>"/>
                        <label class="kv-edit-field"><span>Name</span><input type="text" name="headerName" value="<?php echo htmlspecialchars($_h_name); ?>" pattern="[A-Za-z0-9-]+" autocomplete="off"/></label>
                        <label class="kv-edit-field"><span>Site URL</span><input type="url" name="headerOrigin" value="<?php echo htmlspecialchars($_h_origins[$_h_name] ?? ''); ?>" placeholder="https://example.com" required/></label>
                        <label class="kv-edit-field"><span>Value</span><input type="text" name="headerValue" value="<?php echo htmlspecialchars($_h_value); ?>" autocomplete="off"/></label>
                        <div class="kv-edit-actions">
                            <button class="button-submit" type="submit">Save</button>
                        </div>
                    </form>
                </details>
                <form class="kv-delete" method="post" action="?action=delete-header">
                    <?php echo $_panel_return_html; ?>
                    <input type="hidden" name="name" value="<?php echo htmlspecialchars($_h_name); ?>"/>
                    <button class="button-icon" type="submit" title="Delete header" aria-label="Delete header <?php echo htmlspecialchars($_h_name); ?>">&times;</button>
                </form>
            </li>
<?php endforeach; ?>
        </ul>
<?php endif; ?>
        <p class="section-label">Add a header</p>
        <form class="kv-add" method="post" action="?action=add-header">
            <?php echo $_panel_return_html; ?>
            <input type="url" name="headerOrigin" placeholder="https://example.com" required/>
            <input type="text" name="headerAddName" placeholder="Accept-Language" pattern="[A-Za-z0-9-]+" autocomplete="off"/>
            <input type="text" name="headerAddValue" placeholder="en-GB,en;q=0.9" autocomplete="off"/>
            <button type="submit">Add</button>
        </form>
    </section>

    <?php if ($_panel_show_netchecks): ?>
    <section class="tab-panel" data-tab="ip">
        <p class="tab-help">Network identity for the current request. <strong>Client</strong> is who you appear as to this server; <strong>Outgoing</strong> is the local network interface used for outbound traffic; its public address may differ behind NAT. All data is collected locally via PHP built-ins — no external lookups, no API keys.</p>
        <div class="ipinfo-wrap" data-ipinfo-target>
            <div class="ipinfo-loading">Looking up IPs…</div>
        </div>
        <hr class="divider"/>
        <p class="section-label">Look up any IP</p>
        <form class="netcheck netcheck-solo" data-ipinfo-lookup autocomplete="off">
            <div class="netcheck-fields">
                <input type="text" name="ip" placeholder="1.1.1.1  or  2606:4700:4700::1111" required spellcheck="false" autocapitalize="off"/>
                <button class="button-submit" type="submit">Look up</button>
            </div>
            <pre class="netcheck-result" hidden></pre>
        </form>
    </section>

    <?php if ($_panel_diagnostics): ?>
    <section class="tab-panel" data-tab="port">
        <p class="tab-help">Test TCP reachability and measure connection latency. A single port (<code>443</code>), an inclusive range (<code>8000-8010</code>) or a comma list (<code>22,80,443,8000-8010</code>) — up to 128 ports per scan. Only public destinations are allowed; checks stop after 10 seconds.</p>
        <form class="netcheck netcheck-solo" data-netcheck="portcheck" autocomplete="off">
            <div class="netcheck-fields">
                <input type="text" name="host" placeholder="host.example.com" required spellcheck="false" autocapitalize="off"/>
                <input type="text" name="port" placeholder="443  or  8000-8010  or  22,80,443" pattern="[0-9,\-\s]+" required spellcheck="false" autocapitalize="off"/>
            </div>
            <button class="button-submit" type="submit">Check port</button>
            <pre class="netcheck-result" hidden></pre>
        </form>
    </section>

    <?php endif; ?>
    <section class="tab-panel" data-tab="dns">
        <p class="tab-help">Resolve DNS records via the server's resolver. A / AAAA / MX / TXT / NS / SOA / CAA / CNAME / SRV / ANY supported.</p>
        <form class="netcheck netcheck-solo" data-netcheck="dns" autocomplete="off">
            <div class="netcheck-fields">
                <input type="text" name="host" placeholder="example.com" required spellcheck="false" autocapitalize="off"/>
                <select name="type">
                    <option value="A">A</option>
                    <option value="AAAA">AAAA</option>
                    <option value="MX">MX</option>
                    <option value="TXT">TXT</option>
                    <option value="NS">NS</option>
                    <option value="SOA">SOA</option>
                    <option value="CAA">CAA</option>
                    <option value="CNAME">CNAME</option>
                    <option value="SRV">SRV</option>
                    <option value="ANY">ANY</option>
                </select>
            </div>
            <button class="button-submit" type="submit">Lookup</button>
            <pre class="netcheck-result" hidden></pre>
        </form>
    </section>
    <?php endif; ?>

    <?php if ($_panel_show_cert): ?>
    <section class="tab-panel" data-tab="cert">
        <p class="tab-help">Open an SSL/TLS handshake and inspect everything available: TLS versions the server accepts, the cipher negotiated per version, full certificate chain with every parsed extension, fingerprints, and the raw PEM blocks. All data comes from PHP's OpenSSL functions — no <code>openssl s_client</code> shell-out, no library.</p>
        <form class="netcheck netcheck-solo" data-netcheck="cert"<?php echo $_panel_cert_autorun ? ' data-autorun="1"' : ''; ?> autocomplete="off">
            <div class="netcheck-fields">
                <input type="text" name="host" placeholder="example.com" value="<?php echo htmlspecialchars($_panel_cert_host); ?>" required spellcheck="false" autocapitalize="off"/>
                <input type="number" name="port" placeholder="443" min="1" max="65535" value="<?php echo (int) $_panel_cert_port; ?>" required/>
            </div>
            <button class="button-submit" type="submit">Inspect cert</button>
            <div class="netcheck-result cert-result" hidden></div>
        </form>
    </section>
    <?php endif; ?>

    <?php if ($_panel_show_response): ?>
    <section class="tab-panel" data-tab="response">
        <p class="section-label">Request to upstream</p>
        <p class="tab-help">The HTTP request the proxy sent on your behalf for this URL.</p>
<?php if ($_panel_request_line !== ''): ?>
        <ul class="kv-list">
            <li class="kv-row kv-row-readonly">
                <div class="kv-card">
                    <div class="kv-card-readonly kv-card-status"><?php echo htmlspecialchars($_panel_request_line); ?></div>
                </div>
            </li>
<?php foreach ($_panel_request_pairs as $_rh): list($_rh_name, $_rh_value) = $_rh; ?>
            <li class="kv-row kv-row-readonly">
                <div class="kv-card">
                    <div class="kv-card-readonly">
                        <span class="kv-name"><?php echo htmlspecialchars($_rh_name); ?></span><span class="kv-sep">:</span><span class="kv-val"><?php echo htmlspecialchars($_rh_value); ?></span>
                    </div>
                </div>
            </li>
<?php endforeach; ?>
        </ul>
<?php else: ?>
        <ul class="kv-list"><li class="empty">No request captured</li></ul>
<?php endif; ?>

        <hr class="divider"/>
        <p class="section-label">Response from upstream</p>
        <p class="tab-help">Headers the upstream server sent back.</p>
<?php if (empty($_panel_response_pairs)): ?>
        <ul class="kv-list"><li class="empty">No response headers captured</li></ul>
<?php else: ?>
        <ul class="kv-list">
<?php foreach ($_panel_response_pairs as $_rh): list($_rh_name, $_rh_value) = $_rh; ?>
            <li class="kv-row kv-row-readonly">
                <div class="kv-card">
                    <div class="kv-card-readonly<?php echo $_rh_value === '' ? ' kv-card-status' : ''; ?>">
<?php if ($_rh_value === ''): ?>
                        <?php echo htmlspecialchars($_rh_name); ?>
<?php else: ?>
                        <span class="kv-name"><?php echo htmlspecialchars($_rh_name); ?></span><span class="kv-sep">:</span><span class="kv-val"><?php echo htmlspecialchars($_rh_value); ?></span>
<?php endif; ?>
                    </div>
                </div>
            </li>
<?php endforeach; ?>
        </ul>
<?php endif; ?>
    </section>
    <?php endif; ?>

    <?php
        $_cli_has_url = $_panel_cli_url !== '';
        // The proxy endpoint always comes from this deployment's public URL;
        // the selected upstream destination belongs only in the request payload.
        $_cli_endpoints = phproxy_cli_endpoints($_SERVER);
        $_cli_base = $_cli_endpoints['base'];
        // When there's no URL context (entry page) we still want to show how
        // to drive ?api=fetch — fall back to a clear placeholder URL.
        $_cli_url_eff     = $_cli_has_url ? $_panel_cli_url     : 'https://example.com/';
        $_cli_method_eff  = $_panel_cli_method !== '' ? $_panel_cli_method : 'GET';
        $_cli_headers_eff = $_cli_has_url ? $_panel_cli_headers : [['User-Agent', 'PHProxy/1.4.0']];
        $_cli_body_eff    = $_panel_cli_body;
        $_cli_api_url_eff = $_cli_endpoints['fetch'];
        $_cli_snippets = [
            'curl'   => [
                'label'  => 'curl',
                'direct' => phproxy_cli_curl_direct($_cli_url_eff, $_cli_method_eff, $_cli_headers_eff, $_cli_body_eff),
                'proxy'  => phproxy_cli_curl_proxy($_cli_api_url_eff, $_cli_url_eff, $_cli_method_eff, $_cli_headers_eff, [], $_cli_body_eff),
                'checks' => phproxy_cli_checks_curl($_cli_base),
            ],
            'php'    => [
                'label'  => 'PHP',
                'direct' => phproxy_cli_php_direct($_cli_url_eff, $_cli_method_eff, $_cli_headers_eff, $_cli_body_eff),
                'proxy'  => phproxy_cli_php_proxy($_cli_api_url_eff, $_cli_url_eff, $_cli_method_eff, $_cli_headers_eff, [], $_cli_body_eff),
                'checks' => phproxy_cli_checks_php($_cli_base),
            ],
            'python' => [
                'label'  => 'Python',
                'direct' => phproxy_cli_python_direct($_cli_url_eff, $_cli_method_eff, $_cli_headers_eff, $_cli_body_eff),
                'proxy'  => phproxy_cli_python_proxy($_cli_api_url_eff, $_cli_url_eff, $_cli_method_eff, $_cli_headers_eff, [], $_cli_body_eff),
                'checks' => phproxy_cli_checks_python($_cli_base),
            ],
            'js'     => [
                'label'  => 'JavaScript',
                'direct' => phproxy_cli_js_direct($_cli_url_eff, $_cli_method_eff, $_cli_headers_eff, $_cli_body_eff),
                'proxy'  => phproxy_cli_js_proxy($_cli_api_url_eff, $_cli_url_eff, $_cli_method_eff, $_cli_headers_eff, [], $_cli_body_eff),
                'checks' => phproxy_cli_checks_js($_cli_base),
            ],
            'go'     => [
                'label'  => 'Go',
                'direct' => phproxy_cli_go_direct($_cli_url_eff, $_cli_method_eff, $_cli_headers_eff, $_cli_body_eff),
                'proxy'  => phproxy_cli_go_proxy($_cli_api_url_eff, $_cli_url_eff, $_cli_method_eff, $_cli_headers_eff, [], $_cli_body_eff),
                'checks' => phproxy_cli_checks_go($_cli_base),
            ],
        ];
        $_cli_first = true;
    ?>
    <section class="tab-panel" data-tab="cli">
        <p class="tab-help">Use <strong>Via PHProxy</strong> to make the request from this proxy server. The destination URL appears in the JSON payload. <strong>Direct to destination</strong> sends the request from your own computer.</p>
        <p class="tab-help">Proxy endpoint: <code><?php echo htmlspecialchars($_cli_api_url_eff, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); ?></code><br/>Destination<?php echo $_cli_has_url ? '' : ' (example)'; ?>: <code><?php echo htmlspecialchars($_cli_url_eff, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); ?></code></p>
        <div class="cli-wrap">
<?php foreach ($_cli_snippets as $_cli_key => $_cli_meta): ?>
            <input type="radio" name="cli-tab" id="cli-tab-<?php echo $_cli_key; ?>"<?php echo $_cli_first ? ' checked' : ''; $_cli_first = false; ?>/>
<?php endforeach; ?>
            <nav class="cli-tabs">
<?php foreach ($_cli_snippets as $_cli_key => $_cli_meta): ?>
                <label for="cli-tab-<?php echo $_cli_key; ?>"><?php echo htmlspecialchars($_cli_meta['label']); ?></label>
<?php endforeach; ?>
            </nav>
<?php foreach ($_cli_snippets as $_cli_key => $_cli_meta): ?>
            <section class="cli-panel" data-cli="<?php echo $_cli_key; ?>">
                <div class="cli-variant">
                    <div class="cli-toolbar">
                        <span class="cli-variant-label">Via PHProxy server<?php echo $_cli_has_url ? '' : ' (example)'; ?></span>
                        <button type="button" class="button-cancel cli-copy" data-target="cli-snippet-<?php echo $_cli_key; ?>-proxy">Copy proxy command</button>
                    </div>
                    <pre id="cli-snippet-<?php echo $_cli_key; ?>-proxy" class="cli-snippet"><?php echo htmlspecialchars($_cli_meta['proxy']); ?></pre>
                </div>
                <div class="cli-variant">
                    <div class="cli-toolbar">
                        <span class="cli-variant-label">Direct to destination<?php echo $_cli_has_url ? '' : ' (example)'; ?></span>
                        <button type="button" class="button-cancel cli-copy" data-target="cli-snippet-<?php echo $_cli_key; ?>-direct">Copy direct command</button>
                    </div>
                    <pre id="cli-snippet-<?php echo $_cli_key; ?>-direct" class="cli-snippet"><?php echo htmlspecialchars($_cli_meta['direct']); ?></pre>
                </div>
                <div class="cli-variant">
                    <div class="cli-toolbar">
                        <span class="cli-variant-label">Port / DNS / SSL checks</span>
                        <button type="button" class="button-cancel cli-copy" data-target="cli-snippet-<?php echo $_cli_key; ?>-checks">Copy</button>
                    </div>
                    <pre id="cli-snippet-<?php echo $_cli_key; ?>-checks" class="cli-snippet"><?php echo htmlspecialchars($_cli_meta['checks']); ?></pre>
                </div>
            </section>
<?php endforeach; ?>
        </div>
    </section>

    <?php if ($_panel_show_network): ?>
    <section class="tab-panel" data-tab="network">
        <div class="tab-toolbar">
            <p class="tab-help">Every URL the proxy has fetched on your behalf, newest first. The current page is highlighted. <?php echo count($_panel_network); ?>/50 entries.</p>
            <form class="toolbar-toggle" method="post" action="?action=clear-network">
                <?php echo $_panel_return_html; ?>
                <button type="submit" class="button-ghost" title="Clear the Network log">Clear</button>
            </form>
        </div>
<?php if (empty($_panel_network)): ?>
        <ul class="kv-list"><li class="empty">No requests logged yet</li></ul>
<?php else: ?>
        <table class="net-table">
            <thead>
                <tr>
                    <th>URL</th>
                    <th>Method</th>
                    <th>Status</th>
                    <th>Type</th>
                    <th class="num">Size</th>
                    <th class="num">TTFB</th>
                    <th class="num">Time</th>
                </tr>
            </thead>
            <tbody>
<?php
$_net_rev = array_reverse($_panel_network);
foreach ($_net_rev as $_ne):
    $_is_current = $_ne['url'] === $_panel_net_current;
    $_status_class = 'st-other';
    if ($_ne['status'] >= 200 && $_ne['status'] < 300) $_status_class = 'st-2xx';
    elseif ($_ne['status'] >= 300 && $_ne['status'] < 400) $_status_class = 'st-3xx';
    elseif ($_ne['status'] >= 400 && $_ne['status'] < 500) $_status_class = 'st-4xx';
    elseif ($_ne['status'] >= 500) $_status_class = 'st-5xx';
?>
                <tr<?php echo $_is_current ? ' class="current"' : ''; ?>>
                    <td class="url" title="<?php echo htmlspecialchars($_ne['url']); ?>"><?php echo htmlspecialchars(mb_strimwidth($_ne['url'], 0, 78, '…')); ?></td>
                    <td class="method"><?php echo htmlspecialchars($_ne['method']); ?></td>
                    <td class="status <?php echo $_status_class; ?>"><?php echo (int) $_ne['status']; ?></td>
                    <td class="type"><?php echo htmlspecialchars($_ne['type']); ?></td>
                    <td class="num"><?php echo phproxy_fmt_size((int) $_ne['size']); ?></td>
                    <td class="num"><?php echo (int) $_ne['ttfb_ms']; ?> ms</td>
                    <td class="num"><?php echo (int) $_ne['duration_ms']; ?> ms</td>
                </tr>
<?php endforeach; ?>
            </tbody>
        </table>
<?php endif; ?>
    </section>
    <?php endif; ?>
</div>
<?php
}

// --- EMBEDDED STYLESHEETS (served via ?asset=...) ---

/**
 * Append a request to the Network tab log kept in $_SESSION. Kept to the
 * last 50 entries so the cookie-backed session file doesn't grow without
 * bound. Times are in float seconds (microtime(true)); rendering converts
 * them to ms.
 */
function phproxy_net_log(string $url, string $method, int $status, string $type, int $size, float $start, ?float $ttfb_t, float $end): void
{
    // Re-read while holding the lock; parallel downloads cannot overwrite
    // entries appended after their original request snapshot was taken.
    phproxy_state_open();
    if (!isset($_SESSION['phproxy_network']) || !is_array($_SESSION['phproxy_network'])) $_SESSION['phproxy_network'] = [];
    $ttfb_ms     = $ttfb_t !== null ? (int) (($ttfb_t - $start) * 1000) : 0;
    $duration_ms = (int) (($end - $start) * 1000);
    $_SESSION['phproxy_network'][] = [
        'ts'          => $start,
        'url'         => substr($url, 0, 2048),
        'method'      => substr($method, 0, 16),
        'status'      => $status,
        'type'        => $type !== '' ? substr($type, 0, 128) : 'unknown',
        'size'        => $size,
        'ttfb_ms'     => $ttfb_ms,
        'duration_ms' => $duration_ms,
    ];
    if (count($_SESSION['phproxy_network']) > 50) {
        $_SESSION['phproxy_network'] = array_slice($_SESSION['phproxy_network'], -50);
    }
    phproxy_state_close();
}

/**
 * Format a byte count for the Network table.
 */
function phproxy_fmt_size(int $bytes): string
{
    if ($bytes < 1024)     return $bytes . ' B';
    if ($bytes < 1048576)  return number_format($bytes / 1024, 1)    . ' KB';
    return                 number_format($bytes / 1048576, 1) . ' MB';
}

/**
 * CLI snippet helpers — build copy-pasteable code that replicates the
 * upstream request the proxy just made, in a handful of languages. The
 * snippets target the upstream directly (not the JSON API), so a user
 * can take the output and run it without going through PHProxy.
 *
 * Each helper takes the same shape: ($url, $method, $headers, $body) and
 * returns a single-string snippet. Quoting / escaping is per-language so
 * values containing apostrophes or backslashes survive the round-trip.
 */

/** Resolve CLI transport endpoints independently of the selected destination. */
function phproxy_cli_endpoints(array $server, ?string $configured = null): array
{
    $base = phproxy_public_script_url($server, $configured);
    return ['base' => $base, 'fetch' => $base . '?api=fetch'];
}

function phproxy_snip_shell(string $v): string {
    // POSIX-shell single-quoted: close, escaped quote, reopen — 'don'\''t' style
    return "'" . str_replace("'", "'\\''", $v) . "'";
}
function phproxy_snip_php(string $v): string {
    return "'" . str_replace(['\\', "'"], ['\\\\', "\\'"], $v) . "'";
}
function phproxy_snip_py(string $v): string {
    $escaped = str_replace(['\\', "'", "\n", "\r"], ['\\\\', "\\'", '\\n', '\\r'], $v);
    return "'" . $escaped . "'";
}
function phproxy_snip_js(string $v): string {
    $escaped = str_replace(['\\', "'", "\n", "\r"], ['\\\\', "\\'", '\\n', '\\r'], $v);
    return "'" . $escaped . "'";
}
function phproxy_snip_go(string $v): string {
    $escaped = str_replace(['\\', '"', "\n", "\r", "\t"], ['\\\\', '\\"', '\\n', '\\r', '\\t'], $v);
    return '"' . $escaped . '"';
}

/**
 * Strip headers that the JSON API rebuilds itself (so the "Via PHProxy"
 * snippets don't double them up). Also returns the Cookie header parsed
 * into a {name: value} dict for the api's `cookies` field.
 */
function phproxy_cli_split_for_api(array $headers): array
{
    $skip = ['host' => 1, 'connection' => 1, 'content-length' => 1, 'cookie' => 1];
    $filtered = [];
    $cookies  = [];
    foreach ($headers as $h) {
        [$name, $value] = $h;
        $lower = strtolower($name);
        if ($lower === 'cookie') {
            foreach (preg_split('/;\s*/', $value) as $pair) {
                if ($pair === '') continue;
                $eq = strpos($pair, '=');
                if ($eq === false) continue;
                $cookies[substr($pair, 0, $eq)] = substr($pair, $eq + 1);
            }
            continue;
        }
        if (isset($skip[$lower])) continue;
        $filtered[] = $h;
    }
    return ['headers' => $filtered, 'cookies' => $cookies];
}

/**
 * Build the JSON payload string the API expects. Pretty-printed so
 * snippets stay readable when shown in the panel.
 */
function phproxy_cli_api_payload(string $url, string $method, array $headers, array $cookies, string $body): string
{
    $payload = ['url' => $url];
    if ($method !== 'GET') $payload['method'] = $method;
    if (!empty($headers)) {
        $payload['headers'] = [];
        foreach ($headers as $h) {
            [$name, $value] = $h;
            $payload['headers'][$name] = $value;
        }
    }
    if (!empty($cookies)) $payload['cookies'] = $cookies;
    if ($body !== '')     $payload['body']    = $body;
    return json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}

/**
 * curl — direct fetch to upstream.
 */
function phproxy_cli_curl_direct(string $url, string $method, array $headers, string $body = ''): string
{
    $lines = ['curl -X ' . phproxy_snip_shell($method) . ' ' . phproxy_snip_shell($url) . ' \\'];
    foreach ($headers as $h) {
        [$name, $value] = $h;
        $lines[] = '  -H ' . phproxy_snip_shell($name . ': ' . $value) . ' \\';
    }
    if ($body !== '') {
        $lines[] = '  --data-binary ' . phproxy_snip_shell($body);
    } else {
        $lines[count($lines) - 1] = rtrim($lines[count($lines) - 1], ' \\');
    }
    return implode("\n", $lines);
}

/**
 * curl — POST the JSON envelope to /index.php?api=fetch so the upstream
 * fetch happens through PHProxy. Pipes the resulting JSON to jq for the
 * body field.
 */
function phproxy_cli_curl_proxy(string $api_url, string $upstream, string $method, array $headers, array $cookies, string $body = ''): string
{
    $split   = phproxy_cli_split_for_api($headers);
    $payload = phproxy_cli_api_payload($upstream, $method, $split['headers'], $cookies, $body);
    $out  = 'curl -X POST ' . phproxy_snip_shell($api_url) . ' \\' . "\n";
    $out .= '  -H ' . phproxy_snip_shell('Content-Type: application/json') . ' \\' . "\n";
    $out .= '  -d ' . phproxy_snip_shell($payload) . " \\\n";
    $out .= "  | jq -r .body";
    return $out;
}

/**
 * PHP cURL — direct.
 */
function phproxy_cli_php_direct(string $url, string $method, array $headers, string $body = ''): string
{
    $out  = "<?php\n";
    $out .= '$ch = curl_init(' . phproxy_snip_php($url) . ");\n";
    $out .= "curl_setopt_array(\$ch, [\n";
    $out .= '    CURLOPT_CUSTOMREQUEST  => ' . phproxy_snip_php($method) . ",\n";
    $out .= "    CURLOPT_RETURNTRANSFER => true,\n";
    $out .= "    CURLOPT_FOLLOWLOCATION => true,\n";
    if (!empty($headers)) {
        $out .= "    CURLOPT_HTTPHEADER     => [\n";
        foreach ($headers as $h) {
            [$name, $value] = $h;
            $out .= '        ' . phproxy_snip_php($name . ': ' . $value) . ",\n";
        }
        $out .= "    ],\n";
    }
    if ($body !== '') $out .= '    CURLOPT_POSTFIELDS     => ' . phproxy_snip_php($body) . ",\n";
    $out .= "]);\n";
    $out .= "\$response = curl_exec(\$ch);\n";
    $out .= "\$status   = curl_getinfo(\$ch, CURLINFO_HTTP_CODE);\n";
    $out .= "curl_close(\$ch);\n\n";
    $out .= "echo \$status, \"\\n\", \$response;";
    return $out;
}

/**
 * PHP cURL — via PHProxy JSON API.
 */
function phproxy_cli_php_proxy(string $api_url, string $upstream, string $method, array $headers, array $cookies, string $body = ''): string
{
    $split   = phproxy_cli_split_for_api($headers);
    $payload = [];
    $payload['url']     = $upstream;
    if ($method !== 'GET') $payload['method'] = $method;
    if (!empty($split['headers'])) {
        $payload['headers'] = [];
        foreach ($split['headers'] as $h) {
            [$name, $value] = $h;
            $payload['headers'][$name] = $value;
        }
    }
    if (!empty($split['cookies'])) $payload['cookies'] = $split['cookies'];
    if ($body !== '') $payload['body'] = $body;

    $out  = "<?php\n";
    $out .= "\$payload = " . var_export($payload, true) . ";\n\n";
    $out .= '$ch = curl_init(' . phproxy_snip_php($api_url) . ");\n";
    $out .= "curl_setopt_array(\$ch, [\n";
    $out .= "    CURLOPT_POST           => true,\n";
    $out .= "    CURLOPT_POSTFIELDS     => json_encode(\$payload),\n";
    $out .= "    CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],\n";
    $out .= "    CURLOPT_RETURNTRANSFER => true,\n";
    $out .= "]);\n";
    $out .= "\$envelope = json_decode(curl_exec(\$ch), true);\n";
    $out .= "curl_close(\$ch);\n\n";
    $out .= "echo \$envelope['status'], \"\\n\", \$envelope['body'];";
    return $out;
}

/**
 * Python — direct.
 */
function phproxy_cli_python_direct(string $url, string $method, array $headers, string $body = ''): string
{
    $out  = "import requests\n\n";
    $out .= 'response = requests.request(' . phproxy_snip_py($method) . ', ' . phproxy_snip_py($url) . ",\n";
    if (!empty($headers)) {
        $out .= "    headers={\n";
        foreach ($headers as $h) {
            [$name, $value] = $h;
            $out .= '        ' . phproxy_snip_py($name) . ': ' . phproxy_snip_py($value) . ",\n";
        }
        $out .= "    },\n";
    }
    if ($body !== '') $out .= '    data=' . phproxy_snip_py($body) . ",\n";
    $out .= "    allow_redirects=True,\n";
    $out .= ")\n\n";
    $out .= "print(response.status_code)\n";
    $out .= "print(response.text)";
    return $out;
}

/**
 * Python — via PHProxy JSON API.
 */
function phproxy_cli_python_proxy(string $api_url, string $upstream, string $method, array $headers, array $cookies, string $body = ''): string
{
    $split = phproxy_cli_split_for_api($headers);
    $out  = "import requests\n\n";
    $out .= "payload = {\n";
    $out .= '    "url":    ' . phproxy_snip_py($upstream) . ",\n";
    if ($method !== 'GET') {
        $out .= '    "method": ' . phproxy_snip_py($method) . ",\n";
    }
    if (!empty($split['headers'])) {
        $out .= "    \"headers\": {\n";
        foreach ($split['headers'] as $h) {
            [$name, $value] = $h;
            $out .= '        ' . phproxy_snip_py($name) . ': ' . phproxy_snip_py($value) . ",\n";
        }
        $out .= "    },\n";
    }
    if (!empty($split['cookies'])) {
        $out .= "    \"cookies\": {\n";
        foreach ($split['cookies'] as $cn => $cv) {
            $out .= '        ' . phproxy_snip_py($cn) . ': ' . phproxy_snip_py($cv) . ",\n";
        }
        $out .= "    },\n";
    }
    if ($body !== '') $out .= '    "body":   ' . phproxy_snip_py($body) . ",\n";
    $out .= "}\n\n";
    $out .= 'envelope = requests.post(' . phproxy_snip_py($api_url) . ", json=payload).json()\n";
    $out .= "print(envelope['status'])\n";
    $out .= "print(envelope['body'])";
    return $out;
}

/**
 * JavaScript — direct.
 */
function phproxy_cli_js_direct(string $url, string $method, array $headers, string $body = ''): string
{
    $out = 'const response = await fetch(' . phproxy_snip_js($url) . ", {\n";
    $out .= '    method: ' . phproxy_snip_js($method) . ",\n";
    if (!empty($headers)) {
        $out .= "    headers: {\n";
        foreach ($headers as $h) {
            [$name, $value] = $h;
            $out .= '        ' . phproxy_snip_js($name) . ': ' . phproxy_snip_js($value) . ",\n";
        }
        $out .= "    },\n";
    }
    if ($body !== '') $out .= '    body: ' . phproxy_snip_js($body) . ",\n";
    $out .= "});\n";
    $out .= "console.log(response.status, await response.text());";
    return $out;
}

/**
 * JavaScript — via PHProxy JSON API.
 */
function phproxy_cli_js_proxy(string $api_url, string $upstream, string $method, array $headers, array $cookies, string $body = ''): string
{
    $split = phproxy_cli_split_for_api($headers);
    $out  = "const payload = {\n";
    $out .= '    url: ' . phproxy_snip_js($upstream) . ",\n";
    if ($method !== 'GET') $out .= '    method: ' . phproxy_snip_js($method) . ",\n";
    if (!empty($split['headers'])) {
        $out .= "    headers: {\n";
        foreach ($split['headers'] as $h) {
            [$name, $value] = $h;
            $out .= '        ' . phproxy_snip_js($name) . ': ' . phproxy_snip_js($value) . ",\n";
        }
        $out .= "    },\n";
    }
    if (!empty($split['cookies'])) {
        $out .= "    cookies: {\n";
        foreach ($split['cookies'] as $cn => $cv) {
            $out .= '        ' . phproxy_snip_js($cn) . ': ' . phproxy_snip_js($cv) . ",\n";
        }
        $out .= "    },\n";
    }
    if ($body !== '') $out .= '    body: ' . phproxy_snip_js($body) . ",\n";
    $out .= "};\n\n";
    $out .= 'const r = await fetch(' . phproxy_snip_js($api_url) . ", {\n";
    $out .= "    method: 'POST',\n";
    $out .= "    headers: { 'Content-Type': 'application/json' },\n";
    $out .= "    body: JSON.stringify(payload),\n";
    $out .= "});\n";
    $out .= "const envelope = await r.json();\n";
    $out .= "console.log(envelope.status, envelope.body);";
    return $out;
}

/**
 * Go — direct.
 */
function phproxy_cli_go_direct(string $url, string $method, array $headers, string $body = ''): string
{
    $out  = "package main\n\n";
    $out .= "import (\n";
    $out .= "    \"fmt\"\n    \"io\"\n    \"net/http\"\n";
    if ($body !== '') $out .= "    \"strings\"\n";
    $out .= ")\n\n";
    $out .= "func main() {\n";
    if ($body !== '') {
        $out .= '    req, _ := http.NewRequest(' . phproxy_snip_go($method) . ', ' . phproxy_snip_go($url) . ', strings.NewReader(' . phproxy_snip_go($body) . "))\n";
    } else {
        $out .= '    req, _ := http.NewRequest(' . phproxy_snip_go($method) . ', ' . phproxy_snip_go($url) . ", nil)\n";
    }
    foreach ($headers as $h) {
        [$name, $value] = $h;
        $out .= '    req.Header.Set(' . phproxy_snip_go($name) . ', ' . phproxy_snip_go($value) . ")\n";
    }
    $out .= "\n";
    $out .= "    resp, err := (&http.Client{}).Do(req)\n";
    $out .= "    if err != nil { panic(err) }\n";
    $out .= "    defer resp.Body.Close()\n";
    $out .= "    body, _ := io.ReadAll(resp.Body)\n";
    $out .= "    fmt.Println(resp.StatusCode, string(body))\n";
    $out .= "}";
    return $out;
}

/**
 * Go — via PHProxy JSON API.
 */
function phproxy_cli_go_proxy(string $api_url, string $upstream, string $method, array $headers, array $cookies, string $body = ''): string
{
    $split = phproxy_cli_split_for_api($headers);
    $hdr_lines = '';
    foreach ($split['headers'] as $h) {
        [$name, $value] = $h;
        $hdr_lines .= '            ' . phproxy_snip_go($name) . ': ' . phproxy_snip_go($value) . ",\n";
    }
    $cookie_lines = '';
    foreach ($split['cookies'] as $cn => $cv) {
        $cookie_lines .= '            ' . phproxy_snip_go($cn) . ': ' . phproxy_snip_go($cv) . ",\n";
    }
    $body_field = $body !== '' ? '        "body":    ' . phproxy_snip_go($body) . ",\n" : '';
    $method_field = $method !== 'GET' ? '        "method":  ' . phproxy_snip_go($method) . ",\n" : '';

    $out  = "package main\n\n";
    $out .= "import (\n";
    $out .= "    \"bytes\"\n    \"encoding/json\"\n    \"fmt\"\n    \"net/http\"\n";
    $out .= ")\n\n";
    $out .= "func main() {\n";
    $out .= "    payload := map[string]any{\n";
    $out .= '        "url":     ' . phproxy_snip_go($upstream) . ",\n";
    $out .= $method_field;
    if ($hdr_lines !== '') {
        $out .= "        \"headers\": map[string]string{\n";
        $out .= $hdr_lines;
        $out .= "        },\n";
    }
    if ($cookie_lines !== '') {
        $out .= "        \"cookies\": map[string]string{\n";
        $out .= $cookie_lines;
        $out .= "        },\n";
    }
    $out .= $body_field;
    $out .= "    }\n";
    $out .= "    j, _ := json.Marshal(payload)\n";
    $out .= '    resp, err := http.Post(' . phproxy_snip_go($api_url) . ', "application/json", bytes.NewReader(j))' . "\n";
    $out .= "    if err != nil { panic(err) }\n";
    $out .= "    defer resp.Body.Close()\n\n";
    $out .= "    var envelope struct{ Status int `json:\"status\"`; Body string `json:\"body\"` }\n";
    $out .= "    json.NewDecoder(resp.Body).Decode(&envelope)\n";
    $out .= "    fmt.Println(envelope.Status, envelope.Body)\n";
    $out .= "}";
    return $out;
}

/**
 * CLI snippet helpers for the network-check endpoints. Each returns a
 * single multi-block string with examples for portcheck / dns / cert.
 * $base must be the proxy's scheme+host+path (e.g. https://proxy/index.php).
 */
function phproxy_cli_checks_curl(string $base): string
{
    $u_port_one   = $base . '?api=portcheck&host=example.com&port=443';
    $u_port_range = $base . '?api=portcheck&host=example.com&port=8000-8010';
    $u_port_list  = $base . '?api=portcheck&host=example.com&port=22,80,443,8000-8010';
    $u_dns        = $base . '?api=dns&host=example.com&type=A';
    $u_cert       = $base . '?api=cert&host=example.com&port=443';
    $u_port_stream = $base . '?api=portcheck&host=example.com&port=22-30&stream=1';
    $u_ip_self     = $base . '?api=ipinfo';
    $u_ip_lookup   = $base . '?api=ipinfo&ip=1.1.1.1';
    return "# IP info — client + server + outgoing IP + reverse DNS + request headers\n"
         . 'curl ' . phproxy_snip_shell($u_ip_self) . "\n\n"
         . "# IP info — reverse DNS for any IP (IPv4 or IPv6)\n"
         . 'curl ' . phproxy_snip_shell($u_ip_lookup) . "\n\n"
         . "# Port check — single port\n"
         . 'curl ' . phproxy_snip_shell($u_port_one) . "\n\n"
         . "# Port check — inclusive range\n"
         . 'curl ' . phproxy_snip_shell($u_port_range) . "\n\n"
         . "# Port check — comma-list, mixed with ranges (max 128 ports)\n"
         . 'curl ' . phproxy_snip_shell($u_port_list) . "\n\n"
         . "# Port check — streaming (NDJSON, one line per port as it completes)\n"
         . 'curl -N ' . phproxy_snip_shell($u_port_stream) . "\n\n"
         . "# DNS lookup — A / AAAA / MX / TXT / NS / SOA / CAA / CNAME / SRV / ANY\n"
         . 'curl ' . phproxy_snip_shell($u_dns) . "\n\n"
         . "# SSL handshake + cert chain inspection\n"
         . 'curl ' . phproxy_snip_shell($u_cert);
}

function phproxy_cli_checks_php(string $base): string
{
    $out  = "<?php\n";
    $out .= '$base = ' . phproxy_snip_php($base) . ";\n\n";
    $out .= "// IP info — me, the server, the server's outgoing IP + reverse DNS\n";
    $out .= "\$ipinfo = json_decode(file_get_contents(\$base . '?api=ipinfo'), true);\n";
    $out .= "printf(\"client:   %s   %s\\n\",   \$ipinfo['client']['ip'],   \$ipinfo['client']['reverse']   ?? '');\n";
    $out .= "printf(\"outgoing: %s   %s\\n\", \$ipinfo['outgoing']['ip'], \$ipinfo['outgoing']['reverse'] ?? '');\n\n";
    $out .= "// Port check — accepts: 443  |  8000-8010  |  22,80,443,8000-8010  (max 128)\n";
    $out .= "\$port = json_decode(file_get_contents(\$base . '?api=portcheck&host=example.com&port=8000-8010'), true);\n";
    $out .= "foreach (\$port['results'] as \$r) {\n";
    $out .= "    printf(\"%5d  %s  %d ms\\n\", \$r['port'], \$r['reachable'] ? 'OPEN  ' : 'CLOSED', \$r['latency_ms']);\n";
    $out .= "}\n\n";
    $out .= "// DNS lookup\n";
    $out .= "\$dns = json_decode(file_get_contents(\$base . '?api=dns&host=example.com&type=A'), true);\n";
    $out .= "print_r(\$dns);\n\n";
    $out .= "// SSL cert inspect\n";
    $out .= "\$cert = json_decode(file_get_contents(\$base . '?api=cert&host=example.com&port=443'), true);\n";
    $out .= "print_r(\$cert);";
    return $out;
}

function phproxy_cli_checks_python(string $base): string
{
    $out  = "import requests\n\n";
    $out .= 'base = ' . phproxy_snip_php($base) . "\n\n";
    $out .= "# IP info — me, the server, the server's outgoing IP + reverse DNS\n";
    $out .= "ip = requests.get(base, params={'api': 'ipinfo'}).json()\n";
    $out .= "print(f\"client:   {ip['client']['ip']}   {ip['client'].get('reverse','')}\")\n";
    $out .= "print(f\"outgoing: {ip['outgoing']['ip']}   {ip['outgoing'].get('reverse','')}\")\n\n";
    $out .= "# Port check — accepts: 443  |  8000-8010  |  22,80,443,8000-8010  (max 128)\n";
    $out .= "scan = requests.get(base, params={'api': 'portcheck', 'host': 'example.com', 'port': '8000-8010'}).json()\n";
    $out .= "for r in scan['results']:\n";
    $out .= "    print(f\"{r['port']:>5}  {'OPEN  ' if r['reachable'] else 'CLOSED'}  {r['latency_ms']} ms\")\n\n";
    $out .= "# DNS lookup\n";
    $out .= "print(requests.get(base, params={'api': 'dns', 'host': 'example.com', 'type': 'A'}).json())\n\n";
    $out .= "# SSL cert inspect\n";
    $out .= "print(requests.get(base, params={'api': 'cert', 'host': 'example.com', 'port': 443}).json())";
    return $out;
}

function phproxy_cli_checks_js(string $base): string
{
    $b = phproxy_snip_php($base);
    return "const base = $b;\n\n"
         . "// IP info — me, the server, the server's outgoing IP + reverse DNS\n"
         . "const ip = await fetch(base + '?api=ipinfo').then(r => r.json());\n"
         . "console.log(`client:   \${ip.client.ip}   \${ip.client.reverse ?? ''}`);\n"
         . "console.log(`outgoing: \${ip.outgoing.ip}   \${ip.outgoing.reverse ?? ''}`);\n\n"
         . "// Port check — accepts: 443  |  8000-8010  |  22,80,443,8000-8010  (max 128)\n"
         . "const scan = await fetch(base + '?api=portcheck&host=example.com&port=8000-8010').then(r => r.json());\n"
         . "for (const r of scan.results) {\n"
         . "    console.log(`\${String(r.port).padStart(5)}  \${r.reachable ? 'OPEN  ' : 'CLOSED'}  \${r.latency_ms} ms`);\n"
         . "}\n\n"
         . "// DNS lookup\n"
         . "const dns = await fetch(base + '?api=dns&host=example.com&type=A').then(r => r.json());\n"
         . "console.log(dns);\n\n"
         . "// SSL cert inspect\n"
         . "const cert = await fetch(base + '?api=cert&host=example.com&port=443').then(r => r.json());\n"
         . "console.log(cert);";
}

function phproxy_cli_checks_go(string $base): string
{
    $b = phproxy_snip_go($base);
    $out  = "package main\n\n";
    $out .= "import (\n";
    $out .= "    \"encoding/json\"\n";
    $out .= "    \"fmt\"\n";
    $out .= "    \"io\"\n";
    $out .= "    \"net/http\"\n";
    $out .= ")\n\n";
    $out .= "func get(url string) map[string]any {\n";
    $out .= "    r, _ := http.Get(url)\n";
    $out .= "    defer r.Body.Close()\n";
    $out .= "    b, _ := io.ReadAll(r.Body)\n";
    $out .= "    var m map[string]any\n";
    $out .= "    json.Unmarshal(b, &m)\n";
    $out .= "    return m\n";
    $out .= "}\n\n";
    $out .= "func main() {\n";
    $out .= '    base := ' . $b . "\n\n";
    $out .= "    // IP info — me, the server, the server's outgoing IP + reverse DNS\n";
    $out .= "    fmt.Println(get(base + \"?api=ipinfo\"))\n\n";
    $out .= "    // Port check — accepts: 443  |  8000-8010  |  22,80,443,8000-8010  (max 128)\n";
    $out .= "    scan := get(base + \"?api=portcheck&host=example.com&port=8000-8010\")\n";
    $out .= "    for _, r := range scan[\"results\"].([]any) {\n";
    $out .= "        rr := r.(map[string]any)\n";
    $out .= "        status := \"CLOSED\"\n";
    $out .= "        if rr[\"reachable\"].(bool) { status = \"OPEN  \" }\n";
    $out .= "        fmt.Printf(\"%5.0f  %s  %.0f ms\\n\", rr[\"port\"], status, rr[\"latency_ms\"])\n";
    $out .= "    }\n\n";
    $out .= "    fmt.Println(get(base + \"?api=dns&host=example.com&type=A\"))\n";
    $out .= "    fmt.Println(get(base + \"?api=cert&host=example.com&port=443\"))\n";
    $out .= "}";
    return $out;
}

/**
 * JSON API: fetch a URL on behalf of the caller with the given headers,
 * cookies and (optional) body. Pure stream_socket_client; no curl needed.
 * Returns a structured array ready for json_encode().
 */
function phproxy_api_fetch(array $req): array
{
    $started = microtime(true);
    $url = is_string($req['url'] ?? null) ? $req['url'] : '';
    $deadline = $started + max(1, min(30, (int) ($req['timeout'] ?? 30)));
    $limit = max(1, min(16 * 1024 * 1024, (int) ($req['max_response_bytes'] ?? 8 * 1024 * 1024)));
    $redirects = [];
    $sock = null;
    try {
        if (isset($req['method']) && !is_string($req['method'])) throw new InvalidArgumentException('Method must be a string');
        if (($req['verify_ssl'] ?? true) !== true) throw new InvalidArgumentException('TLS certificate verification cannot be disabled');
        $method = strtoupper($req['method'] ?? 'GET');
        if (!in_array($method, ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'], true)) {
            throw new InvalidArgumentException('Unsupported HTTP method');
        }
        $headers = phproxy_prepare_request_headers($req['headers'] ?? []);
        $cookies = $req['cookies'] ?? [];
        if (!is_array($cookies)) throw new InvalidArgumentException('Cookies must be an object');
        $cookie_parts = [];
        foreach ($cookies as $name => $value) {
            if (!is_string($name) || !preg_match('/^[!#$%&\'*+.^_`|~0-9A-Za-z-]+$/D', $name) || !is_scalar($value)) {
                throw new InvalidArgumentException('Invalid cookie');
            }
            $value = (string) $value;
            if (preg_match('/[\x00-\x20\x7f;,]/', $value)) throw new InvalidArgumentException('Invalid cookie value');
            $cookie_parts[] = $name . '=' . $value;
        }
        if ($cookie_parts) {
            if (isset($headers['cookie'])) throw new InvalidArgumentException('Specify cookies in only one field');
            $headers['cookie'] = implode('; ', $cookie_parts);
        }
        $body = $req['body'] ?? '';
        if (!is_string($body) || strlen($body) > 2 * 1024 * 1024) throw new InvalidArgumentException('Request body exceeds 2 MiB or is not a string');
        if ($body !== '' && in_array($method, ['GET', 'HEAD'], true)) throw new InvalidArgumentException('This method does not accept a body');
        $follow = !empty($req['follow_redirects']);
        $max_redirects = max(0, min(5, (int) ($req['max_redirects'] ?? 5)));
        while (true) {
            $target = phproxy_parse_http_url($url);
            $sock = phproxy_open_public_socket($target['host'], $target['port'], $target['scheme'] === 'https', $deadline);
            $request_headers = $headers;
            $request_headers['host'] = $target['authority'];
            $request_headers['connection'] = 'close';
            $request_headers['accept'] ??= '*/*';
            $request_headers['user-agent'] ??= 'PHProxy/1.4.0';
            $request_headers['accept-encoding'] ??= 'gzip, deflate';
            if ($body !== '' || in_array($method, ['POST', 'PUT', 'PATCH'], true)) {
                $request_headers['content-length'] = (string) strlen($body);
                $request_headers['content-type'] ??= 'application/octet-stream';
            }
            $wire = $method . ' ' . $target['path'] . " HTTP/1.1\r\n";
            foreach ($request_headers as $name => $value) {
                if ($name === 'user-agent' && $value === '') continue;
                $wire .= $name . ': ' . $value . "\r\n";
            }
            if (strlen($wire) > 32768) throw new InvalidArgumentException('Request headers exceed 32 KiB');
            phproxy_stream_write_all($sock, $wire . "\r\n" . $body, $deadline);
            $response = phproxy_read_http_response($sock, $method, $deadline, $limit);
            fclose($sock);
            $sock = null;
            $status = $response['status'];
            if ($follow && in_array($status, [301, 302, 303, 307, 308], true) && isset($response['headers']['location'])) {
                if (count($redirects) >= $max_redirects) throw new RuntimeException('Too many redirects');
                $next_url = phproxy_resolve_http_location($url, $response['headers']['location']);
                $next = phproxy_parse_http_url($next_url);
                [$method, $headers, $body] = phproxy_redirect_request($target, $next, $status, $method, $headers, $body);
                $redirects[] = ['from' => $url, 'status' => $status, 'to' => $next_url];
                $url = $next_url;
                continue;
            }
            $response['ok'] = true;
            $response['url'] = $url;
            $response['redirects'] = $redirects;
            $response['duration_ms'] = (int) ((microtime(true) - $started) * 1000);
            return $response;
        }
    } catch (Throwable $e) {
        if (is_resource($sock)) fclose($sock);
        $invalid = $e instanceof InvalidArgumentException;
        $timeout = $e->getCode() === 408;
        return ['ok' => false, 'error' => $e->getMessage(), 'error_code' => $invalid ? 'invalid_request' : ($timeout ? 'timeout' : 'upstream_error'),
            'http_status' => $invalid ? 400 : ($timeout ? 504 : 502), 'url' => $url, 'redirects' => $redirects];
    }
}

/** Decode a complete chunked body, rejecting incomplete framing. */
function phproxy_api_decode_chunked(string $body): string
{
    $stream = fopen('php://temp', 'w+b');
    fwrite($stream, $body);
    rewind($stream);
    try {
        return phproxy_read_chunked_body($stream, microtime(true) + 5, 8 * 1024 * 1024);
    } finally {
        fclose($stream);
    }
}

/**
 * Shared JS asset — defines window.phproxyFmtCertHtml(json) so both the
 * entry-form script and the inline-panel script can render the rich
 * cert detail HTML without duplicating ~100 lines of logic.
 */
function phproxy_netcheck_js(): string {
    return <<<'PHPROXY_NETCHECK_JS'
(function () {
    function esc(s) {
        return String(s == null ? '' : s).replace(/[&<>]/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c];
        });
    }
    function kvGrid(rows) {
        var html = '';
        rows.forEach(function (pair) {
            var k = pair[0], v = pair[1];
            if (v == null || v === '') return;
            html += '<div class="cert-kv-k">' + esc(k) + '</div><div class="cert-kv-v">' + esc(v) + '</div>';
        });
        return html ? '<div class="cert-kv">' + html + '</div>' : '';
    }
    function dnGrid(parts) {
        if (!parts || typeof parts !== 'object') return '';
        var html = '';
        Object.keys(parts).forEach(function (k) {
            var v = parts[k];
            if (Array.isArray(v)) v = v.join(' + ');
            if (v === '' || v == null) return;
            html += '<div class="cert-kv-k">' + esc(k) + '</div><div class="cert-kv-v">' + esc(String(v)) + '</div>';
        });
        return html ? '<div class="cert-kv">' + html + '</div>' : '';
    }
    function fmtKey(c) {
        if (!c.key_type) return '';
        return c.key_type + ' ' + c.key_bits + (c.key_curve ? ' (' + c.key_curve + ')' : '');
    }
    function fmtStatus(days) {
        if (days == null) return '';
        if (days < 0)  return '<span class="cert-status err">EXPIRED ' + Math.abs(days) + 'd ago</span>';
        if (days < 30) return '<span class="cert-status warn">expires in ' + days + 'd</span>';
        return '<span class="cert-status ok">expires in ' + days + 'd</span>';
    }
    function copyBtn(target) {
        return '<button type="button" class="button-cancel cli-copy" data-target="' + target + '">Copy</button>';
    }
    function renderCertCard(c, i, isLeaf) {
        var id   = 'cert-' + Math.random().toString(36).slice(2, 8) + '-' + i;
        var role = isLeaf
            ? 'leaf'
            : (c.subject === c.issuer_dn || c.subject_cn === c.issuer_cn ? 'root' : 'intermediate');
        var title = '<span class="cert-role">' + role + '</span> ' +
                    '<strong>' + esc(c.subject_cn || c.subject || '?') + '</strong>' +
                    ' <span class="cert-arrow">←</span> ' + esc(c.issuer_cn || '?') +
                    '   ' + fmtStatus(c.days_left);

        var coreRows = [
            ['Version',             'X.509 v' + (c.version || '?')],
            ['Serial (hex)',        c.serial_hex],
            ['Serial (decimal)',    c.serial_dec],
            ['Valid from',          c.valid_from],
            ['Valid to',            c.valid_to],
            ['Signature algorithm', c.sig_algorithm + (c.sig_algorithm_long && c.sig_algorithm_long !== c.sig_algorithm ? ' (' + c.sig_algorithm_long + ')' : '')],
            ['Public key',          fmtKey(c)],
            ['SAN',                 (c.san || []).join(', ')],
        ];

        var extHtml = '';
        if (c.extensions && Object.keys(c.extensions).length) {
            var pairs = '';
            Object.keys(c.extensions).forEach(function (k) {
                pairs += '<div class="cert-ext-k">' + esc(k) + '</div><div class="cert-ext-v"><pre>' + esc(String(c.extensions[k])) + '</pre></div>';
            });
            extHtml = '<h5>Extensions (' + Object.keys(c.extensions).length + ')</h5><div class="cert-ext">' + pairs + '</div>';
        }

        var fp = c.fingerprints || {};
        var fpRows = '';
        ['sha256', 'sha1', 'md5'].forEach(function (k) {
            if (fp[k]) fpRows += '<div class="cert-kv-k">' + k.toUpperCase() + '</div><div class="cert-kv-v cert-fp">' + esc(fp[k]) + '</div>';
        });
        var fpBlock = fpRows ? '<h5>Fingerprints</h5><div class="cert-kv">' + fpRows + '</div>' : '';

        var pubId = id + '-pubkey';
        var pemId = id + '-pem';
        var pubBlock = c.public_key_pem
            ? '<details class="cert-raw"><summary>Public key (PEM) ' + copyBtn(pubId) + '</summary><pre id="' + pubId + '" class="cert-pem">' + esc(c.public_key_pem) + '</pre></details>'
            : '';
        var pemBlock = c.pem
            ? '<details class="cert-raw"><summary>Certificate (PEM) ' + copyBtn(pemId) + '</summary><pre id="' + pemId + '" class="cert-pem">' + esc(c.pem) + '</pre></details>'
            : '';

        return '<details class="cert-card"' + (isLeaf ? ' open' : '') + '>' +
                 '<summary><span class="cert-idx">' + i + '</span> ' + title + '</summary>' +
                 '<div class="cert-body">' +
                   '<h5>Subject</h5>' + dnGrid(c.subject_parts) +
                   '<h5>Issuer</h5>'  + dnGrid(c.issuer_parts) +
                   '<h5>Details</h5>' + kvGrid(coreRows) +
                   extHtml +
                   fpBlock +
                   pubBlock + pemBlock +
                 '</div>' +
               '</details>';
    }
    window.phproxyFmtCertHtml = function (j) {
        var N = j.negotiated || {};
        var probe = '';
        if (j.tls_versions && j.tls_versions.length) {
            probe = '<table class="tls-probes">';
            j.tls_versions.forEach(function (v) {
                if (v.supported) {
                    probe += '<tr class="ok"><td class="ver">' + esc(v.version) + '</td><td>✓</td>' +
                             '<td>' + esc(v.cipher_name || '') + '</td>' +
                             '<td>' + (v.cipher_bits ? v.cipher_bits + '-bit' : '') + '</td>' +
                             '<td>' + (v.latency_ms || 0) + ' ms</td></tr>';
                } else {
                    probe += '<tr class="err"><td class="ver">' + esc(v.version) + '</td><td>✗</td>' +
                             '<td colspan="3">' + esc(v.error || 'unsupported') + '</td></tr>';
                }
            });
            probe += '</table>';
        }
        var top =
            '<div class="cert-top">' +
              '<div class="cert-top-line"><strong>' + esc(j.host) + ':' + j.port + '</strong>' +
                ' <span class="cert-time">' + (j.duration_ms || 0) + ' ms</span></div>' +
              '<div class="cert-top-neg">negotiated&nbsp;&nbsp;' +
                '<strong>' + esc(N.protocol || '?') + '</strong>&nbsp;&nbsp;' +
                esc(N.cipher_name || '?') +
                (N.cipher_bits ? '&nbsp;&nbsp;(' + N.cipher_bits + '-bit)' : '') +
              '</div>' +
              probe +
            '</div>';
        var chain = '<h4 class="cert-chain-title">Certificate chain (' + (j.chain_length || (j.chain || []).length) + ')</h4>';
        (j.chain || [j.leaf]).forEach(function (c, i) { chain += renderCertCard(c, i, i === 0); });
        return top + chain;
    };

    // Reusable copy-button wiring for any container that has just been
    // populated with .cli-copy buttons (e.g. cert PEM blocks).
    window.phproxyBindCertCopy = function (container) {
        container.querySelectorAll('.cli-copy').forEach(function (btn) {
            if (btn.dataset.bound) return;
            btn.dataset.bound = '1';
            btn.addEventListener('click', function (ev) {
                ev.preventDefault();
                ev.stopPropagation();
                var t = document.getElementById(btn.dataset.target);
                if (!t) return;
                var done = function () { var o = btn.textContent; btn.textContent = 'Copied!'; setTimeout(function () { btn.textContent = o; }, 1500); };
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(t.textContent).then(done, done);
                } else {
                    var ta = document.createElement('textarea');
                    ta.value = t.textContent;
                    document.body.appendChild(ta);
                    ta.select();
                    try { document.execCommand('copy'); done(); } catch (e) {}
                    document.body.removeChild(ta);
                }
            });
        });
    };
})();
PHPROXY_NETCHECK_JS;
}

function phproxy_index_css(): string {
    return <<<'PHPROXY_INDEX_CSS'
:root {
    --bg: #f4f5f7;
    --surface: #ffffff;
    --surface-2: #f8fafc;
    --border: #e2e6ec;
    --border-strong: #cbd5e1;
    --text: #0f172a;
    --text-muted: #64748b;
    --accent: #2563eb;
    --accent-hover: #1d4ed8;
    --accent-soft: #dbeafe;
    --accent-ring: rgba(37, 99, 235, .18);
    --danger: #ef4444;
    --danger-soft: #fee2e2;
    --warning: #f59e0b;
    --warning-soft: #fef3c7;
    --success: #10b981;
    --success-soft: #d1fae5;
    --radius: 10px;
    --radius-sm: 6px;
    --shadow: 0 10px 15px -3px rgba(15, 23, 42, .06), 0 4px 6px -4px rgba(15, 23, 42, .04);
    --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    --font-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Monaco, Consolas, monospace;
    color-scheme: light;
}

@media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) {
        --bg: #0b1220;
        --surface: #131c2e;
        --surface-2: #1a2438;
        --border: #2a374e;
        --border-strong: #3b4a66;
        --text: #f1f5f9;
        --text-muted: #94a3b8;
        --accent: #60a5fa;
        --accent-hover: #93c5fd;
        --accent-soft: #1e3a8a;
        --accent-ring: rgba(96, 165, 250, .25);
        --danger: #f87171;
        --danger-soft: #7f1d1d;
        --warning: #fbbf24;
        --warning-soft: #78350f;
        --success: #34d399;
        --success-soft: #064e3b;
        --shadow: 0 10px 15px -3px rgba(0, 0, 0, .4), 0 4px 6px -4px rgba(0, 0, 0, .25);
        color-scheme: dark;
    }
}

:root[data-theme="dark"] {
    --bg: #0b1220;
    --surface: #131c2e;
    --surface-2: #1a2438;
    --border: #2a374e;
    --border-strong: #3b4a66;
    --text: #f1f5f9;
    --text-muted: #94a3b8;
    --accent: #60a5fa;
    --accent-hover: #93c5fd;
    --accent-soft: #1e3a8a;
    --accent-ring: rgba(96, 165, 250, .25);
    --danger: #f87171;
    --danger-soft: #7f1d1d;
    --warning: #fbbf24;
    --warning-soft: #78350f;
    --success: #34d399;
    --success-soft: #064e3b;
    --shadow: 0 10px 15px -3px rgba(0, 0, 0, .4), 0 4px 6px -4px rgba(0, 0, 0, .25);
    color-scheme: dark;
}

* { box-sizing: border-box; }

html, body { margin: 0; padding: 0; }

body {
    background: var(--bg);
    color: var(--text);
    font: 400 16px/1.5 var(--font);
    -webkit-font-smoothing: antialiased;
}

.page {
    width: 100%;
    max-width: 880px;
    margin: 32px auto;
    padding: 0 20px;
}

.appbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 20px;
}

.appbar h1 {
    margin: 0;
    color: var(--text);
    font-size: 22px;
    font-weight: 700;
    letter-spacing: -.01em;
}

.appbar h1 .dot { color: var(--accent); }

.theme-toggle {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 36px;
    height: 36px;
    padding: 0;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    color: var(--text-muted);
    cursor: pointer;
    transition: background-color .15s, color .15s, border-color .15s;
}

.theme-toggle:hover,
.theme-toggle:focus-visible {
    background: var(--surface-2);
    color: var(--text);
    border-color: var(--border-strong);
    outline: none;
}

.theme-toggle svg { width: 18px; height: 18px; display: block; }
.theme-toggle .icon-moon { display: none; }
.theme-toggle .icon-sun { display: block; }
:root[data-theme="dark"] .theme-toggle .icon-moon { display: block; }
:root[data-theme="dark"] .theme-toggle .icon-sun { display: none; }
@media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) .theme-toggle .icon-moon { display: block; }
    :root:not([data-theme="light"]) .theme-toggle .icon-sun { display: none; }
}

.card {
    background-color: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
    padding: 20px;
    margin-bottom: 16px;
}

.form-title-row { margin-bottom: 16px; }

.form-title-row h1,
.form-title-row h2 {
    margin: 0;
    padding-bottom: 8px;
    color: var(--text);
    font-size: 18px;
    font-weight: 600;
    letter-spacing: -.01em;
    border-bottom: 2px solid var(--accent);
}

.auth-header { border-bottom-color: var(--warning) !important; }
.main-auth-box { border-color: var(--danger); }

.form-row { margin-bottom: 14px; }
.form-row:last-child { margin-bottom: 0; }

.form-row label > span {
    display: block;
    margin-bottom: 6px;
    color: var(--text-muted);
    font-size: 13px;
    font-weight: 500;
}

.url-row {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
}

.url-row .url-input {
    flex: 1 1 320px;
    min-width: 0;
    font-size: 16px;
    padding: 12px 16px;
}

form input,
form textarea,
form select {
    width: 100%;
    padding: 10px 14px;
    color: var(--text);
    background-color: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    font: inherit;
    transition: border-color .15s, box-shadow .15s;
}

form input:focus,
form textarea:focus,
form select:focus {
    outline: none;
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--accent-ring);
}

form input[type=checkbox],
form input[type=radio] {
    width: auto;
    margin-right: 8px;
    accent-color: var(--accent);
}

form input[type=number] { max-width: 120px; }
form textarea { min-height: 80px; resize: vertical; }

.button-submit,
.button-cancel,
.button-ghost {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 12px 22px;
    font: 600 14px var(--font);
    text-decoration: none;
    border: 0;
    border-radius: var(--radius-sm);
    cursor: pointer;
    transition: background-color .15s, color .15s, border-color .15s;
    white-space: nowrap;
}

.button-submit {
    background-color: var(--accent);
    color: #fff;
}
.button-submit:hover, .button-submit:focus { background-color: var(--accent-hover); }

.button-cancel {
    background: transparent;
    color: var(--text-muted);
    border: 1px solid var(--border);
    padding: 10px 16px;
}
.button-cancel:hover, .button-cancel:focus {
    color: var(--text);
    border-color: var(--border-strong);
}

.button-ghost {
    background: transparent;
    color: var(--danger);
    border: 1px solid var(--border);
    padding: 10px 16px;
}
.button-ghost:hover, .button-ghost:focus {
    color: #fff;
    background-color: var(--danger);
    border-color: var(--danger);
}

.button-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    padding: 0;
    color: var(--text-muted);
    background: transparent;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    cursor: pointer;
    font: 600 16px/1 var(--font);
    transition: color .15s, background-color .15s, border-color .15s;
}
.button-icon:hover, .button-icon:focus {
    color: #fff;
    background-color: var(--danger);
    border-color: var(--danger);
    outline: none;
}

p.explanation,
p.error,
p.info {
    margin: 16px 0 0;
    padding: 12px 16px;
    border-radius: var(--radius-sm);
    font-size: 13px;
    line-height: 1.5;
}
p.explanation { background: var(--warning-soft); color: var(--text); border-left: 3px solid var(--warning); }
p.error { background: var(--danger-soft); color: var(--text); border-left: 3px solid var(--danger); }
p.info { background: var(--success-soft); color: var(--text); border-left: 3px solid var(--success); }

.tabs-wrap { margin-top: 16px; }

.tabs-wrap > input[type="radio"] {
    position: absolute;
    opacity: 0;
    pointer-events: none;
}

.tabs {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 16px;
}

.tabs label {
    padding: 8px 14px;
    color: var(--text-muted);
    font-size: 14px;
    font-weight: 500;
    border-bottom: 2px solid transparent;
    margin-bottom: -1px;
    cursor: pointer;
    transition: color .15s, border-color .15s;
}

.tabs label:hover { color: var(--text); }

#tab-options:checked  ~ .tabs label[for="tab-options"],
#tab-cookies:checked  ~ .tabs label[for="tab-cookies"],
#tab-headers:checked  ~ .tabs label[for="tab-headers"],
#tab-ip:checked       ~ .tabs label[for="tab-ip"],
#tab-port:checked     ~ .tabs label[for="tab-port"],
#tab-dns:checked      ~ .tabs label[for="tab-dns"],
#tab-cert:checked     ~ .tabs label[for="tab-cert"],
#tab-cli:checked      ~ .tabs label[for="tab-cli"],
#tab-response:checked ~ .tabs label[for="tab-response"] {
    color: var(--accent);
    border-bottom-color: var(--accent);
}

.tab-panel { display: none; }

#tab-options:checked  ~ .tab-panel[data-tab="options"],
#tab-cookies:checked  ~ .tab-panel[data-tab="cookies"],
#tab-headers:checked  ~ .tab-panel[data-tab="headers"],
#tab-ip:checked       ~ .tab-panel[data-tab="ip"],
#tab-port:checked     ~ .tab-panel[data-tab="port"],
#tab-dns:checked      ~ .tab-panel[data-tab="dns"],
#tab-cert:checked     ~ .tab-panel[data-tab="cert"],
#tab-cli:checked      ~ .tab-panel[data-tab="cli"],
#tab-response:checked ~ .tab-panel[data-tab="response"] {
    display: block;
}

.option-group {
    margin: 0 0 14px;
    padding: 8px 14px 10px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--surface-2);
}

.option-group:last-child { margin-bottom: 0; }

.option-group legend {
    padding: 0 6px;
    color: var(--text-muted);
    font-size: 11px;
    font-weight: 600;
    letter-spacing: .06em;
    text-transform: uppercase;
}

.prx-opt-menu {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 4px 16px;
}

.option label {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 5px 0;
    color: var(--text);
    font-size: 14px;
    cursor: pointer;
}

.option label input { margin: 0; }
.option label span { color: inherit; }

.radio-row {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px 18px;
    padding: 4px 0;
}

.radio-row-label {
    color: var(--text-muted);
    font-size: 14px;
    margin-right: 4px;
}

.radio-row label {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    color: var(--text);
    font-size: 14px;
    cursor: pointer;
}

.radio-row label input { margin: 0; }
.radio-row .hint { color: var(--text-muted); font-size: 11px; margin-left: 2px; }

.seed-config {
    margin-top: 10px;
    padding-top: 10px;
    border-top: 1px solid var(--border);
}

.seed-config .tab-help { margin-bottom: 10px; }

.seed-row {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 10px;
}

.seed-mini {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 10px 12px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    margin: 0;
}

.seed-mini-label {
    color: var(--text-muted);
    font-size: 12px;
    font-weight: 500;
}

.seed-mini input,
.seed-mini select {
    padding: 6px 10px;
    font: 13px var(--font-mono);
    width: 100%;
    max-width: none;
}

.seed-mini button {
    padding: 8px 12px;
    font: 600 13px var(--font);
    align-self: flex-start;
}

.seed-mini .hint { color: var(--text-muted); font-size: 11px; font-weight: 400; }

.kv-list {
    list-style: none;
    margin: 0 0 12px;
    padding: 0;
    max-height: 380px;
    overflow-y: auto;
}

.kv-list .kv-row {
    display: flex;
    gap: 6px;
    align-items: stretch;
    margin-bottom: 6px;
}

.kv-list .kv-card {
    flex: 1 1 auto;
    min-width: 0;
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    overflow: hidden;
}

.kv-list .kv-card > summary {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding: 8px 12px;
    cursor: pointer;
    list-style: none;
    font: 13px var(--font-mono);
    color: var(--text);
}

.kv-list .kv-card > summary::-webkit-details-marker { display: none; }
.kv-list .kv-card > summary::marker { content: ''; }
.kv-list .kv-card > summary:hover { background: rgba(0,0,0,.03); }
:root[data-theme="dark"] .kv-list .kv-card > summary:hover { background: rgba(255,255,255,.04); }

.kv-list .kv-display {
    flex: 1 1 auto;
    min-width: 0;
    word-break: break-all;
}

.kv-list .kv-name    { font-weight: 600; }
.kv-list .kv-host    { color: var(--accent); }
.kv-list .kv-val     { color: var(--text-muted); }
.kv-list .kv-sep     { color: var(--text-muted); margin: 0 6px; }
.kv-list .kv-chevron {
    color: var(--text-muted);
    font-size: 11px;
    flex-shrink: 0;
    transition: transform .15s;
}
.kv-list .kv-card[open] .kv-chevron { transform: rotate(180deg); }

.kv-list .kv-edit {
    padding: 10px 12px 12px;
    border-top: 1px solid var(--border);
    background: var(--surface);
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px;
}

.kv-edit-cookie {
    grid-template-columns: 1fr 1fr 1fr;
}

.kv-edit-wide { grid-column: span 2; }

.kv-edit-checks {
    grid-column: 1 / -1;
    display: flex;
    flex-wrap: wrap;
    gap: 16px;
    padding: 4px 0;
}

.kv-card.kv-card-add {
    background: var(--surface);
    border-style: dashed;
    margin-bottom: 10px;
}

.kv-card.kv-card-add > summary { color: var(--text-muted); font: 13px var(--font); }
.kv-card.kv-card-add > summary .kv-name { font-weight: 500; }
.kv-card.kv-card-add[open] > summary { color: var(--text); }

.tab-toolbar {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 10px;
    margin-bottom: 12px;
}

.tab-toolbar .tab-help { flex: 1 1 auto; margin: 0; }

.toolbar-toggle {
    margin: 0;
    flex-shrink: 0;
}

.toolbar-toggle button {
    padding: 6px 12px;
    font-size: 12px;
}

@media (max-width: 600px) {
    .kv-edit-cookie { grid-template-columns: 1fr; }
    .kv-edit-wide { grid-column: span 1; }
}

.kv-list .kv-edit-field {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font: 13px var(--font);
}

.kv-list .kv-edit-field > span {
    color: var(--text-muted);
    font-size: 12px;
}

.kv-list .kv-edit-field input {
    padding: 6px 10px;
    font: 13px var(--font-mono);
}

.kv-list .kv-edit-check {
    grid-column: 1 / -1;
    display: flex;
    align-items: center;
    gap: 6px;
    font: 13px var(--font);
    color: var(--text);
}

.kv-list .kv-edit-actions {
    grid-column: 1 / -1;
    display: flex;
    gap: 8px;
    justify-content: flex-end;
}

.kv-list .kv-edit-actions .button-submit { padding: 8px 14px; font-size: 13px; }

.kv-list .kv-delete {
    display: flex;
    align-items: center;
}

.kv-list .empty {
    background: transparent;
    border: 1px dashed var(--border);
    border-radius: var(--radius-sm);
    color: var(--text-muted);
    font: 13px var(--font);
    text-align: center;
    padding: 12px;
    margin-bottom: 6px;
}

.tabs label .tab-count {
    display: inline-block;
    margin-left: 4px;
    padding: 1px 7px;
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: 999px;
    color: var(--text-muted);
    font-size: 11px;
    font-weight: 500;
    vertical-align: middle;
}

#tab-options:checked  ~ .tabs label[for="tab-options"]  .tab-count,
#tab-cookies:checked  ~ .tabs label[for="tab-cookies"]  .tab-count,
#tab-headers:checked  ~ .tabs label[for="tab-headers"]  .tab-count,
#tab-response:checked ~ .tabs label[for="tab-response"] .tab-count {
    color: var(--accent);
    border-color: var(--accent);
}

.kv-card-readonly {
    padding: 8px 12px;
    font: 13px var(--font-mono);
    color: var(--text);
    word-break: break-all;
}

.kv-row-readonly .kv-card { background: var(--surface-2); }
.kv-row-readonly .kv-card-readonly .kv-name { font-weight: 600; color: var(--accent); }
.kv-row-readonly .kv-card-readonly .kv-sep  { color: var(--text-muted); margin: 0 6px; }
.kv-row-readonly .kv-card-readonly .kv-val  { color: var(--text); }

.kv-card-overridden > summary { border-left: 3px solid var(--accent); }
.kv-card-overridden .kv-name  { color: var(--accent); }
.kv-badge {
    display: inline-block;
    margin-left: 8px;
    padding: 1px 7px;
    background: var(--accent-soft);
    color: var(--accent);
    border-radius: 999px;
    font: 600 10px var(--font);
    letter-spacing: .04em;
    text-transform: uppercase;
}

.kv-add {
    display: grid;
    grid-template-columns: 1fr 1.4fr auto;
    gap: 8px;
    align-items: stretch;
    margin-bottom: 14px;
}

.kv-add input { padding: 9px 12px; font: inherit; }

.kv-add button {
    padding: 9px 18px;
    background: var(--accent);
    color: #fff;
    border: 0;
    border-radius: var(--radius-sm);
    font: 600 14px var(--font);
    cursor: pointer;
    transition: background-color .15s;
}
.kv-add button:hover, .kv-add button:focus { background: var(--accent-hover); }

.tab-actions {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
}

.tab-help {
    margin: 0 0 12px;
    color: var(--text-muted);
    font-size: 13px;
    line-height: 1.5;
}

.tab-help code {
    padding: 1px 5px;
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: 4px;
    font: 12px var(--font-mono);
}

.divider {
    margin: 18px 0;
    border: 0;
    border-top: 1px solid var(--border);
}

.section-label {
    margin: 0 0 8px;
    color: var(--text);
    font-size: 13px;
    font-weight: 600;
}

.ua-picker {
    display: grid;
    grid-template-columns: 1fr;
    gap: 8px;
}

.ua-picker select { padding: 9px 12px; }

.netcheck {
    display: flex;
    flex-direction: column;
}

.netcheck-solo .netcheck-fields { grid-template-columns: 1fr 140px; }

.netcheck-fields {
    display: grid;
    grid-template-columns: 1fr 140px;
    gap: 8px;
    margin-bottom: 10px;
}

.netcheck[data-netcheck="dns"] .netcheck-fields {
    grid-template-columns: 1fr 140px;
}

.netcheck-fields input,
.netcheck-fields select {
    padding: 10px 12px;
    font-size: 14px;
}

.netcheck .button-submit {
    padding: 10px 14px;
    font-size: 14px;
    align-self: flex-start;
}

.netcheck-result {
    margin: 10px 0 0 0;
    padding: 10px 12px;
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    color: var(--text);
    font-family: var(--font-mono);
    font-size: 12px;
    line-height: 1.45;
    max-height: 240px;
    overflow: auto;
    white-space: pre-wrap;
    word-break: break-word;
}

.netcheck-result.ok    { border-color: var(--success); background: var(--success-soft); }
.netcheck-result.err   { border-color: var(--danger);  background: var(--danger-soft);  }
.netcheck-result.warn  { border-color: var(--warning); background: var(--warning-soft); }
.netcheck-result.busy  { color: var(--text-muted); font-style: italic; }

/* Cert-result variant uses a <div> instead of <pre> so it can hold a rich
   structured layout with collapsible cert cards. */
.netcheck-result.cert-result {
    font-family: var(--font);
    font-size: 13px;
    white-space: normal;
    padding: 0;
    background: transparent;
    border: none;
    max-height: 600px;
}
.cert-top {
    padding: 12px 14px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--surface-2);
    margin-bottom: 12px;
}
.cert-top-line {
    font-family: var(--font-mono);
    font-size: 14px;
    margin-bottom: 4px;
}
.cert-top-line .cert-time { color: var(--text-muted); font-size: 12px; }
.cert-top-neg {
    font-family: var(--font-mono);
    font-size: 13px;
    margin-bottom: 8px;
    color: var(--text);
}
.tls-probes {
    width: 100%;
    border-collapse: collapse;
    font-family: var(--font-mono);
    font-size: 12.5px;
}
.tls-probes td {
    padding: 3px 8px;
    border-top: 1px solid var(--border);
}
.tls-probes tr:first-child td { border-top: none; }
.tls-probes .ver { font-weight: 600; width: 70px; }
.tls-probes .ok td { color: var(--text); }
.tls-probes .err td { color: var(--text-muted); }
.tls-probes .ok td:nth-child(2) { color: var(--success); font-weight: 700; }
.tls-probes .err td:nth-child(2) { color: var(--danger);  font-weight: 700; }

.cert-chain-title {
    margin: 16px 0 8px;
    font: 600 13px var(--font);
    color: var(--text-muted);
    letter-spacing: .04em;
    text-transform: uppercase;
}
.cert-card {
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    margin-bottom: 8px;
    background: var(--surface);
    overflow: hidden;
}
.cert-card > summary {
    padding: 10px 14px;
    list-style: none;
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13px;
    color: var(--text);
}
.cert-card > summary::-webkit-details-marker { display: none; }
.cert-card > summary::before {
    content: '▸';
    color: var(--text-muted);
    transition: transform .15s;
    display: inline-block;
}
.cert-card[open] > summary::before { transform: rotate(90deg); }
.cert-card[open] > summary { border-bottom: 1px solid var(--border); background: var(--surface-2); }
.cert-idx {
    display: inline-block;
    min-width: 22px;
    padding: 1px 6px;
    background: var(--accent-soft);
    color: var(--accent);
    border-radius: 4px;
    font: 600 11px var(--font-mono);
    text-align: center;
}
.cert-role {
    display: inline-block;
    padding: 1px 6px;
    background: var(--surface-2);
    color: var(--text-muted);
    border: 1px solid var(--border);
    border-radius: 999px;
    font: 600 10px var(--font);
    letter-spacing: .04em;
    text-transform: uppercase;
}
.cert-arrow { color: var(--text-muted); margin: 0 4px; }
.cert-status { font: 600 11px var(--font); margin-left: auto; padding: 1px 8px; border-radius: 999px; }
.cert-status.ok   { background: var(--success-soft); color: var(--success); }
.cert-status.warn { background: var(--warning-soft); color: var(--warning); }
.cert-status.err  { background: var(--danger-soft);  color: var(--danger);  }
.cert-body { padding: 12px 14px; }
.cert-body h5 {
    margin: 12px 0 6px;
    font: 600 11px var(--font);
    color: var(--text-muted);
    letter-spacing: .06em;
    text-transform: uppercase;
}
.cert-body h5:first-child { margin-top: 0; }
.cert-kv {
    display: grid;
    grid-template-columns: 160px 1fr;
    gap: 3px 12px;
    font-size: 12.5px;
}
.cert-kv-k { color: var(--text-muted); font-family: var(--font-mono); }
.cert-kv-v { color: var(--text); font-family: var(--font-mono); word-break: break-all; }
.cert-fp { font-size: 11.5px; letter-spacing: 0; }
.cert-ext {
    display: grid;
    grid-template-columns: 200px 1fr;
    gap: 4px 12px;
    font-size: 12.5px;
}
.cert-ext-k {
    color: var(--text-muted);
    font-family: var(--font-mono);
    font-size: 12px;
    padding-top: 4px;
}
.cert-ext-v pre {
    margin: 0;
    padding: 6px 10px;
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: 4px;
    font: 11.5px/1.5 var(--font-mono);
    color: var(--text);
    white-space: pre-wrap;
    word-break: break-all;
    overflow-x: auto;
}
.cert-raw {
    margin-top: 10px;
    border: 1px solid var(--border);
    border-radius: 4px;
    background: var(--surface-2);
}
.cert-raw > summary {
    padding: 8px 12px;
    cursor: pointer;
    font: 600 11px var(--font);
    color: var(--text-muted);
    letter-spacing: .04em;
    text-transform: uppercase;
    display: flex;
    align-items: center;
    justify-content: space-between;
}
.cert-raw > summary::-webkit-details-marker { display: none; }
.cert-raw .button-cancel { padding: 4px 10px; font-size: 11px; margin-left: 8px; }
.cert-pem {
    margin: 0;
    padding: 10px 12px;
    border-top: 1px solid var(--border);
    background: var(--surface);
    font: 11.5px/1.5 var(--font-mono);
    color: var(--text);
    white-space: pre;
    overflow-x: auto;
    max-height: 320px;
}
@media (max-width: 600px) {
    .cert-kv  { grid-template-columns: 1fr; }
    .cert-kv-k { font-weight: 600; }
    .cert-ext { grid-template-columns: 1fr; }
}

/* IP tab — identity cards (client / server / outgoing) + request/host info */
.ipinfo-wrap {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 12px;
}
.ipinfo-loading {
    grid-column: 1 / -1;
    padding: 24px;
    text-align: center;
    color: var(--text-muted);
    font-style: italic;
    border: 1px dashed var(--border);
    border-radius: var(--radius-sm);
}
.ipinfo-card {
    padding: 12px 14px;
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    display: flex;
    flex-direction: column;
    gap: 6px;
    min-width: 0;
}
.ipinfo-card-title {
    font-size: 11px;
    font-weight: 700;
    letter-spacing: .08em;
    text-transform: uppercase;
    color: var(--text-muted);
    margin-bottom: 2px;
}
.ipinfo-ip {
    font-family: var(--font-mono);
    font-size: 16px;
    font-weight: 600;
    color: var(--text);
    word-break: break-all;
}
.ipinfo-ip .ipinfo-family {
    display: inline-block;
    margin-left: 6px;
    padding: 1px 6px;
    border-radius: 999px;
    background: var(--accent-soft);
    color: var(--accent);
    font: 600 10px var(--font);
    letter-spacing: .04em;
    vertical-align: middle;
}
.ipinfo-row {
    display: flex;
    gap: 8px;
    font-size: 13px;
    min-width: 0;
}
.ipinfo-row .k {
    flex: 0 0 78px;
    color: var(--text-muted);
}
.ipinfo-row .v {
    flex: 1 1 auto;
    color: var(--text);
    min-width: 0;
    word-break: break-all;
    font-family: var(--font-mono);
    font-size: 12.5px;
}
.ipinfo-asn .ipinfo-asn-num {
    font-weight: 600;
}
.ipinfo-private {
    display: inline-block;
    padding: 1px 6px;
    border-radius: 999px;
    background: var(--warning-soft);
    color: var(--warning);
    font: 600 10px var(--font);
    letter-spacing: .04em;
}
.ipinfo-flag {
    display: inline-block;
    padding: 1px 6px;
    border-radius: 4px;
    background: var(--surface);
    border: 1px solid var(--border);
    font: 600 11px var(--font-mono);
    color: var(--text);
}
.ipinfo-section {
    margin-top: 14px;
    padding: 12px 14px;
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
}
.ipinfo-section h4 {
    margin: 0 0 8px 0;
    font: 600 11px var(--font);
    letter-spacing: .08em;
    text-transform: uppercase;
    color: var(--text-muted);
}
.ipinfo-grid {
    display: grid;
    grid-template-columns: 160px 1fr;
    gap: 4px 12px;
    font-size: 13px;
}
.ipinfo-grid .k { color: var(--text-muted); }
.ipinfo-grid .v {
    color: var(--text);
    word-break: break-all;
    font-family: var(--font-mono);
    font-size: 12.5px;
}
.ipinfo-grid .v.empty { color: var(--text-muted); font-style: italic; font-family: var(--font); font-size: 13px; }

/* Wide grid layout for the three identity cards spans the full ip tab. */
@media (max-width: 720px) {
    .ipinfo-wrap { grid-template-columns: 1fr; }
    .ipinfo-grid { grid-template-columns: 120px 1fr; }
}

/* CLI tab — base styles (entry page). The panel-scoped equivalents live
   under #phproxy-panel so proxied-page injection doesn't leak rules to
   the host document. */
.cli-wrap > input[type="radio"] {
    position: absolute;
    opacity: 0;
    pointer-events: none;
}
.cli-tabs {
    display: flex;
    gap: 4px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 12px;
    flex-wrap: wrap;
}
.cli-tabs label {
    padding: 6px 12px;
    color: var(--text-muted);
    font-size: 13px;
    font-weight: 500;
    border-bottom: 2px solid transparent;
    margin-bottom: -1px;
    cursor: pointer;
    transition: color .15s, border-color .15s;
}
.cli-tabs label:hover { color: var(--text); }
#cli-tab-curl:checked   ~ .cli-tabs label[for="cli-tab-curl"],
#cli-tab-php:checked    ~ .cli-tabs label[for="cli-tab-php"],
#cli-tab-python:checked ~ .cli-tabs label[for="cli-tab-python"],
#cli-tab-js:checked     ~ .cli-tabs label[for="cli-tab-js"],
#cli-tab-go:checked     ~ .cli-tabs label[for="cli-tab-go"] {
    color: var(--accent);
    border-bottom-color: var(--accent);
}
.cli-panel { display: none; }
#cli-tab-curl:checked   ~ .cli-panel[data-cli="curl"],
#cli-tab-php:checked    ~ .cli-panel[data-cli="php"],
#cli-tab-python:checked ~ .cli-panel[data-cli="python"],
#cli-tab-js:checked     ~ .cli-panel[data-cli="js"],
#cli-tab-go:checked     ~ .cli-panel[data-cli="go"] {
    display: block;
}
.cli-variant            { margin-bottom: 16px; }
.cli-variant:last-child { margin-bottom: 0; }
.cli-toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 6px;
}
.cli-variant-label {
    color: var(--text-muted);
    font: 600 11px var(--font);
    letter-spacing: .06em;
    text-transform: uppercase;
}
.cli-variant-label code {
    background: var(--surface-2);
    padding: 1px 5px;
    border-radius: 4px;
    font: 11px var(--font-mono);
    text-transform: none;
    letter-spacing: 0;
    color: var(--text);
}
.cli-toolbar .button-cancel { padding: 6px 12px; font-size: 12px; }
.cli-snippet {
    margin: 0;
    padding: 14px 16px;
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    font: 12.5px/1.55 var(--font-mono);
    color: var(--text);
    overflow-x: auto;
    white-space: pre;
    -webkit-text-size-adjust: 100%;
}

.footer {
    margin: 24px 0;
    text-align: center;
    font-size: 12px;
    color: var(--text-muted);
}

.footer a {
    color: var(--text-muted);
    text-decoration: none;
}

.footer a:hover { color: var(--accent); }

@media (max-width: 880px) {
    .netcheck-row { grid-template-columns: 1fr; }
}

@media (max-width: 600px) {
    .page { margin: 16px auto; padding: 0 12px; }
    .card { padding: 16px; }
    .prx-opt-menu { grid-template-columns: 1fr; }
    .kv-add { grid-template-columns: 1fr; }
}
PHPROXY_INDEX_CSS;
}

function phproxy_panel_css(): string {
    return <<<'PHPROXY_PANEL_CSS'
/* PHProxy inline panel stylesheet — scoped to #phproxy-panel.
 *
 * Every selector below begins with #phproxy-panel so loading this file on a
 * proxied page can't touch the host page's elements. The trade-off vs.
 * loading the entry-form's index.css here is that we have to duplicate the
 * rules, but it keeps the panel's styling fully isolated.
 *
 * CSS variables live on #phproxy-panel itself (not :root) for the same
 * reason. Theme follows [data-theme] on <html> and prefers-color-scheme,
 * matching the entry form's behavior.
 */

/* Full-viewport overlay below the sticky bar. The panel covers the entire
 * window from the bar down; the host page's content is hidden behind it
 * until the user closes the panel. Show/hide is driven by the sibling
 * #phproxy-panel-toggle checkbox via ~. */
#phproxy-panel {
    /* Reset every inheritable property so the host page can't bleed in.
     * `all: initial` forces this element to its initial styles regardless
     * of what the proxied page's CSS has set on its ancestors. We then
     * re-establish exactly the styling we want below. */
    all: initial;
    display: none;
    position: fixed;
    inset: 54px 0 0 0;
    overflow-y: auto;
    z-index: 2147483646;
    box-sizing: border-box;
    padding: 24px 0 40px;
    border-top: 1px solid var(--border);
    border-radius: 0;

    --bg: #f4f5f7;
    --surface: #ffffff;
    --surface-2: #f8fafc;
    --border: #e2e6ec;
    --border-strong: #cbd5e1;
    --text: #0f172a;
    --text-muted: #64748b;
    --accent: #2563eb;
    --accent-hover: #1d4ed8;
    --accent-ring: rgba(37, 99, 235, .18);
    --danger: #ef4444;
    --danger-soft: #fee2e2;
    --warning: #f59e0b;
    --warning-soft: #fef3c7;
    --success: #10b981;
    --success-soft: #d1fae5;
    --radius: 10px;
    --radius-sm: 6px;
    --shadow: 0 18px 32px -8px rgba(15, 23, 42, .18);
    --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    --font-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Monaco, Consolas, monospace;
    color-scheme: light;
    color: var(--text);
    background: var(--bg);
    border: 1px solid var(--border);
    box-shadow: var(--shadow);
    font: 400 14px/1.5 var(--font);
    -webkit-font-smoothing: antialiased;
}

#phproxy-panel-toggle:checked ~ #phproxy-panel { display: block; }

/* Dark variant. The mini-bar script sets data-theme=dark on #phproxy-panel
 * (and on #phproxy-bar) when the user picked dark in the entry form or when
 * the OS prefers dark and the user hasn't explicitly picked light. We
 * deliberately do NOT set data-theme on <html> on a proxied page — that
 * would touch the host site's own [data-theme] selectors. */
#phproxy-panel[data-theme="dark"] {
    --bg: #131c2e;
    --surface: #1a2438;
    --surface-2: #0f172a;
    --border: #2a374e;
    --border-strong: #3b4a66;
    --text: #f1f5f9;
    --text-muted: #94a3b8;
    --accent: #60a5fa;
    --accent-hover: #93c5fd;
    --accent-ring: rgba(96, 165, 250, .25);
    --danger: #f87171;
    --danger-soft: #7f1d1d;
    --warning: #fbbf24;
    --warning-soft: #78350f;
    --success: #34d399;
    --success-soft: #064e3b;
    --shadow: 0 18px 32px -8px rgba(0, 0, 0, .55);
    color-scheme: dark;
}

/* Inner wrapper centers content on wide screens so the forms don't
 * stretch edge-to-edge. */
#phproxy-panel > .panel-inner {
    max-width: 960px;
    margin: 0 auto;
    padding: 0 24px;
}

/* Panel chrome */
#phproxy-panel .panel-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 14px;
    padding-bottom: 10px;
    border-bottom: 1px solid var(--border);
}
#phproxy-panel .panel-head h2 {
    margin: 0;
    font-size: 15px;
    font-weight: 600;
    color: var(--text);
    letter-spacing: -.01em;
}
#phproxy-panel .panel-head .close {
    padding: 4px 10px;
    font-size: 13px;
    cursor: pointer;
    background: transparent;
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--text-muted);
    text-decoration: none;
}
#phproxy-panel .panel-head .close:hover { color: var(--text); }
#phproxy-panel .panel-refresh {
    margin-top: 16px;
    padding-top: 14px;
    border-top: 1px solid var(--border);
    display: flex;
    gap: 8px;
    justify-content: space-between;
    flex-wrap: wrap;
}
#phproxy-panel .panel-refresh .button-submit { padding: 10px 18px; font-weight: 600; }
#phproxy-panel .panel-refresh small {
    color: var(--text-muted);
    font-size: 12px;
    align-self: center;
}

#phproxy-panel,
#phproxy-panel *,
#phproxy-panel *::before,
#phproxy-panel *::after { box-sizing: border-box; }

#phproxy-panel a              { color: var(--accent); text-decoration: none; }
#phproxy-panel a:hover         { text-decoration: underline; }
#phproxy-panel h1,
#phproxy-panel h2,
#phproxy-panel h3,
#phproxy-panel p,
#phproxy-panel ul,
#phproxy-panel ol,
#phproxy-panel fieldset,
#phproxy-panel legend,
#phproxy-panel hr             { all: revert; margin: 0; padding: 0; color: inherit; font: inherit; }
#phproxy-panel ul,
#phproxy-panel ol             { list-style: none; }
#phproxy-panel fieldset       { border: 0; }

#phproxy-panel .card {
    background-color: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
    padding: 20px;
    margin-bottom: 16px;
}

#phproxy-panel .form-title-row { margin-bottom: 16px; }
#phproxy-panel .form-title-row h1,
#phproxy-panel .form-title-row h2 {
    margin: 0;
    padding-bottom: 8px;
    color: var(--text);
    font-size: 18px;
    font-weight: 600;
    letter-spacing: -.01em;
    border-bottom: 2px solid var(--accent);
}
#phproxy-panel .auth-header     { border-bottom-color: var(--warning) !important; }
#phproxy-panel .main-auth-box   { border-color: var(--danger); }

#phproxy-panel .form-row              { margin-bottom: 14px; }
#phproxy-panel .form-row:last-child   { margin-bottom: 0; }
#phproxy-panel .form-row label > span {
    display: block;
    margin-bottom: 6px;
    color: var(--text-muted);
    font-size: 13px;
    font-weight: 500;
}

#phproxy-panel form input,
#phproxy-panel form textarea,
#phproxy-panel form select {
    width: 100%;
    padding: 10px 14px;
    color: var(--text);
    background-color: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    font: 14px var(--font);
    transition: border-color .15s, box-shadow .15s;
}
#phproxy-panel form input:focus,
#phproxy-panel form textarea:focus,
#phproxy-panel form select:focus {
    outline: none;
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--accent-ring);
}
#phproxy-panel form input[type=checkbox],
#phproxy-panel form input[type=radio] {
    width: auto;
    margin-right: 8px;
    accent-color: var(--accent);
}
#phproxy-panel form input[type=number] { max-width: 120px; }
#phproxy-panel form textarea           { min-height: 80px; resize: vertical; }

#phproxy-panel .button-submit,
#phproxy-panel .button-cancel,
#phproxy-panel .button-ghost {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 10px 18px;
    font: 600 14px var(--font);
    text-decoration: none;
    border: 0;
    border-radius: var(--radius-sm);
    cursor: pointer;
    transition: background-color .15s, color .15s, border-color .15s;
    white-space: nowrap;
}
#phproxy-panel .button-submit                  { background-color: var(--accent); color: #fff; }
#phproxy-panel .button-submit:hover,
#phproxy-panel .button-submit:focus            { background-color: var(--accent-hover); }
#phproxy-panel .button-cancel                  { background: transparent; color: var(--text-muted); border: 1px solid var(--border); padding: 8px 14px; }
#phproxy-panel .button-cancel:hover,
#phproxy-panel .button-cancel:focus            { color: var(--text); border-color: var(--border-strong); }
#phproxy-panel .button-ghost                   { background: transparent; color: var(--danger); border: 1px solid var(--border); padding: 8px 14px; }
#phproxy-panel .button-ghost:hover,
#phproxy-panel .button-ghost:focus             { color: #fff; background-color: var(--danger); border-color: var(--danger); }

#phproxy-panel .button-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    padding: 0;
    color: var(--text-muted);
    background: transparent;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    cursor: pointer;
    font: 600 16px/1 var(--font);
    transition: color .15s, background-color .15s, border-color .15s;
}
#phproxy-panel .button-icon:hover,
#phproxy-panel .button-icon:focus {
    color: #fff;
    background-color: var(--danger);
    border-color: var(--danger);
    outline: none;
}

#phproxy-panel p.explanation,
#phproxy-panel p.error,
#phproxy-panel p.info {
    margin: 16px 0 0;
    padding: 12px 16px;
    border-radius: var(--radius-sm);
    font-size: 13px;
    line-height: 1.5;
}
#phproxy-panel p.explanation { background: var(--warning-soft); color: var(--text); border-left: 3px solid var(--warning); }
#phproxy-panel p.error       { background: var(--danger-soft);  color: var(--text); border-left: 3px solid var(--danger); }
#phproxy-panel p.info        { background: var(--success-soft); color: var(--text); border-left: 3px solid var(--success); }

#phproxy-panel .tabs-wrap                            { margin-top: 0; }
#phproxy-panel .tabs-wrap > input[type="radio"]      { position: absolute; opacity: 0; pointer-events: none; }
#phproxy-panel .tabs {
    display: flex;
    gap: 4px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 16px;
    flex-wrap: wrap;
}
#phproxy-panel .tabs label {
    padding: 8px 14px;
    color: var(--text-muted);
    font-size: 14px;
    font-weight: 500;
    border-bottom: 2px solid transparent;
    margin-bottom: -1px;
    cursor: pointer;
    transition: color .15s, border-color .15s;
}
#phproxy-panel .tabs label:hover  { color: var(--text); }

#phproxy-panel #tab-options:checked  ~ .tabs label[for="tab-options"],
#phproxy-panel #tab-cookies:checked  ~ .tabs label[for="tab-cookies"],
#phproxy-panel #tab-headers:checked  ~ .tabs label[for="tab-headers"],
#phproxy-panel #tab-ip:checked       ~ .tabs label[for="tab-ip"],
#phproxy-panel #tab-port:checked     ~ .tabs label[for="tab-port"],
#phproxy-panel #tab-dns:checked      ~ .tabs label[for="tab-dns"],
#phproxy-panel #tab-cert:checked     ~ .tabs label[for="tab-cert"],
#phproxy-panel #tab-response:checked ~ .tabs label[for="tab-response"],
#phproxy-panel #tab-cli:checked      ~ .tabs label[for="tab-cli"],
#phproxy-panel #tab-network:checked  ~ .tabs label[for="tab-network"] {
    color: var(--accent);
    border-bottom-color: var(--accent);
}

#phproxy-panel .tab-panel { display: none; }
#phproxy-panel #tab-options:checked  ~ .tab-panel[data-tab="options"],
#phproxy-panel #tab-cookies:checked  ~ .tab-panel[data-tab="cookies"],
#phproxy-panel #tab-headers:checked  ~ .tab-panel[data-tab="headers"],
#phproxy-panel #tab-ip:checked       ~ .tab-panel[data-tab="ip"],
#phproxy-panel #tab-port:checked     ~ .tab-panel[data-tab="port"],
#phproxy-panel #tab-dns:checked      ~ .tab-panel[data-tab="dns"],
#phproxy-panel #tab-cert:checked     ~ .tab-panel[data-tab="cert"],
#phproxy-panel #tab-response:checked ~ .tab-panel[data-tab="response"],
#phproxy-panel #tab-cli:checked      ~ .tab-panel[data-tab="cli"],
#phproxy-panel #tab-network:checked  ~ .tab-panel[data-tab="network"] {
    display: block;
}

/* Network tab — dev-tools-style request log */
#phproxy-panel .net-table {
    width: 100%;
    border-collapse: collapse;
    font: 12.5px var(--font-mono);
    color: var(--text);
}
#phproxy-panel .net-table th,
#phproxy-panel .net-table td {
    padding: 6px 10px;
    border-bottom: 1px solid var(--border);
    text-align: left;
    vertical-align: top;
    white-space: nowrap;
}
#phproxy-panel .net-table thead th {
    position: sticky;
    top: 0;
    background: var(--surface-2);
    color: var(--text-muted);
    font: 600 11px var(--font);
    letter-spacing: .04em;
    text-transform: uppercase;
    border-bottom: 1px solid var(--border-strong);
}
#phproxy-panel .net-table td.num,
#phproxy-panel .net-table th.num { text-align: right; font-variant-numeric: tabular-nums; }
#phproxy-panel .net-table td.url {
    max-width: 0;
    width: 50%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--text);
}
#phproxy-panel .net-table td.method { color: var(--accent); font-weight: 600; }
#phproxy-panel .net-table td.type   { color: var(--text-muted); }
#phproxy-panel .net-table td.status { font-weight: 600; }
#phproxy-panel .net-table td.status.st-2xx { color: var(--success); }
#phproxy-panel .net-table td.status.st-3xx { color: var(--warning); }
#phproxy-panel .net-table td.status.st-4xx { color: var(--danger); }
#phproxy-panel .net-table td.status.st-5xx { color: var(--danger); }
#phproxy-panel .net-table tr.current { background: var(--accent-soft); }
#phproxy-panel .net-table tr.current td { font-weight: 600; }
#phproxy-panel .net-table tr:hover td { background: rgba(0,0,0,.02); }
#phproxy-panel[data-theme="dark"] .net-table tr:hover td { background: rgba(255,255,255,.03); }

/* IP tab — identity cards + sections */
#phproxy-panel .ipinfo-wrap {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 12px;
}
#phproxy-panel .ipinfo-loading {
    grid-column: 1 / -1;
    padding: 24px;
    text-align: center;
    color: var(--text-muted);
    font-style: italic;
    border: 1px dashed var(--border);
    border-radius: var(--radius-sm);
}
#phproxy-panel .ipinfo-card {
    padding: 12px 14px;
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    display: flex;
    flex-direction: column;
    gap: 6px;
    min-width: 0;
}
#phproxy-panel .ipinfo-card-title {
    font-size: 11px;
    font-weight: 700;
    letter-spacing: .08em;
    text-transform: uppercase;
    color: var(--text-muted);
    margin-bottom: 2px;
}
#phproxy-panel .ipinfo-ip {
    font-family: var(--font-mono);
    font-size: 16px;
    font-weight: 600;
    color: var(--text);
    word-break: break-all;
}
#phproxy-panel .ipinfo-ip .ipinfo-family {
    display: inline-block;
    margin-left: 6px;
    padding: 1px 6px;
    border-radius: 999px;
    background: var(--accent-soft);
    color: var(--accent);
    font: 600 10px var(--font);
    letter-spacing: .04em;
    vertical-align: middle;
}
#phproxy-panel .ipinfo-row {
    display: flex;
    gap: 8px;
    font-size: 13px;
    min-width: 0;
}
#phproxy-panel .ipinfo-row .k { flex: 0 0 78px; color: var(--text-muted); }
#phproxy-panel .ipinfo-row .v {
    flex: 1 1 auto;
    color: var(--text);
    min-width: 0;
    word-break: break-all;
    font-family: var(--font-mono);
    font-size: 12.5px;
}
#phproxy-panel .ipinfo-asn .ipinfo-asn-num { font-weight: 600; }
#phproxy-panel .ipinfo-private {
    display: inline-block;
    padding: 1px 6px;
    border-radius: 999px;
    background: var(--warning-soft);
    color: var(--warning);
    font: 600 10px var(--font);
    letter-spacing: .04em;
}
#phproxy-panel .ipinfo-flag {
    display: inline-block;
    padding: 1px 6px;
    border-radius: 4px;
    background: var(--surface);
    border: 1px solid var(--border);
    font: 600 11px var(--font-mono);
    color: var(--text);
}
#phproxy-panel .ipinfo-section {
    margin-top: 14px;
    padding: 12px 14px;
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
}
#phproxy-panel .ipinfo-section h4 {
    margin: 0 0 8px 0;
    font: 600 11px var(--font);
    letter-spacing: .08em;
    text-transform: uppercase;
    color: var(--text-muted);
}
#phproxy-panel .ipinfo-grid {
    display: grid;
    grid-template-columns: 160px 1fr;
    gap: 4px 12px;
    font-size: 13px;
}
#phproxy-panel .ipinfo-grid .k { color: var(--text-muted); }
#phproxy-panel .ipinfo-grid .v {
    color: var(--text);
    word-break: break-all;
    font-family: var(--font-mono);
    font-size: 12.5px;
}
#phproxy-panel .ipinfo-grid .v.empty { color: var(--text-muted); font-style: italic; font-family: var(--font); font-size: 13px; }
@media (max-width: 720px) {
    #phproxy-panel .ipinfo-wrap { grid-template-columns: 1fr; }
    #phproxy-panel .ipinfo-grid { grid-template-columns: 120px 1fr; }
}

/* Cert-result variant — collapsible cert cards (panel-scoped mirror) */
#phproxy-panel .netcheck-result.cert-result {
    font-family: var(--font);
    font-size: 13px;
    white-space: normal;
    padding: 0;
    background: transparent;
    border: none;
    max-height: 600px;
}
#phproxy-panel .cert-top {
    padding: 12px 14px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--surface-2);
    margin-bottom: 12px;
}
#phproxy-panel .cert-top-line { font-family: var(--font-mono); font-size: 14px; margin-bottom: 4px; }
#phproxy-panel .cert-top-line .cert-time { color: var(--text-muted); font-size: 12px; }
#phproxy-panel .cert-top-neg { font-family: var(--font-mono); font-size: 13px; margin-bottom: 8px; color: var(--text); }
#phproxy-panel .tls-probes { width: 100%; border-collapse: collapse; font-family: var(--font-mono); font-size: 12.5px; }
#phproxy-panel .tls-probes td { padding: 3px 8px; border-top: 1px solid var(--border); }
#phproxy-panel .tls-probes tr:first-child td { border-top: none; }
#phproxy-panel .tls-probes .ver { font-weight: 600; width: 70px; }
#phproxy-panel .tls-probes .ok td  { color: var(--text); }
#phproxy-panel .tls-probes .err td { color: var(--text-muted); }
#phproxy-panel .tls-probes .ok td:nth-child(2)  { color: var(--success); font-weight: 700; }
#phproxy-panel .tls-probes .err td:nth-child(2) { color: var(--danger);  font-weight: 700; }
#phproxy-panel .cert-chain-title { margin: 16px 0 8px; font: 600 13px var(--font); color: var(--text-muted); letter-spacing: .04em; text-transform: uppercase; }
#phproxy-panel .cert-card { border: 1px solid var(--border); border-radius: var(--radius-sm); margin-bottom: 8px; background: var(--surface); overflow: hidden; }
#phproxy-panel .cert-card > summary { padding: 10px 14px; list-style: none; cursor: pointer; display: flex; align-items: center; gap: 8px; font-size: 13px; color: var(--text); }
#phproxy-panel .cert-card > summary::-webkit-details-marker { display: none; }
#phproxy-panel .cert-card > summary::before { content: '▸'; color: var(--text-muted); transition: transform .15s; display: inline-block; }
#phproxy-panel .cert-card[open] > summary::before { transform: rotate(90deg); }
#phproxy-panel .cert-card[open] > summary { border-bottom: 1px solid var(--border); background: var(--surface-2); }
#phproxy-panel .cert-idx { display: inline-block; min-width: 22px; padding: 1px 6px; background: var(--accent-soft); color: var(--accent); border-radius: 4px; font: 600 11px var(--font-mono); text-align: center; }
#phproxy-panel .cert-role { display: inline-block; padding: 1px 6px; background: var(--surface-2); color: var(--text-muted); border: 1px solid var(--border); border-radius: 999px; font: 600 10px var(--font); letter-spacing: .04em; text-transform: uppercase; }
#phproxy-panel .cert-arrow { color: var(--text-muted); margin: 0 4px; }
#phproxy-panel .cert-status { font: 600 11px var(--font); margin-left: auto; padding: 1px 8px; border-radius: 999px; }
#phproxy-panel .cert-status.ok   { background: var(--success-soft); color: var(--success); }
#phproxy-panel .cert-status.warn { background: var(--warning-soft); color: var(--warning); }
#phproxy-panel .cert-status.err  { background: var(--danger-soft);  color: var(--danger);  }
#phproxy-panel .cert-body { padding: 12px 14px; }
#phproxy-panel .cert-body h5 { margin: 12px 0 6px; font: 600 11px var(--font); color: var(--text-muted); letter-spacing: .06em; text-transform: uppercase; }
#phproxy-panel .cert-body h5:first-child { margin-top: 0; }
#phproxy-panel .cert-kv { display: grid; grid-template-columns: 160px 1fr; gap: 3px 12px; font-size: 12.5px; }
#phproxy-panel .cert-kv-k { color: var(--text-muted); font-family: var(--font-mono); }
#phproxy-panel .cert-kv-v { color: var(--text); font-family: var(--font-mono); word-break: break-all; }
#phproxy-panel .cert-fp { font-size: 11.5px; letter-spacing: 0; }
#phproxy-panel .cert-ext { display: grid; grid-template-columns: 200px 1fr; gap: 4px 12px; font-size: 12.5px; }
#phproxy-panel .cert-ext-k { color: var(--text-muted); font-family: var(--font-mono); font-size: 12px; padding-top: 4px; }
#phproxy-panel .cert-ext-v pre { margin: 0; padding: 6px 10px; background: var(--surface-2); border: 1px solid var(--border); border-radius: 4px; font: 11.5px/1.5 var(--font-mono); color: var(--text); white-space: pre-wrap; word-break: break-all; overflow-x: auto; }
#phproxy-panel .cert-raw { margin-top: 10px; border: 1px solid var(--border); border-radius: 4px; background: var(--surface-2); }
#phproxy-panel .cert-raw > summary { padding: 8px 12px; cursor: pointer; font: 600 11px var(--font); color: var(--text-muted); letter-spacing: .04em; text-transform: uppercase; display: flex; align-items: center; justify-content: space-between; }
#phproxy-panel .cert-raw > summary::-webkit-details-marker { display: none; }
#phproxy-panel .cert-raw .button-cancel { padding: 4px 10px; font-size: 11px; margin-left: 8px; }
#phproxy-panel .cert-pem { margin: 0; padding: 10px 12px; border-top: 1px solid var(--border); background: var(--surface); font: 11.5px/1.5 var(--font-mono); color: var(--text); white-space: pre; overflow-x: auto; max-height: 320px; }
@media (max-width: 600px) {
    #phproxy-panel .cert-kv  { grid-template-columns: 1fr; }
    #phproxy-panel .cert-kv-k { font-weight: 600; }
    #phproxy-panel .cert-ext { grid-template-columns: 1fr; }
}

/* CLI tab — sub-tabs for curl / PHP / Python / JS / Go */
#phproxy-panel .cli-wrap > input[type="radio"] {
    position: absolute;
    opacity: 0;
    pointer-events: none;
}
#phproxy-panel .cli-tabs {
    display: flex;
    gap: 4px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 12px;
    flex-wrap: wrap;
}
#phproxy-panel .cli-tabs label {
    padding: 6px 12px;
    color: var(--text-muted);
    font-size: 13px;
    font-weight: 500;
    border-bottom: 2px solid transparent;
    margin-bottom: -1px;
    cursor: pointer;
    transition: color .15s, border-color .15s;
}
#phproxy-panel .cli-tabs label:hover { color: var(--text); }
#phproxy-panel #cli-tab-curl:checked   ~ .cli-tabs label[for="cli-tab-curl"],
#phproxy-panel #cli-tab-php:checked    ~ .cli-tabs label[for="cli-tab-php"],
#phproxy-panel #cli-tab-python:checked ~ .cli-tabs label[for="cli-tab-python"],
#phproxy-panel #cli-tab-js:checked     ~ .cli-tabs label[for="cli-tab-js"],
#phproxy-panel #cli-tab-go:checked     ~ .cli-tabs label[for="cli-tab-go"] {
    color: var(--accent);
    border-bottom-color: var(--accent);
}
#phproxy-panel .cli-panel { display: none; }
#phproxy-panel #cli-tab-curl:checked   ~ .cli-panel[data-cli="curl"],
#phproxy-panel #cli-tab-php:checked    ~ .cli-panel[data-cli="php"],
#phproxy-panel #cli-tab-python:checked ~ .cli-panel[data-cli="python"],
#phproxy-panel #cli-tab-js:checked     ~ .cli-panel[data-cli="js"],
#phproxy-panel #cli-tab-go:checked     ~ .cli-panel[data-cli="go"] {
    display: block;
}
#phproxy-panel .cli-variant         { margin-bottom: 16px; }
#phproxy-panel .cli-variant:last-child { margin-bottom: 0; }
#phproxy-panel .cli-toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 6px;
}
#phproxy-panel .cli-variant-label {
    color: var(--text-muted);
    font: 600 11px var(--font);
    letter-spacing: .06em;
    text-transform: uppercase;
}
#phproxy-panel .cli-variant-label code {
    background: var(--surface-2);
    padding: 1px 5px;
    border-radius: 4px;
    font: 11px var(--font-mono);
    text-transform: none;
    letter-spacing: 0;
    color: var(--text);
}
#phproxy-panel .cli-toolbar .button-cancel { padding: 6px 12px; font-size: 12px; }
#phproxy-panel .cli-snippet {
    margin: 0;
    padding: 14px 16px;
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    font: 12.5px/1.55 var(--font-mono);
    color: var(--text);
    overflow-x: auto;
    white-space: pre;
    -webkit-text-size-adjust: 100%;
}

#phproxy-panel .option-group {
    margin: 0 0 14px;
    padding: 8px 14px 10px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--surface-2);
}
#phproxy-panel .option-group:last-child { margin-bottom: 0; }
#phproxy-panel .option-group legend {
    padding: 0 6px;
    color: var(--text-muted);
    font-size: 11px;
    font-weight: 600;
    letter-spacing: .06em;
    text-transform: uppercase;
}

#phproxy-panel .prx-opt-menu {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 4px 16px;
}
#phproxy-panel .option label {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 5px 0;
    color: var(--text);
    font-size: 14px;
    cursor: pointer;
}
#phproxy-panel .option label input { margin: 0; }
#phproxy-panel .option label span  { color: inherit; }

#phproxy-panel .radio-row {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px 18px;
    padding: 4px 0;
}
#phproxy-panel .radio-row-label { color: var(--text-muted); font-size: 14px; margin-right: 4px; }
#phproxy-panel .radio-row label {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    color: var(--text);
    font-size: 14px;
    cursor: pointer;
}
#phproxy-panel .radio-row label input { margin: 0; }
#phproxy-panel .radio-row .hint       { color: var(--text-muted); font-size: 11px; margin-left: 2px; }

#phproxy-panel .seed-config {
    margin-top: 10px;
    padding-top: 10px;
    border-top: 1px solid var(--border);
}
#phproxy-panel .seed-config .tab-help { margin-bottom: 10px; }
#phproxy-panel .seed-row {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 10px;
}
#phproxy-panel .seed-mini {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 10px 12px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    margin: 0;
}
#phproxy-panel .seed-mini-label { color: var(--text-muted); font-size: 12px; font-weight: 500; }
#phproxy-panel .seed-mini input,
#phproxy-panel .seed-mini select {
    padding: 6px 10px;
    font: 13px var(--font-mono);
    width: 100%;
    max-width: none;
}
#phproxy-panel .seed-mini button { padding: 8px 12px; font: 600 13px var(--font); align-self: flex-start; }
#phproxy-panel .seed-mini .hint   { color: var(--text-muted); font-size: 11px; font-weight: 400; }

#phproxy-panel .kv-list {
    list-style: none;
    margin: 0 0 12px;
    padding: 0;
    max-height: 380px;
    overflow-y: auto;
}
#phproxy-panel .kv-list .kv-row {
    display: flex;
    gap: 6px;
    align-items: stretch;
    margin-bottom: 6px;
}
#phproxy-panel .kv-list .kv-card {
    flex: 1 1 auto;
    min-width: 0;
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    overflow: hidden;
}
#phproxy-panel .kv-list .kv-card > summary {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding: 8px 12px;
    cursor: pointer;
    list-style: none;
    font: 13px var(--font-mono);
    color: var(--text);
}
#phproxy-panel .kv-list .kv-card > summary::-webkit-details-marker { display: none; }
#phproxy-panel .kv-list .kv-card > summary::marker                  { content: ''; }
#phproxy-panel .kv-list .kv-card > summary:hover                    { background: rgba(0,0,0,.03); }
#phproxy-panel[data-theme="dark"] .kv-list .kv-card > summary:hover { background: rgba(255,255,255,.04); }

#phproxy-panel .kv-list .kv-display { flex: 1 1 auto; min-width: 0; word-break: break-all; }
#phproxy-panel .kv-list .kv-name    { font-weight: 600; }
#phproxy-panel .kv-list .kv-host    { color: var(--accent); }
#phproxy-panel .kv-list .kv-val     { color: var(--text-muted); }
#phproxy-panel .kv-list .kv-sep     { color: var(--text-muted); margin: 0 6px; }
#phproxy-panel .kv-list .kv-chevron {
    color: var(--text-muted);
    font-size: 11px;
    flex-shrink: 0;
    transition: transform .15s;
}
#phproxy-panel .kv-list .kv-card[open] .kv-chevron { transform: rotate(180deg); }

#phproxy-panel .kv-list .kv-edit {
    padding: 10px 12px 12px;
    border-top: 1px solid var(--border);
    background: var(--surface);
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px;
}
#phproxy-panel .kv-edit-cookie { grid-template-columns: 1fr 1fr 1fr; }
#phproxy-panel .kv-edit-wide   { grid-column: span 2; }
#phproxy-panel .kv-edit-checks {
    grid-column: 1 / -1;
    display: flex;
    flex-wrap: wrap;
    gap: 16px;
    padding: 4px 0;
}

#phproxy-panel .kv-card.kv-card-add {
    background: var(--surface);
    border-style: dashed;
    margin-bottom: 10px;
}
#phproxy-panel .kv-card.kv-card-add > summary       { color: var(--text-muted); font: 13px var(--font); }
#phproxy-panel .kv-card.kv-card-add > summary .kv-name { font-weight: 500; }
#phproxy-panel .kv-card.kv-card-add[open] > summary { color: var(--text); }

#phproxy-panel .kv-list .kv-edit-field {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font: 13px var(--font);
}
#phproxy-panel .kv-list .kv-edit-field > span { color: var(--text-muted); font-size: 12px; }
#phproxy-panel .kv-list .kv-edit-field input  { padding: 6px 10px; font: 13px var(--font-mono); }

#phproxy-panel .kv-list .kv-edit-check {
    grid-column: 1 / -1;
    display: flex;
    align-items: center;
    gap: 6px;
    font: 13px var(--font);
    color: var(--text);
}
#phproxy-panel .kv-list .kv-edit-actions {
    grid-column: 1 / -1;
    display: flex;
    gap: 8px;
    justify-content: flex-end;
}
#phproxy-panel .kv-list .kv-edit-actions .button-submit { padding: 8px 14px; font-size: 13px; }

#phproxy-panel .kv-list .kv-delete { display: flex; align-items: center; }

#phproxy-panel .kv-list .empty {
    background: transparent;
    border: 1px dashed var(--border);
    border-radius: var(--radius-sm);
    color: var(--text-muted);
    font: 13px var(--font);
    text-align: center;
    padding: 12px;
    margin-bottom: 6px;
}

#phproxy-panel .tabs label .tab-count {
    display: inline-block;
    margin-left: 4px;
    padding: 1px 7px;
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: 999px;
    color: var(--text-muted);
    font-size: 11px;
    font-weight: 500;
    vertical-align: middle;
}
#phproxy-panel #tab-options:checked  ~ .tabs label[for="tab-options"]  .tab-count,
#phproxy-panel #tab-cookies:checked  ~ .tabs label[for="tab-cookies"]  .tab-count,
#phproxy-panel #tab-headers:checked  ~ .tabs label[for="tab-headers"]  .tab-count,
#phproxy-panel #tab-response:checked ~ .tabs label[for="tab-response"] .tab-count {
    color: var(--accent);
    border-color: var(--accent);
}

#phproxy-panel .kv-add {
    display: grid;
    grid-template-columns: 1fr 1.4fr auto;
    gap: 8px;
    align-items: stretch;
    margin-bottom: 14px;
}
#phproxy-panel .kv-add input  { padding: 9px 12px; font: 14px var(--font); }
#phproxy-panel .kv-add button {
    padding: 9px 18px;
    background: var(--accent);
    color: #fff;
    border: 0;
    border-radius: var(--radius-sm);
    font: 600 14px var(--font);
    cursor: pointer;
    transition: background-color .15s;
}
#phproxy-panel .kv-add button:hover,
#phproxy-panel .kv-add button:focus { background: var(--accent-hover); }

#phproxy-panel .tab-actions { display: flex; gap: 8px; flex-wrap: wrap; }

#phproxy-panel .tab-help {
    margin: 0 0 12px;
    color: var(--text-muted);
    font-size: 13px;
    line-height: 1.5;
}
#phproxy-panel .tab-help code {
    padding: 1px 5px;
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: 4px;
    font: 12px var(--font-mono);
}

#phproxy-panel .divider {
    margin: 18px 0;
    border: 0;
    border-top: 1px solid var(--border);
}

#phproxy-panel .section-label {
    margin: 0 0 8px;
    color: var(--text);
    font-size: 13px;
    font-weight: 600;
}

#phproxy-panel .ua-picker {
    display: grid;
    grid-template-columns: 1fr;
    gap: 8px;
}
#phproxy-panel .ua-picker select { padding: 9px 12px; }

#phproxy-panel .tab-toolbar {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 10px;
    margin-bottom: 12px;
}
#phproxy-panel .tab-toolbar .tab-help     { flex: 1 1 auto; margin: 0; }
#phproxy-panel .toolbar-toggle            { margin: 0; flex-shrink: 0; }
#phproxy-panel .toolbar-toggle button     { padding: 6px 12px; font-size: 12px; }

/* Trace tab — read-only rows for request + response headers */
#phproxy-panel .kv-card-readonly {
    padding: 8px 12px;
    font: 13px var(--font-mono);
    color: var(--text);
    word-break: break-all;
}
#phproxy-panel .kv-row-readonly .kv-card                     { background: var(--surface-2); }
#phproxy-panel .kv-row-readonly .kv-card-readonly .kv-name   { font-weight: 600; color: var(--accent); }
#phproxy-panel .kv-row-readonly .kv-card-readonly .kv-sep    { color: var(--text-muted); margin: 0 6px; }
#phproxy-panel .kv-row-readonly .kv-card-readonly .kv-val    { color: var(--text); }
#phproxy-panel .kv-card-overridden > summary { border-left: 3px solid var(--accent); }
#phproxy-panel .kv-card-overridden .kv-name  { color: var(--accent); }
#phproxy-panel .kv-badge {
    display: inline-block;
    margin-left: 8px;
    padding: 1px 7px;
    background: var(--accent-soft);
    color: var(--accent);
    border-radius: 999px;
    font: 600 10px var(--font);
    letter-spacing: .04em;
    text-transform: uppercase;
}
#phproxy-panel .kv-row-readonly .kv-card-readonly.kv-card-status {
    color: var(--accent);
    font-weight: 600;
    background: var(--accent-soft, var(--surface-2));
}

@media (max-width: 600px) {
    #phproxy-panel .prx-opt-menu   { grid-template-columns: 1fr; }
    #phproxy-panel .kv-add         { grid-template-columns: 1fr; }
    #phproxy-panel .kv-edit-cookie { grid-template-columns: 1fr; }
    #phproxy-panel .kv-edit-wide   { grid-column: span 1; }
}
PHPROXY_PANEL_CSS;
}

// Shared bounded transport. All outbound HTTP and diagnostic sockets use this policy.
function phproxy_ip_in_cidr(string $ip, string $cidr): bool
{
    [$network, $prefix] = explode('/', $cidr, 2);
    $address = @inet_pton($ip);
    $base = @inet_pton($network);
    if ($address === false || $base === false || strlen($address) !== strlen($base)) return false;
    $bits = (int) $prefix;
    $bytes = intdiv($bits, 8);
    $remainder = $bits % 8;
    if (substr($address, 0, $bytes) !== substr($base, 0, $bytes)) return false;
    return $remainder === 0 || ((ord($address[$bytes]) ^ ord($base[$bytes])) & (0xff << (8 - $remainder))) === 0;
}

function phproxy_is_public_ip(string $ip): bool
{
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        foreach (['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24',
            '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4'] as $range) {
            if (phproxy_ip_in_cidr($ip, $range)) return false;
        }
        return true;
    }
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) || !phproxy_ip_in_cidr($ip, '2000::/3')) return false;
    foreach (['2001::/23', '2001:db8::/32', '2002::/16', '3fff::/20'] as $range) if (phproxy_ip_in_cidr($ip, $range)) return false;
    return true;
}

function phproxy_normalize_host(string $host): string
{
    $host = strtolower(rtrim($host, '.'));
    if (str_starts_with($host, '[') && str_ends_with($host, ']')) $host = substr($host, 1, -1);
    if (filter_var($host, FILTER_VALIDATE_IP)) return $host;
    if ($host === '' || strlen($host) > 253 || !str_contains($host, '.')) throw new InvalidArgumentException('A fully qualified hostname is required');
    foreach (explode('.', $host) as $label) {
        if (!preg_match('/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/D', $label)) throw new InvalidArgumentException('Invalid hostname');
    }
    // Reject ambiguous numeric IPv4 forms rather than relying on libc interpretation.
    if (preg_match('/^[0-9.]+$/D', $host)) throw new InvalidArgumentException('Invalid IP address');
    return $host;
}

function phproxy_remaining_time(float $deadline): float
{
    $remaining = $deadline - microtime(true);
    if ($remaining <= 0) throw new RuntimeException('Request deadline exceeded', 408);
    return $remaining;
}

function phproxy_resolve_public_host(string $host, float $deadline): array
{
    $host = phproxy_normalize_host($host);
    phproxy_remaining_time($deadline);
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        $addresses = [$host];
    } else {
        // A trailing dot prevents resolver search-domain expansion. PHP's system
        // DNS call cannot be interrupted; OS resolver timeouts still apply here.
        $records = @dns_get_record($host . '.', DNS_A | DNS_AAAA);
        phproxy_remaining_time($deadline);
        if (!is_array($records)) throw new RuntimeException('DNS lookup failed');
        $addresses = [];
        foreach ($records as $record) {
            $address = $record['ip'] ?? $record['ipv6'] ?? null;
            if (is_string($address)) $addresses[] = $address;
        }
    }
    $addresses = array_values(array_unique($addresses));
    if (!$addresses) throw new RuntimeException('No usable destination addresses');
    foreach ($addresses as $address) if (!phproxy_is_public_ip($address)) throw new InvalidArgumentException('Destination is outside the permitted public network');
    return $addresses;
}

function phproxy_open_public_socket(string $host, int $port, bool $tls, float $deadline, array $ssl_options = [], bool $inspect_certificate = false, ?string $pinned_address = null)
{
    $host = phproxy_normalize_host($host);
    if ($port < 1 || $port > 65535) throw new InvalidArgumentException('Invalid port');
    $addresses = $pinned_address === null ? phproxy_resolve_public_host($host, $deadline) : [$pinned_address];
    foreach ($addresses as $candidate) if (!phproxy_is_public_ip($candidate)) throw new InvalidArgumentException('Destination is outside the permitted public network');
    // Choose one validated address. Never pass a hostname to the connector,
    // which would resolve it a second time after the security decision.
    $address = $addresses[0];
    $endpoint = str_contains($address, ':') ? '[' . $address . ']' : $address;
    $ssl = array_merge($ssl_options, ['peer_name' => $host, 'SNI_enabled' => true,
        'verify_peer' => !$inspect_certificate, 'verify_peer_name' => !$inspect_certificate,
        'allow_self_signed' => $inspect_certificate, 'disable_compression' => true]);
    $context = stream_context_create(['ssl' => $ssl]);
    $socket = @stream_socket_client('tcp://' . $endpoint . ':' . $port, $errno, $errstr, phproxy_remaining_time($deadline), STREAM_CLIENT_CONNECT, $context);
    if ($socket === false) throw new RuntimeException('Unable to connect to destination');
    try {
        phproxy_set_stream_deadline($socket, $deadline);
        if ($tls) {
            $method = $ssl_options['crypto_method'] ?? (STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT);
            if (@stream_socket_enable_crypto($socket, true, $method) !== true) throw new RuntimeException('TLS handshake or certificate verification failed');
        }
        phproxy_remaining_time($deadline);
        return $socket;
    } catch (Throwable $e) {
        fclose($socket);
        throw $e;
    }
}

function phproxy_set_stream_deadline($stream, float $deadline): void
{
    $remaining = phproxy_remaining_time($deadline);
    $seconds = (int) floor($remaining);
    $micros = max(1, (int) (($remaining - $seconds) * 1000000));
    stream_set_timeout($stream, $seconds, $micros);
}

function phproxy_stream_write_all($stream, string $bytes, float $deadline): void
{
    $offset = 0;
    $length = strlen($bytes);
    while ($offset < $length) {
        phproxy_set_stream_deadline($stream, $deadline);
        $written = @fwrite($stream, substr($bytes, $offset, 65536));
        if ($written === false || $written === 0) throw new RuntimeException('Upstream write failed');
        $offset += $written;
    }
}

function phproxy_stream_read($stream, int $length, float $deadline): string
{
    phproxy_set_stream_deadline($stream, $deadline);
    $data = @fread($stream, $length);
    $meta = stream_get_meta_data($stream);
    if (!empty($meta['timed_out'])) throw new RuntimeException('Upstream read timed out', 408);
    phproxy_remaining_time($deadline);
    if ($data === false || ($data === '' && !feof($stream))) throw new RuntimeException('Upstream read failed');
    return $data;
}

function phproxy_read_line($stream, float $deadline, int &$budget): string
{
    if ($budget < 2) throw new RuntimeException('Upstream headers exceed limit');
    phproxy_set_stream_deadline($stream, $deadline);
    $line = @fgets($stream, min($budget + 1, 8194));
    $meta = stream_get_meta_data($stream);
    if (!empty($meta['timed_out'])) throw new RuntimeException('Upstream read timed out', 408);
    phproxy_remaining_time($deadline);
    if ($line === false || !str_ends_with($line, "\r\n")) throw new RuntimeException('Incomplete or oversized upstream line');
    $budget -= strlen($line);
    if ($budget < 0) throw new RuntimeException('Upstream headers exceed limit');
    return substr($line, 0, -2);
}

function phproxy_read_exact($stream, int $length, float $deadline): string
{
    $out = '';
    while (strlen($out) < $length) {
        $part = phproxy_stream_read($stream, min(8192, $length - strlen($out)), $deadline);
        if ($part === '') throw new RuntimeException('Incomplete upstream body');
        $out .= $part;
    }
    return $out;
}

function phproxy_read_chunked_body($stream, float $deadline, int $limit): string
{
    $body = '';
    $line_budget = 65536;
    while (true) {
        $line = phproxy_read_line($stream, $deadline, $line_budget);
        if (!preg_match('/^([0-9a-fA-F]{1,8})(?:;[^\x00-\x1f\x7f]*)?$/D', $line, $match)) throw new RuntimeException('Invalid chunk framing');
        $size = (int) hexdec($match[1]);
        if ($size > $limit - strlen($body)) throw new RuntimeException('Upstream body exceeds limit');
        if ($size === 0) {
            $trailer_budget = 8192;
            while (($trailer = phproxy_read_line($stream, $deadline, $trailer_budget)) !== '') {
                if (!preg_match('/^[!#$%&\'*+.^_`|~0-9A-Za-z-]+:[\x09\x20-\x7e\x80-\xff]*$/D', $trailer)) throw new RuntimeException('Invalid trailer');
            }
            return $body;
        }
        $body .= phproxy_read_exact($stream, $size, $deadline);
        if (phproxy_read_exact($stream, 2, $deadline) !== "\r\n") throw new RuntimeException('Invalid chunk terminator');
    }
}

function phproxy_prepare_request_headers($input): array
{
    if (!is_array($input)) throw new InvalidArgumentException('Headers must be an object');
    $headers = [];
    $size = 0;
    $blocked = ['host', 'connection', 'content-length', 'transfer-encoding', 'te', 'trailer', 'upgrade', 'keep-alive', 'proxy-authorization', 'proxy-connection', 'expect'];
    foreach ($input as $name => $value) {
        if (!is_string($name) || !preg_match('/^[!#$%&\'*+.^_`|~0-9A-Za-z-]+$/D', $name) || !is_scalar($value)) throw new InvalidArgumentException('Invalid request header');
        $name = strtolower($name);
        $value = (string) $value;
        if (preg_match('/[\x00-\x08\x0a-\x1f\x7f]/', $value)) throw new InvalidArgumentException('Invalid request header value');
        if (in_array($name, $blocked, true)) continue;
        if (isset($headers[$name])) throw new InvalidArgumentException('Duplicate request header');
        $size += strlen($name) + strlen($value) + 4;
        if ($size > 32768) throw new InvalidArgumentException('Request headers exceed 32 KiB');
        $headers[$name] = $value;
    }
    return $headers;
}

function phproxy_parse_http_url(string $url): array
{
    if ($url === '' || strlen($url) > 8192 || preg_match('/[\x00-\x20\x7f\\\\]/', $url)) throw new InvalidArgumentException('Invalid URL');
    $parts = @parse_url($url);
    if (!is_array($parts) || !isset($parts['scheme'], $parts['host']) || isset($parts['user']) || isset($parts['pass'])) throw new InvalidArgumentException('URL must have a host and no credentials');
    $scheme = strtolower($parts['scheme']);
    if (!in_array($scheme, ['http', 'https'], true)) throw new InvalidArgumentException('Only HTTP and HTTPS are supported');
    $host = phproxy_normalize_host($parts['host']);
    $port = $parts['port'] ?? ($scheme === 'https' ? 443 : 80);
    if ($port < 1 || $port > 65535) throw new InvalidArgumentException('Invalid port');
    $display_host = str_contains($host, ':') ? '[' . $host . ']' : $host;
    $authority = $display_host . ($port !== ($scheme === 'https' ? 443 : 80) ? ':' . $port : '');
    $path = ($parts['path'] ?? '') ?: '/';
    if ($path[0] !== '/') throw new InvalidArgumentException('Invalid request target');
    $path .= isset($parts['query']) ? '?' . $parts['query'] : '';
    return ['scheme' => $scheme, 'host' => $host, 'port' => $port, 'authority' => $authority,
        'origin' => $scheme . '://' . $display_host . ':' . $port, 'path' => $path];
}

function phproxy_remove_dot_segments(string $path): string
{
    $output = '';
    while ($path !== '') {
        if (str_starts_with($path, '../')) $path = substr($path, 3);
        elseif (str_starts_with($path, './')) $path = substr($path, 2);
        elseif (str_starts_with($path, '/./')) $path = substr($path, 2);
        elseif ($path === '/.') $path = '/';
        elseif (str_starts_with($path, '/../') || $path === '/..') {
            $path = $path === '/..' ? '/' : substr($path, 3);
            $output = preg_replace('#/?[^/]*$#', '', $output);
        } elseif ($path === '.' || $path === '..') $path = '';
        else {
            $end = strpos($path, '/', $path[0] === '/' ? 1 : 0);
            if ($end === false) { $output .= $path; $path = ''; }
            else { $output .= substr($path, 0, $end); $path = substr($path, $end); }
        }
    }
    return $output;
}

function phproxy_resolve_http_location(string $base, string $location): string
{
    if (strlen($location) > 8192 || preg_match('/[\x00-\x20\x7f\\\\]/', $location)) throw new RuntimeException('Invalid redirect location');
    $base_parts = parse_url($base);
    $ref = parse_url($location);
    if ($ref === false) throw new RuntimeException('Invalid redirect location');
    if (isset($ref['scheme'])) {
        phproxy_parse_http_url($location);
        return $location;
    }
    if (str_starts_with($location, '//')) {
        $result = $base_parts['scheme'] . ':' . $location;
        phproxy_parse_http_url($result);
        return $result;
    }
    $target = phproxy_parse_http_url($base);
    $base_path = $base_parts['path'] ?? '/';
    $ref_path = $ref['path'] ?? '';
    if ($ref_path === '') {
        $path = $base_path;
        $query = $ref['query'] ?? $base_parts['query'] ?? null;
    } else {
        $path = $ref_path[0] === '/' ? $ref_path : substr($base_path, 0, (int) strrpos($base_path, '/') + 1) . $ref_path;
        $path = phproxy_remove_dot_segments($path);
        $query = $ref['query'] ?? null;
    }
    $result = $target['scheme'] . '://' . $target['authority'] . ($path ?: '/') . ($query !== null ? '?' . $query : '');
    phproxy_parse_http_url($result);
    return $result;
}

function phproxy_read_http_response($stream, string $method, float $deadline, int $limit): array
{
    $budget = 65536;
    $interim = 0;
    do {
        $status_line = phproxy_read_line($stream, $deadline, $budget);
        if (!preg_match('#^HTTP/1\.[01] ([1-5][0-9]{2})(?: ([\x20-\x7e\x80-\xff]*))?$#D', $status_line, $match)) throw new RuntimeException('Invalid upstream status');
        $status = (int) $match[1];
        $status_text = $match[2] ?? '';
        $values = [];
        $header_lines = [];
        while (($line = phproxy_read_line($stream, $deadline, $budget)) !== '') {
            if (!preg_match('/^([!#$%&\'*+.^_`|~0-9A-Za-z-]+):([\x09\x20-\x7e\x80-\xff]*)$/D', $line, $match)) throw new RuntimeException('Invalid upstream header');
            $name = strtolower($match[1]);
            $value = trim($match[2]);
            $values[$name][] = $value;
            $header_lines[] = ['name' => $name, 'value' => $value];
        }
        if ($status === 101 || ++$interim > 5) throw new RuntimeException('Unsupported upstream protocol response');
    } while ($status < 200);
    $no_body = $method === 'HEAD' || in_array($status, [204, 304], true);
    $body = '';
    if (!$no_body) {
        if (isset($values['transfer-encoding'], $values['content-length'])) throw new RuntimeException('Ambiguous upstream framing');
        if (isset($values['transfer-encoding'])) {
            if (count($values['transfer-encoding']) !== 1 || strtolower($values['transfer-encoding'][0]) !== 'chunked') throw new RuntimeException('Unsupported transfer encoding');
            $body = phproxy_read_chunked_body($stream, $deadline, $limit);
        } elseif (isset($values['content-length'])) {
            $length = $values['content-length'][0];
            if (count($values['content-length']) !== 1 || !preg_match('/^[0-9]{1,10}$/D', $length) || (float) $length > $limit) throw new RuntimeException('Invalid or oversized upstream body length');
            $body = phproxy_read_exact($stream, (int) $length, $deadline);
        } else {
            while (!feof($stream)) {
                $part = phproxy_stream_read($stream, min(8192, $limit - strlen($body) + 1), $deadline);
                if ($part === '') break;
                $body .= $part;
                if (strlen($body) > $limit) throw new RuntimeException('Upstream body exceeds limit');
            }
        }
    }
    $decoded = false;
    if (!$no_body && isset($values['content-encoding']) && $body !== '') {
        $encoding = strtolower(implode(', ', $values['content-encoding']));
        if ($encoding === 'gzip' && function_exists('gzdecode')) {
            $result = @gzdecode($body, $limit);
            if ($result === false) throw new RuntimeException('Invalid or oversized compressed response');
            $body = $result;
            $decoded = true;
        } elseif ($encoding === 'deflate' && function_exists('gzuncompress')) {
            $result = @gzuncompress($body, $limit);
            if ($result === false) $result = @gzinflate($body, $limit);
            if ($result === false) throw new RuntimeException('Invalid or oversized compressed response');
            $body = $result;
            $decoded = true;
        }
    }
    phproxy_remaining_time($deadline);
    $drop = array_fill_keys(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'proxy-connection', 'te', 'trailer', 'transfer-encoding', 'upgrade', 'content-length', 'set-cookie'], true);
    foreach ($values['connection'] ?? [] as $connection) foreach (explode(',', $connection) as $name) $drop[strtolower(trim($name))] = true;
    if ($decoded) $drop['content-encoding'] = true;
    $headers = [];
    $safe_lines = [];
    foreach ($header_lines as $line) {
        if (isset($drop[$line['name']])) continue;
        $safe_lines[] = $line;
        $headers[$line['name']] = isset($headers[$line['name']]) ? $headers[$line['name']] . ', ' . $line['value'] : $line['value'];
    }
    $set_cookie_headers = $values['set-cookie'] ?? [];
    $set_cookies = [];
    foreach ($set_cookie_headers as $cookie) $set_cookies[] = phproxy_parse_set_cookie($cookie);
    return ['status' => $status, 'status_text' => $status_text, 'headers' => $headers, 'header_lines' => $safe_lines,
        'set_cookie_headers' => $set_cookie_headers, 'set_cookies' => $set_cookies, 'body_raw' => $body];
}

function phproxy_parse_set_cookie(string $header): array
{
    $parts = preg_split('/;\s*/', $header);
    $first = explode('=', (string) array_shift($parts), 2);
    $cookie = ['name' => $first[0], 'value' => $first[1] ?? '', 'domain' => '', 'path' => '', 'expires' => '', 'max_age' => null, 'secure' => false, 'httponly' => false, 'samesite' => ''];
    foreach ($parts as $part) {
        [$name, $value] = array_pad(explode('=', $part, 2), 2, '');
        $name = strtolower(trim($name));
        if ($name === 'secure' || $name === 'httponly') $cookie[$name] = true;
        elseif ($name === 'max-age') $cookie['max_age'] = (int) $value;
        elseif (in_array($name, ['domain', 'path', 'expires', 'samesite'], true)) $cookie[$name] = trim($value);
    }
    return $cookie;
}

function phproxy_redirect_request(array $target, array $next, int $status, string $method, array $headers, string $body): array
{
    if ($target['scheme'] === 'https' && $next['scheme'] !== 'https') throw new RuntimeException('HTTPS downgrade redirect refused');
    if (($status === 303 && $method !== 'HEAD') || (in_array($status, [301, 302], true) && $method === 'POST')) {
        $method = 'GET';
        $body = '';
        foreach (['content-type', 'content-encoding', 'content-language', 'content-location', 'digest'] as $name) unset($headers[$name]);
    }
    if ($target['origin'] !== $next['origin']) {
        // Custom credential names cannot be enumerated safely. Carry only
        // representation preferences to another origin; discard cookies and auth.
        $headers = array_intersect_key($headers, array_flip(['accept', 'accept-language', 'accept-encoding', 'user-agent']));
        if ($body !== '') throw new RuntimeException('Cross-origin request-body redirect refused');
    }
    return [$method, $headers, $body];
}

function phproxy_valid_dns_name(string $host): bool
{
    $host = rtrim($host, '.');
    if ($host === '' || strlen($host) > 253) return false;
    foreach (explode('.', $host) as $label) {
        if (!preg_match('/^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$/D', $label)) return false;
    }
    return true;
}

function phproxy_api_origin_allowed(string $origin, string $public_url): bool
{
    $parts = @parse_url($origin);
    if (!is_array($parts) || isset($parts['path']) || isset($parts['query']) || isset($parts['fragment'])) return false;
    $normalized = phproxy_request_origin($origin);
    return $normalized !== '' && $normalized === phproxy_request_origin($public_url);
}

/** Validate browsing context and produce a fresh proxy-local return URL. */
function phproxy_browsing_return(string $return_to, string $return_url, string $tab = 'options'): ?string
{
    global $_config, $_flags, $_frozen_flags;
    $script = phproxy_public_script_url($_SERVER);
    $prefix = $script . '?' . $_config['url_var_name'] . '=';
    if (!str_starts_with($return_to, $prefix) || strlen($return_to) > 32768) return null;
    $token = substr($return_to, strlen($prefix));
    if ($token === '' || preg_match('/[\x00-\x20\x7f&#]/', $token)) return null;
    try {
        $target = phproxy_parse_http_url($return_url);
    } catch (Throwable $e) {
        return null;
    }
    $url = $target['scheme'] . '://' . $target['authority'] . $target['path'];
    $allowed_tabs = ['options', 'cookies', 'headers', 'response', 'network', 'cli', 'ip', 'dns', 'port', 'cert'];
    if (!in_array($tab, $allowed_tabs, true)) $tab = 'options';
    if (in_array($tab, ['port', 'cert'], true) && getenv('PHPROXY_DIAGNOSTICS') !== '1') $tab = 'options';
    // Actions execute before the normal flag decoder. Reuse the saved encoding
    // mode, while key rotation/expiry deliberately produces a fresh URL token.
    $saved_flags = $_flags;
    $cookie_flags = $_COOKIE['flags'] ?? '';
    if (is_string($cookie_flags) && preg_match('/^[a-f0-9]{1,5}$/iD', $cookie_flags)) {
        $bits = substr(str_pad(base_convert($cookie_flags, 16, 2), count($_flags), '0', STR_PAD_LEFT), -count($_flags));
        $offset = 0;
        foreach ($_flags as $name => $value) {
            $_flags[$name] = !empty($_frozen_flags[$name]) ? $value : (int) $bits[$offset];
            $offset++;
        }
    }
    try {
        return $prefix . encode_url($url) . '&panel=' . $tab;
    } finally {
        $_flags = $saved_flags;
    }
}

/** Management controls rendered only in the trusted outer browsing shell. */
function phproxy_browsing_panel(string $current_proxy_url, string $current_url): string
{
    $buckets = phproxy_panel_buckets();
    $trace = phproxy_trace_entries();
    $globals = [
        '_show_raw_values' => !empty($_COOKIE['phproxy-show-raw']),
        '_visible_cookies' => $buckets['cookies'],
        '_custom_headers' => $buckets['headers'],
        '_header_origins' => $buckets['header_origins'] ?? [],
        '_ua_presets' => phproxy_ua_presets(),
    ];
    $previous = [];
    foreach ($globals as $name => $value) {
        $previous[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? null];
        $GLOBALS[$name] = $value;
    }
    $active = is_string($_GET['panel'] ?? null) ? $_GET['panel'] : 'options';
    if (!in_array($active, ['options', 'cookies', 'headers', 'response', 'network', 'cli', 'ip', 'dns', 'port', 'cert'], true)
        || (in_array($active, ['port', 'cert'], true) && getenv('PHPROXY_DIAGNOSTICS') !== '1')
        || ($active === 'response' && !$trace)) $active = 'options';
    $escape = static fn(string $value): string => htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $script = phproxy_public_script_url($_SERVER);
    $form_id = 'phproxy-browsing-options';
    $level = ob_get_level();
    ob_start();
    try {
        echo '<form id="' . $form_id . '" class="tab-actions" method="post" action="' . $escape($script) . '">';
        echo phproxy_csrf_field();
        echo '<input type="hidden" name="' . $escape($GLOBALS['_config']['url_var_name']) . '" value="' . $escape($current_url) . '">';
        echo '<input type="hidden" name="phproxy_panel_context" value="1">';
        echo '<button class="button-submit" type="submit">Apply options and reload this page</button></form>';
        phproxy_render_panel_tabs(
            return_to: $current_proxy_url,
            show_response: !empty($trace),
            request_pairs: $trace['request_pairs'] ?? [],
            response_pairs: $trace['response_pairs'] ?? [],
            request_line: $trace['request_line'] ?? '',
            active_tab: $active,
            form_id: $form_id,
            show_cli: true,
            cli_url: $current_url,
            cli_method: $trace['method'] ?? 'GET',
            cli_headers: $trace['request_pairs'] ?? [],
            show_network: true,
            network_entries: phproxy_network_entries(),
            network_current_url: $current_url,
            show_netchecks: true,
            show_cert: getenv('PHPROXY_DIAGNOSTICS') === '1',
            cert_host: (string) parse_url($current_url, PHP_URL_HOST),
            cert_port: (int) (parse_url($current_url, PHP_URL_PORT) ?: 443),
            return_url: $current_url
        );
        return (string) ob_get_clean();
    } finally {
        while (ob_get_level() > $level) ob_end_clean();
        foreach ($previous as $name => [$present, $value]) {
            if ($present) $GLOBALS[$name] = $value;
            else unset($GLOBALS[$name]);
        }
    }
}
