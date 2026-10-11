<?php
require __DIR__ . '/bootstrap.php';

$_SERVER = ['HTTP_HOST' => 'localhost:8080', 'SERVER_PORT' => 80, 'SCRIPT_NAME' => '/index.php'];
same('http://localhost:8080/index.php', phproxy_public_script_url($_SERVER, ''), 'published container port preserved');
same('https://proxy.example.test:8443/index.php', phproxy_public_script_url($_SERVER, 'https://proxy.example.test:8443/'), 'configured HTTPS public URL');
same('https://proxy.example.test/index.php', phproxy_public_script_url($_SERVER, 'https://proxy.example.test'), 'configured host without path');
same('http://localhost:8080/index.php', phproxy_public_script_url($_SERVER + ['HTTP_X_FORWARDED_PROTO' => 'https'], ''), 'untrusted forwarded scheme ignored');
same('https://example.test:443', phproxy_request_origin('https://EXAMPLE.test/page'), 'origin includes canonical port');
same('', phproxy_request_origin('/relative'), 'custom headers require absolute origin');

$now = 1800000000;
$cookie = phproxy_cookie_parse('session=alpha; Path=/account; Secure; HttpOnly; Max-Age=120; SameSite=Lax', 'https://www.example.test/account/login', false, $now);
check($cookie !== null, 'normal upstream cookie accepted');
same($now + 120, $cookie['expires'], 'Max-Age expiry retained');
same(true, $cookie['host_only'], 'cookie jar uses exact hosts');
same(true, $cookie['httponly'], 'HttpOnly metadata retained');
same('session=alpha', phproxy_cookie_header([$cookie], 'https://www.example.test/account/profile', true, $now), 'matching host and path forwarded');
same('', phproxy_cookie_header([$cookie], 'https://other.example.test/account/profile', true, $now), 'cookie stays with its host');
same('', phproxy_cookie_header([$cookie], 'https://www.example.test/accounts', true, $now), 'cookie path uses segment boundary');
same('', phproxy_cookie_header([$cookie], 'http://www.example.test/account', true, $now), 'Secure cookies require HTTPS');
same('', phproxy_cookie_header([$cookie], 'https://www.example.test/account', false, $now), 'disabled cookies are not forwarded');
same('', phproxy_cookie_header([$cookie], 'https://www.example.test/account', true, $now + 121), 'expired cookies are not forwarded');
$parentCookie = phproxy_cookie_parse('preference=light; Domain=example.test', 'https://www.example.test/account/page', false, $now);
same('www.example.test', $parentCookie['domain'], 'parent-domain cookies narrowed to setting host');
same('/account', $parentCookie['path'], 'default cookie path derived from request directory');
$sessionCookie = phproxy_cookie_parse('session=alpha; Max-Age=120', 'https://www.example.test/', true, $now);
same(0, $sessionCookie['expires'], 'session-only setting clears future expiry');
$deleted = phproxy_cookie_parse('session=gone; Max-Age=0', 'https://www.example.test/', true, $now);
check($deleted['expires'] > 0 && $deleted['expires'] < $now, 'deletion survives session-only conversion');
$epochDeleted = phproxy_cookie_parse('session=gone; Expires=Thu, 01 Jan 1970 00:00:00 GMT', 'https://www.example.test/', false, $now);
same(1, $epochDeleted['expires'], 'epoch expiry represents deletion, not a session cookie');

$body = phproxy_browser_body(['q' => 'a b', 'nested' => ['x' => 'value']], [], 'application/x-www-form-urlencoded');
same('q=a+b&nested%5Bx%5D=value', $body['body'], 'browser form fields preserve normal encoding');
$json = '{"value":"normal"}';
same($json, phproxy_browser_body([], [], 'application/json', $json)['body'], 'raw JSON POST preserved');
check(phproxy_custom_header_allowed('Authorization', 'Bearer example-token'), 'scoped credential header supported');
check(!phproxy_custom_header_allowed('Content-Length', '10'), 'transport owns message length');

$sessionDir = sys_get_temp_dir() . '/phproxy-browser-test-' . bin2hex(random_bytes(6));
mkdir($sessionDir, 0700);
session_save_path($sessionDir);
session_name('PHPROXY_TEST_SESSION');
try {
    $csrf = phproxy_csrf_token();
    same(PHP_SESSION_NONE, session_status(), 'session lock released after token creation');
    $_POST = ['csrf_token' => $csrf];
    check(phproxy_csrf_valid(), 'trusted form token accepted');
    $navigationToken = phproxy_navigation_token();
    same($navigationToken, phproxy_navigation_token(), 'navigation token stable within session');
    $_POST = ['csrf_token' => $navigationToken];
    check(!phproxy_csrf_valid(), 'browsing token cannot authorize management actions');
    $_POST = [];
    check(!phproxy_csrf_valid(), 'missing form token rejected');

    $_COOKIE = ['phproxy-seed-bits' => '256'];
    $token = phproxy_encrypt_url('https://www.example.test/article');
    same('https://www.example.test/article', phproxy_decrypt_url($token), 'server-side URL encryption round trip');
    check(!isset($_COOKIE['phproxy-seed']), 'URL key is never stored in browser cookies');
    check(phproxy_seed_present(), 'unexpired key present');
    phproxy_state_open();
    $_SESSION['phproxy_seed']['expires'] = time() - 1;
    phproxy_state_close();
    unset($GLOBALS['_phproxy_seed_cache']);
    same(null, phproxy_decrypt_url($token), 'server enforces key expiration');

    phproxy_net_log('https://www.example.test/one', 'GET', 200, 'text/html', 20, 1, 1.1, 1.2);
    // A stale in-memory snapshot must not replace another completed request.
    $_SESSION = ['phproxy_network' => []];
    phproxy_net_log('https://www.example.test/two', 'GET', 200, 'text/html', 30, 2, 2.1, 2.2);
    same(2, count(phproxy_network_entries()), 'network log append merges current session contents');
    same(PHP_SESSION_NONE, session_status(), 'logging releases the session lock');

    phproxy_store_cookies(['session=alpha; Path=/'], 'https://www.example.test/', true, true);
    same(1, count(phproxy_panel_buckets()['cookies']), 'management reads server cookie jar');
    phproxy_store_cookies(['session=gone; Path=/; Max-Age=0'], 'https://www.example.test/', true, true);
    same(0, count(phproxy_panel_buckets()['cookies']), 'upstream deletion removes jar entry');
} finally {
    phproxy_state_open();
    session_destroy();
    foreach (glob($sessionDir . '/*') ?: [] as $file) unlink($file);
    rmdir($sessionDir);
}

echo "Browser checks passed\n";
