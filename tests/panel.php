<?php
require __DIR__ . '/bootstrap.php';

$_SERVER = ['HTTP_HOST' => 'localhost:8080', 'SERVER_PORT' => 80, 'SCRIPT_NAME' => '/index.php'];
$_config = ['url_var_name' => '_proxurl', 'flags_var_name' => '_proxfl', 'get_form_name' => '_proxgfn'];
$_flags = array_fill_keys(['encrypt_url', 'strip_tracking', 'send_gpc', 'send_dnt', 'block_media', 'block_fonts', 'block_3p', 'strip_iframes', 'include_form', 'remove_scripts', 'accept_cookies', 'show_images', 'show_referer', 'rotate13', 'base64_encode', 'strip_meta', 'strip_title', 'session_cookies'], 0);
$_flags['encrypt_url'] = $_flags['include_form'] = $_flags['remove_scripts'] = $_flags['show_images'] = 1;
$_frozen_flags = array_fill_keys(array_keys($_flags), 0);
$_labels = [];
foreach ($_flags as $name => $value) $_labels[$name] = [$name, $name];
$_script_url = phproxy_public_script_url($_SERVER, '');
$_GET = ['panel' => 'headers'];
$_COOKIE = [];
$current = 'https://www.example.test/inbox?page=2&view=all';
$sessionDir = sys_get_temp_dir() . '/phproxy-panel-test-' . bin2hex(random_bytes(6));
mkdir($sessionDir, 0700);
session_save_path($sessionDir);
session_name('PHPROXY_PANEL_TEST');
try {
    $csrf = phproxy_csrf_token();
    $oldToken = encode_url($current);
    $proxy = $_script_url . '?_proxurl=' . $oldToken;
    $return = phproxy_browsing_return($proxy, $current, 'headers');
    parse_str((string) parse_url($return, PHP_URL_QUERY), $returned);
    same($current, phproxy_decrypt_url($returned['_proxurl']), 'management return retains current destination');
    same('headers', $returned['panel'], 'management return reopens affected tab');
    same(null, phproxy_browsing_return('https://other.example/index.php?_proxurl=sample', $current), 'return context must be this proxy');
    same(null, phproxy_browsing_return($proxy . '&extra=value', $current), 'return context does not accept extra route fields');
    same(null, phproxy_browsing_return($proxy, '/relative'), 'return destination must be an absolute HTTP URL');

    phproxy_state_open();
    unset($_SESSION['phproxy_seed']);
    phproxy_state_close();
    unset($GLOBALS['_phproxy_seed_cache']);
    $return = phproxy_browsing_return($proxy, $current, 'options');
    parse_str((string) parse_url($return, PHP_URL_QUERY), $returned);
    same($current, phproxy_decrypt_url($returned['_proxurl']), 'rotating seed creates a usable fresh return token');
    check($returned['_proxurl'] !== $oldToken, 'rotated return does not reuse obsolete token');

    $defaults = $_flags;
    foreach (['base64_encode', 'rotate13', 'none'] as $encoding) {
        $saved = $defaults;
        $saved['encrypt_url'] = $saved['base64_encode'] = $saved['rotate13'] = 0;
        if ($encoding !== 'none') $saved[$encoding] = 1;
        $_COOKIE['flags'] = base_convert(implode('', array_values($saved)), 2, 16);
        $return = phproxy_browsing_return($proxy, $current, 'cookies');
        parse_str((string) parse_url($return, PHP_URL_QUERY), $returned);
        $decoded = match ($encoding) {
            'base64_encode' => base64_decode($returned['_proxurl']),
            'rotate13' => str_rot13($returned['_proxurl']),
            default => $returned['_proxurl'],
        };
        same($current, $decoded, $encoding . ' return uses saved URL encoding');
        same($defaults, $_flags, 'return encoding restores active global flags');
    }
    unset($_COOKIE['flags']);

    phproxy_state_open();
    $_SESSION['phproxy_headers'] = ['Accept-Language' => ['value' => 'en-GB', 'origin' => 'https://www.example.test:443']];
    $_SESSION['phproxy_trace'] = ['url' => $current, 'method' => 'GET', 'request_line' => 'GET /inbox HTTP/1.1', 'request_pairs' => [['authorization', '[redacted]']], 'response_pairs' => [['content-type', 'text/html']]];
    phproxy_state_close();
    $GLOBALS['_custom_headers'] = ['marker' => 'original'];
    ob_start();
    $markup = phproxy_browsing_panel($proxy, $current);
    $unexpected_output = ob_get_clean();
    same('', $unexpected_output, 'browsing panel returns markup without emitting it');
    same(['marker' => 'original'], $GLOBALS['_custom_headers'], 'browsing panel restores temporary template globals');
    check(str_contains($markup, 'id="phproxy-browsing-options"'), 'dedicated options form rendered');
    check(str_contains($markup, 'form="phproxy-browsing-options"'), 'options inputs submit through dedicated form');
    check(str_contains($markup, 'name="_proxurl" value="' . htmlspecialchars($current, ENT_QUOTES, 'UTF-8') . '"'), 'options apply preserves full current URL');
    check(str_contains($markup, 'name="phproxy_panel_context" value="1"'), 'options apply preserves panel context');
    check(str_contains($markup, 'id="tab-headers" checked'), 'requested panel tab opens');
    check(str_contains($markup, 'value="https://www.example.test:443"'), 'header editor retains origin scope');
    preg_match_all('~<form\b[^>]*action="\?action=[^"]+"[^>]*>(.*?)</form>~s', $markup, $forms);
    check(count($forms[1]) >= 8, 'management forms rendered');
    foreach ($forms[1] as $form) {
        check(str_contains($form, 'name="csrf_token" value="' . $csrf . '"'), 'management form contains private CSRF token');
        check(str_contains($form, 'name="return_to"'), 'management form retains proxy-local return context');
        check(str_contains($form, 'name="return_url" value="' . htmlspecialchars($current, ENT_QUOTES, 'UTF-8') . '"'), 'management form retains fresh-encoding destination');
    }
} finally {
    phproxy_state_open();
    session_destroy();
    foreach (glob($sessionDir . '/*') ?: [] as $file) unlink($file);
    rmdir($sessionDir);
}
echo "Panel tests passed\n";
