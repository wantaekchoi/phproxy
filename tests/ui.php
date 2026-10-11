<?php
require __DIR__ . '/bootstrap.php';

$_flags = array_fill_keys(['encrypt_url', 'rotate13', 'base64_encode', 'strip_tracking', 'block_3p', 'strip_title', 'remove_scripts', 'strip_iframes', 'block_media', 'block_fonts', 'strip_meta'], 0);
$_flags['show_images'] = 1;
$_config = ['url_var_name' => '_proxurl', 'flags_var_name' => '_proxfl', 'get_form_name' => '_proxgfn'];
$_script_url = 'http://localhost:8080/index.php';
$_iflags = '0';
$_url = 'https://example.com/dir/page.html';
$_url_parts = [];
check(url_parse($_url, $_url_parts), 'fixture URL parses');
$_base = $_url_parts;

$policy = phproxy_content_policy();
check(str_contains(phproxy_browsing_shell_policy(), "font-src 'self' data:"), 'inherited shell policy permits embedded fonts');
check(str_contains(phproxy_browsing_shell_policy(), "media-src 'self' data:"), 'inherited shell policy permits embedded media');
check(str_contains($policy, "script-src 'none'"), 'scripts disabled by default');
check(str_contains($policy, 'allow-same-origin'), 'blocked-script mode retains session-bound stylesheet and font access');
check(!str_contains($policy, 'allow-scripts'), 'same-origin mode never enables sandbox scripts');
check(!str_contains(phproxy_content_policy(true), 'allow-same-origin'), 'script opt-in preserves opaque origin');
check(str_contains(phproxy_content_policy(true), 'allow-scripts'), 'script opt-in remains available');
foreach ([false, true] as $allowScripts) {
    $selectedPolicy = phproxy_content_policy($allowScripts);
    check(!(str_contains($selectedPolicy, 'allow-scripts') && str_contains($selectedPolicy, 'allow-same-origin')),
        'script execution and same-origin sandbox grants are mutually exclusive');
}
$bar = phproxy_browsing_bar('<html><body><p>Article</p></body></html>', $_script_url, $_url, 'navigation-test-token');
check(str_contains($bar, 'http://localhost:8080/index.php'), 'settings link retains published port');
check(str_contains($bar, 'value="https://example.com/dir/page.html"'), 'bar displays the current upstream page');
check(str_contains($bar, 'name="phproxy_browse_url"'), 'bar supports URL navigation');
check(!str_contains($bar, 'name="csrf_token"') && !str_contains($bar, 'panel_action'), 'bar contains no management token or action');
check(str_contains($bar, 'id="phproxy-settings-button"'), 'settings open inside the browsing view');
check(!str_contains($bar, 'target="_blank"'), 'trusted toolbar does not open new tabs');
preg_match('/<iframe[^>]*srcdoc="([^"]*)"/', $bar, $frame);
same('<html><body><p>Article</p></body></html>', html_entity_decode($frame[1], ENT_QUOTES | ENT_HTML5, 'UTF-8'), 'complete upstream document preserved in separate viewport');
check(str_contains($bar, 'grid-template-rows:auto minmax(0,1fr)'), 'page viewport reserves actual toolbar height');
$private_panel = '<form><input name="csrf_token" value="private-management-token"></form>';
$isolated = phproxy_browsing_bar('<body>Article</body>', $_script_url, $_url, 'navigation-test-token', $private_panel, true);
preg_match('/<iframe[^>]*sandbox="([^"]*)"[^>]*srcdoc="([^"]*)"/', $isolated, $isolated_frame);
check(str_contains($isolated_frame[1], 'allow-scripts') && !str_contains($isolated_frame[1], 'allow-same-origin'), 'upstream script mode cannot access trusted settings');
check(!str_contains(html_entity_decode($isolated_frame[2], ENT_QUOTES | ENT_HTML5, 'UTF-8'), 'private-management-token'), 'management forms stay outside upstream document');
same('<p>Пример</p>', phproxy_html_utf8(mb_convert_encoding('<p>Пример</p>', 'Windows-1251', 'UTF-8'), 'text/html; charset=windows-1251'), 'legacy document charset normalized for srcdoc');
$unicode_document = '<p>Пример</p>';
same($unicode_document, phproxy_html_utf8("\xEF\xBB\xBF" . $unicode_document, 'text/html; charset=windows-1252'), 'UTF-8 BOM overrides conflicting HTTP charset and is removed');
foreach (['UTF-16LE' => "\xFF\xFE", 'UTF-16BE' => "\xFE\xFF"] as $encoding => $bom) {
    $encoded_document = $bom . mb_convert_encoding($unicode_document, $encoding, 'UTF-8');
    same($unicode_document, phproxy_html_utf8($encoded_document, 'text/html'), $encoding . ' BOM supplies missing charset');
    same($unicode_document, phproxy_html_utf8($encoded_document, 'text/html; charset=windows-1252'), $encoding . ' BOM overrides conflicting HTTP charset');
}
$opaque_bar = phproxy_browsing_bar('<body>Article</body>', $_script_url, $_url);
check(str_contains($opaque_bar, 'readonly') && !str_contains($opaque_bar, '<form'), 'opaque script mode navigates through trusted home');
$quoted_bar = phproxy_browsing_bar('<body>Article</body>', $_script_url, 'https://example.com/?q="quoted"&lang=en');
check(str_contains($quoted_bar, 'value="https://example.com/?q=&quot;quoted&quot;&amp;lang=en"'), 'bar escapes the current URL');
$policy_meta = phproxy_rewrite_html('<head><meta http-equiv="Content-Security-Policy" content="form-action https://example.com"><meta charset="UTF-8"></head>');
check(!str_contains($policy_meta, 'Content-Security-Policy'), 'upstream meta policy does not block rewritten assets or navigation');
check(str_contains($policy_meta, 'charset="UTF-8"'), 'unrelated meta tags preserved');

$html = '<html><body><p>Before</p>' . str_repeat('<a href="next.html">Next</a>', 100) . '<p>After</p></body></html>';
$rewritten = phproxy_rewrite_html($html);
same(100, substr_count($rewritten, '_proxurl='), 'duplicate tags rewritten exactly once');
check(str_contains($rewritten, '<p>Before</p>') && str_contains($rewritten, '<p>After</p>'), 'unmodified content retained');
$lazy = phproxy_rewrite_html('<img data-src="photo.png">');
preg_match('/\ssrc="([^"]+)"/', $lazy, $src);
preg_match('/\bdata-src="([^"]+)"/', $lazy, $data);
same($data[1], $src[1], 'lazy image uses already rewritten source');

$_flags['strip_meta'] = 1;
$meta = phproxy_rewrite_html('<head><meta name="description" content="Text"><title>Title</title></head>');
check(!str_contains($meta, '<meta'), 'meta removal preserves replacement offsets');
check(str_contains($meta, '<title>Title</title>'), 'meta removal keeps adjacent tags');

function ui_navigation_tag(string $html, string $id): string
{
    preg_match('/<(?:a|area|form|button|input)\b[^>]*\bid="' . preg_quote($id, '/') . '"[^>]*>/', $html, $match);
    check(isset($match[0]), 'navigation fixture ' . $id . ' exists');
    return $match[0];
}

$nav = phproxy_rewrite_html(
    '<a id="ordinary" href="next.html">Next</a>'
    . '<a id="new-window" href="next.html" target="_blank">New window</a>'
    . '<a id="fragment" href="#details" target="_top">Details</a>'
    . '<area id="map-link" href="next.html"><area id="map-fragment" href="#map">'
    . '<form id="search" action="/search"><input name="q"></form>'
    . '<form id="post" method="post"><button id="submit">Save</button></form>'
    . '<form id="new-form" target="_blank"><button id="inherit">Open</button></form>'
    . '<button id="override" formtarget="result">Submit</button>'
    . '<input id="image-submit" type="image" formtarget="_self">'
    . '<button id="new-submit" formtarget="_blank">New</button>',
    true
);
foreach (['ordinary', 'map-link', 'search', 'post'] as $id) {
    check(str_contains(ui_navigation_tag($nav, $id), 'target="_top"'), $id . ' replaces the outer frame shell');
}
foreach (['new-window', 'new-form'] as $id) {
    check(str_contains(ui_navigation_tag($nav, $id), 'target="_blank"'), $id . ' preserves requested new window');
}
check(str_contains(ui_navigation_tag($nav, 'fragment'), 'href="about:srcdoc#details"')
    && str_contains(ui_navigation_tag($nav, 'fragment'), 'target="_self"'), 'fragment stays inside current srcdoc document');
check(str_contains(ui_navigation_tag($nav, 'map-fragment'), 'href="about:srcdoc#map"'), 'image-map fragment stays in frame');
check(str_contains(ui_navigation_tag($nav, 'post'), '_proxurl='), 'actionless POST has an explicit proxied action');
check(!str_contains(ui_navigation_tag($nav, 'inherit'), 'formtarget='), 'submit control inherits form new-window target');
foreach (['override', 'image-submit'] as $id) {
    check(str_contains(ui_navigation_tag($nav, $id), 'formtarget="_top"'), $id . ' cannot replace only the child frame');
}
check(str_contains(ui_navigation_tag($nav, 'new-submit'), 'formtarget="_blank"'), 'explicit new-window submit preserved');
$emptyForm = phproxy_rewrite_html('<form><input name="q"></form>', true);
check(str_contains($emptyForm, 'target="_top"') && str_contains($emptyForm, 'name="_proxgfn"'), 'attribute-free GET form leaves the frame');
$plainNav = phproxy_rewrite_html('<a href="#details">Details</a><form method="post">Save</form>');
check(str_contains($plainNav, 'href="#details"') && !str_contains($plainNav, 'target="_top"'), 'unframed navigation keeps its original target behavior');
$savedBase = $_base;
$baseNav = phproxy_rewrite_html('<base href="/assets/" target="_self"><a href="next.html">Next</a>', true);
check(!str_contains($baseNav, '<base'), 'srcdoc drops base elements after resolving their URL');
check(str_contains($baseNav, rawurlencode('https://example.com/assets/next.html')), 'relative upstream base resolves navigation explicitly');
$_base = $savedBase;

$css = proxify_css("@import 'theme.css' screen and (min-width: 600px);");
check(str_contains($css, 'screen and (min-width: 600px)'), 'CSS import media condition retained');
check(str_contains($css, rawurlencode('https://example.com/dir/theme.css')), 'single-quoted CSS import URL rewritten');
echo "UI checks passed\n";
