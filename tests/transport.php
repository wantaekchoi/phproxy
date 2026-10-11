<?php
require __DIR__ . '/bootstrap.php';

function transport_response(string $wire, string $method = 'GET', int $limit = 1024): array
{
    $stream = fopen('php://temp', 'w+b');
    fwrite($stream, $wire);
    rewind($stream);
    try {
        return phproxy_read_http_response($stream, $method, microtime(true) + 2, $limit);
    } finally {
        fclose($stream);
    }
}

function transport_rejects(callable $operation, string $label): void
{
    try { $operation(); }
    catch (RuntimeException | InvalidArgumentException $e) { return; }
    throw new RuntimeException($label);
}

check(phproxy_api_origin_allowed('https://example.com', 'https://example.com/index.php'), 'Same API origin allowed');
check(phproxy_api_origin_allowed('https://example.com:443', 'https://example.com/index.php'), 'Default port normalized');
check(!phproxy_api_origin_allowed('null', 'https://example.com/index.php'), 'Opaque API origin refused');
check(!phproxy_api_origin_allowed('https://other.example', 'https://example.com/index.php'), 'Different API origin refused');
check(phproxy_valid_dns_name('_dmarc.example.com'), 'Service DNS labels accepted');
check(phproxy_valid_dns_name('_service._tcp.example.com'), 'SRV DNS labels accepted');

// Policy tests use address literals only; no network or DNS operation occurs.
check(phproxy_is_public_ip('1.1.1.1'), 'Public IPv4 accepted');
check(phproxy_is_public_ip('2606:4700:4700::1111'), 'Public IPv6 accepted');
foreach (['127.0.0.1', '10.0.0.1', '169.254.1.1', '192.168.1.1', '100.64.0.1', '192.0.2.1', '224.0.0.1', '::1', 'fc00::1', 'fe80::1', '2001:db8::1', '::ffff:192.0.2.1'] as $address) {
    check(!phproxy_is_public_ip($address), 'Nonpublic or special address rejected: ' . $address);
}
same('example.com', phproxy_normalize_host('EXAMPLE.COM.'), 'Host normalization');
same('/?page=2', phproxy_parse_http_url('https://example.com?page=2')['path'], 'Empty path becomes slash');
same('[2606:4700:4700::1111]:8443', phproxy_parse_http_url('https://[2606:4700:4700::1111]:8443/')['authority'], 'IPv6 authority retains brackets');

$base = 'https://example.com/a/b?old=1';
same('https://example.com/a/b?new=2', phproxy_resolve_http_location($base, '?new=2'), 'Query-only redirect');
same('https://other.example/path', phproxy_resolve_http_location($base, '//other.example/path'), 'Network-path redirect');
same('https://example.com/c', phproxy_resolve_http_location($base, '../c'), 'Relative parent redirect');
same('https://example.com/a/b?old=1', phproxy_resolve_http_location($base, '#section'), 'Fragment-only redirect');
same('/a//c/', phproxy_remove_dot_segments('/a//b/../c/.'), 'Dot resolution preserves repeated slashes');

$origin = phproxy_parse_http_url('https://example.com/');
$other = phproxy_parse_http_url('https://other.example/');
$headers = ['authorization' => 'Bearer sample-token', 'cookie' => 'session=sample', 'x-api-key' => 'sample', 'accept' => 'text/plain', 'content-type' => 'application/json'];
[$method, $redirect_headers, $body] = phproxy_redirect_request($origin, $other, 303, 'POST', $headers, '{}');
same('GET', $method, '303 changes POST to GET');
same('', $body, '303 clears body');
same(['accept' => 'text/plain'], $redirect_headers, 'Cross-origin redirects retain only representation preferences');
[$method, $same_headers, $body] = phproxy_redirect_request($origin, $origin, 307, 'POST', $headers, '{}');
same($headers, $same_headers, 'Same-origin credentials retained');
same('{}', $body, 'Same-origin 307 retains body');
transport_rejects(fn() => phproxy_redirect_request($origin, $other, 307, 'POST', $headers, '{}'), 'Cross-origin body replay rejected');
transport_rejects(fn() => phproxy_redirect_request($origin, phproxy_parse_http_url('http://example.com/'), 302, 'GET', [], ''), 'TLS downgrade rejected');
same(['accept' => 'text/plain'], phproxy_prepare_request_headers(['Accept' => 'text/plain', 'Content-Length' => '3', 'Connection' => 'keep-alive']), 'Transport owns request framing');
same(false, phproxy_api_fetch(['url' => 'https://example.com/', 'method' => 'BREW'])['ok'], 'Unsupported method rejected before network');

$response = transport_response("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\nSet-Cookie: theme=light; Path=/; Secure; HttpOnly\r\n\r\nhello");
same('hello', $response['body_raw'], 'Fixed-length response read');
same('text/plain', $response['headers']['content-type'], 'Header names normalized');
check(!isset($response['headers']['set-cookie']), 'Cookies excluded from forwarded headers');
same(true, $response['set_cookies'][0]['secure'], 'Cookie metadata retained separately');
same('hello', phproxy_api_decode_chunked("5\r\nhello\r\n0\r\n\r\n"), 'Complete chunked decoding');
$response = transport_response("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n");
same('hello', $response['body_raw'], 'Interim response and chunked body');
check(!isset($response['headers']['transfer-encoding']), 'Decoded framing removed');
same('', transport_response("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", 'HEAD')['body_raw'], 'HEAD has no response body');
same('hello', transport_response("HTTP/1.0 200 OK\r\n\r\nhello")['body_raw'], 'Connection-close body');
transport_rejects(fn() => transport_response("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhi"), 'Interrupted fixed-length response fails');
transport_rejects(fn() => phproxy_api_decode_chunked("5\r\nhello\r\n"), 'Interrupted chunked response fails');
transport_rejects(fn() => transport_response("HTTP/1.0 200 OK\r\n\r\nhello", 'GET', 4), 'Close-delimited body respects cap');
transport_rejects(fn() => transport_response("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", 'GET', 4), 'Declared body respects cap');

foreach (['gzip' => gzencode('hello'), 'deflate' => gzcompress('hello')] as $encoding => $encoded) {
    $response = transport_response("HTTP/1.1 200 OK\r\nContent-Encoding: $encoding\r\nContent-Length: " . strlen($encoded) . "\r\n\r\n" . $encoded);
    same('hello', $response['body_raw'], $encoding . ' decoding');
    check(!isset($response['headers']['content-encoding']), 'Successful decoding clears encoding');
}
$response = transport_response("HTTP/1.1 200 OK\r\nContent-Encoding: br\r\nContent-Length: 5\r\n\r\nbytes");
same('br', $response['headers']['content-encoding'], 'Unsupported encoding preserved');
same('bytes', $response['body_raw'], 'Unsupported representation unchanged');
$compressed = gzencode(str_repeat('A', 128));
transport_rejects(fn() => transport_response("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: " . strlen($compressed) . "\r\n\r\n" . $compressed, 'GET', 64), 'Decoded body respects cap');

same([80, 443], phproxy_parse_port_spec('443,80,80'), 'Port spec deduplicated and sorted');
same([8000, 8001, 8002], phproxy_parse_port_spec('8000-8002'), 'Small decimal range');
same(false, phproxy_parse_port_spec('80x-81'), 'Range endpoints must be decimal');
echo "transport tests passed\n";
