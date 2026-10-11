<?php
require __DIR__ . '/bootstrap.php';

$server = ['HTTP_HOST' => 'localhost:8080', 'SCRIPT_NAME' => '/index.php', 'SERVER_PORT' => '80'];
$local = phproxy_cli_endpoints($server, '');
same('http://localhost:8080/index.php?api=fetch', $local['fetch'], 'Local CLI endpoint retains published port and API route');
$deployed = phproxy_cli_endpoints($server, 'https://proxy.example/tools/proxy.php');
same('https://proxy.example/tools/proxy.php', $deployed['base'], 'Configured public script used for diagnostic endpoints');
same('https://proxy.example/tools/proxy.php?api=fetch', $deployed['fetch'], 'Configured public URL controls CLI API endpoint');

$destination = 'https://www.abv.bg/';
foreach (['curl', 'php', 'python', 'js', 'go'] as $language) {
    $proxy = 'phproxy_cli_' . $language . '_proxy';
    $direct = 'phproxy_cli_' . $language . '_direct';
    $checks = 'phproxy_cli_checks_' . $language;
    $proxied_command = $proxy($deployed['fetch'], $destination, 'GET', [], []);
    check(str_contains($proxied_command, $deployed['fetch']), $language . ' sends the API request to the proxy');
    check(str_contains($proxied_command, $destination), $language . ' retains the destination in its payload');
    check(str_contains($proxied_command, 'application/json') || ($language === 'python' && str_contains($proxied_command, 'json=payload')), $language . ' uses required JSON encoding');
    $direct_command = $direct($destination, 'GET', []);
    check(str_contains($direct_command, $destination), $language . ' direct command targets destination');
    check(!str_contains($direct_command, $deployed['base']), $language . ' direct command has no proxy routing');
    check(str_contains($checks($deployed['base']), $deployed['base']), $language . ' diagnostic commands use the proxy server');
}
echo "CLI tests passed\n";
