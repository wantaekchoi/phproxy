<?php
declare(strict_types=1);

define('PHPROXY_LIBRARY_ONLY', true);
require dirname(__DIR__) . '/index.php';
error_reporting(E_ALL);
set_error_handler(static function (int $level, string $message, string $file, int $line): bool {
    if (!(error_reporting() & $level)) return false;
    throw new ErrorException($message, 0, $level, $file, $line);
});

function check(bool $condition, string $label): void
{
    if (!$condition) throw new RuntimeException($label);
}

function same(mixed $expected, mixed $actual, string $label): void
{
    check($expected === $actual, $label . ': expected ' . var_export($expected, true) . ', got ' . var_export($actual, true));
}
