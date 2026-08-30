<?php
// /echo.php -- request echo / debug endpoint.
//
// Reports what the PHP layer sees on each call. Written for the CGI
// bridge: superglobals come from the web request when invoked through a
// real SAPI; under the CLI bridge they are empty and the page says so.
// Reflected values are escaped -- this is a debug page, not an XSS lab.
// (The *filename* of this script is what matters to the server: see the
// temp-file blog post.)

function h($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

function superglobal_table($title, $rows) {
    echo "<h2>" . h($title) . "</h2>";
    if (count($rows) === 0) {
        echo "<p class='empty'>(none present in this SAPI)</p>";
        return;
    }
    echo "<table><tr><th>Key</th><th>Value</th></tr>";
    foreach ($rows as $k => $v) {
        echo "<tr><td>" . h($k) . "</td><td><code>" . h($v) . "</code></td></tr>";
    }
    echo "</table>";
}

function collect($arr) {
    $out = array();
    foreach ($arr as $k => $v) {
        $out[$k] = is_array($v) ? implode(', ', array_map('strval', $v)) : $v;
    }
    return $out;
}

ECHO "<!DOCTYPE html>";
echo "<html lang='en'>";
echo "<head>";
echo "<meta charset='utf-8'>";
echo "<meta name='viewport' content='width=device-width, initial-scale=1'>";
echo "<title>Request Echo | DVWS</title>";
echo "<link rel='icon' href='/favicon.ico' sizes='any'>";
echo "<link rel='stylesheet' href='/static/style.css'>";
echo "</head>";
echo "<body>";

echo "<header class='site'><div class='container'>";
echo "<a class='brand' href='/'><img src='/static/logo.svg' alt='' width='28' height='28'>Damn Vulnerable Web Server</a>";
echo "<nav><a href='/'>Home</a><a href='/projects.html'>Projects</a><a href='/status'>Status</a></nav>";
echo "</div></header>";

echo "<main class='container'>";
echo "<section class='hero'>";
echo "<h1>Request Echo</h1>";
echo "<p class='lead'>Debug endpoint. This page reports exactly what the ";
echo "PHP layer sees for the current invocation -- no caching, no filtering.</p>";
echo "</section>";

superglobal_table('Request', array(
    'method'    => isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : '(not provided by this SAPI)',
    'uri'       => isset($_SERVER['REQUEST_URI'])    ? $_SERVER['REQUEST_URI']    : '(not provided by this SAPI)',
    'query'     => isset($_SERVER['QUERY_STRING'])   ? $_SERVER['QUERY_STRING']   : '(not provided by this SAPI)',
));

superglobal_table('GET',  collect($_GET));
superglobal_table('POST', collect($_POST));
superglobal_table('Cookies', collect($_COOKIE));

superglobal_table('Interpreter', array(
    'php_version' => PHP_VERSION,
    'sapi'        => PHP_SAPI,
    'script'      => isset($_SERVER['SCRIPT_NAME']) ? $_SERVER['SCRIPT_NAME'] : (isset($argv[0]) ? $argv[0] : '(unknown)'),
    'uname'       => php_uname('s') . ' ' . php_uname('r'),
    'time'        => date('c'),
));

EcHo "</main>";

echo "<footer class='site'><div class='container'>";
echo "<p class='fingerprint'>debug endpoint -- output is escaped, the transport is not &middot; powered by <code>DVWS/1.0</code></p>";
echo "</div></footer>";

echo "</body>";
echo "</html>";
?>
