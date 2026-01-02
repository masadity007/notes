<?php
echo "<h2>SQLite Extension Check</h2>";

if (extension_loaded('pdo_sqlite')) {
    echo "✓ PDO_SQLite is available!<br>";
    
    try {
        $db = new PDO('sqlite::memory:');
        echo "✓ PDO_SQLite is working!<br>";
        
        // Show version
        $version = $db->query('SELECT sqlite_version()')->fetch();
        echo "SQLite Version: " . $version[0];
    } catch (PDOException $e) {
        echo "✗ Error: " . $e->getMessage();
    }
} else {
    echo "✗ PDO_SQLite is NOT available<br>";
}

if (class_exists('SQLite3')) {
    echo "<br>✓ SQLite3 class is available!";
} else {
    echo "<br>✗ SQLite3 class is NOT available";
}

echo "<hr><h3>All loaded extensions:</h3>";
echo implode(', ', get_loaded_extensions());
?>
