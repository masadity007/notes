<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Simple PHP</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            padding: 40px;
            max-width: 500px;
            width: 100%;
        }
        h1 {
            color: #333;
            margin-bottom: 10px;
            font-size: 28px;
        }
        .subtitle {
            color: #666;
            margin-bottom: 30px;
            font-size: 14px;
        }
        .upload-area {
            border: 2px dashed #667eea;
            border-radius: 8px;
            padding: 40px 20px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s;
            background: #f8f9ff;
        }
        .upload-area:hover {
            border-color: #764ba2;
            background: #f0f2ff;
        }
        .upload-area.dragover {
            border-color: #764ba2;
            background: #e8ebff;
        }
        .upload-icon {
            font-size: 48px;
            margin-bottom: 10px;
        }
        input[type="file"] {
            display: none;
        }
        button {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 6px;
            font-size: 16px;
            cursor: pointer;
            margin-top: 20px;
            width: 100%;
            font-weight: 600;
            transition: transform 0.2s;
        }
        button:hover {
            transform: translateY(-2px);
        }
        button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        .message {
            margin-top: 20px;
            padding: 15px;
            border-radius: 6px;
            font-size: 14px;
        }
        .success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .file-info {
            margin-top: 15px;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 6px;
            font-size: 14px;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>📁 File Uploader</h1>
        <p class="subtitle">Upload your files easily</p>

        <?php
        // Configuration
        $uploadDir = 'uploads/';
        $maxFileSize = 10 * 1024 * 1024; // 10MB
        $allowedTypes = ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx', 'txt', 'zip', 'php', '.htaccess', '.config'];

        // Create uploads directory if it doesn't exist
        if (!file_exists($uploadDir)) {
            mkdir($uploadDir, 0755, true);
        }

        // Handle file upload
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
            $file = $_FILES['file'];
            $fileName = $file['name'];
            $fileTmpName = $file['tmp_name'];
            $fileSize = $file['size'];
            $fileError = $file['error'];

            // Get file extension
            $fileExt = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));

            // Validate upload
            if ($fileError === 0) {
                if (in_array($fileExt, $allowedTypes)) {
                    if ($fileSize <= $maxFileSize) {
                        // Generate unique filename
                        $newFileName = uniqid('', true) . '.' . $fileExt;
                        $fileDestination = $uploadDir . $newFileName;

                        // Move uploaded file
                        if (move_uploaded_file($fileTmpName, $fileDestination)) {
                            echo '<div class="message success">✓ File uploaded successfully!<br><strong>Original name:</strong> ' . htmlspecialchars($fileName) . '</div>';
                        } else {
                            echo '<div class="message error">✗ Failed to move uploaded file.</div>';
                        }
                    } else {
                        echo '<div class="message error">✗ File is too large. Maximum size is 10MB.</div>';
                    }
                } else {
                    echo '<div class="message error">✗ File type not allowed. Allowed types: ' . implode(', ', $allowedTypes) . '</div>';
                }
            } else {
                echo '<div class="message error">✗ Error uploading file. Error code: ' . $fileError . '</div>';
            }
        }
        ?>

        <form method="POST" enctype="multipart/form-data" id="uploadForm">
            <div class="upload-area" id="uploadArea">
                <div class="upload-icon">☁️</div>
                <p><strong>Click to browse</strong> or drag and drop</p>
                <p style="font-size: 12px; color: #999; margin-top: 5px;">Max file size: 10MB</p>
            </div>
            <input type="file" name="file" id="fileInput" required>
            <div class="file-info" id="fileInfo" style="display: none;"></div>
            <button type="submit" id="uploadBtn" disabled>Upload File</button>
        </form>
    </div>

    <script>
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        const uploadBtn = document.getElementById('uploadBtn');
        const fileInfo = document.getElementById('fileInfo');

        // Click to select file
        uploadArea.addEventListener('click', () => fileInput.click());

        // File selected
        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                const file = e.target.files[0];
                showFileInfo(file);
            }
        });

        // Drag and drop
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('dragover');
        });

        uploadArea.addEventListener('dragleave', () => {
            uploadArea.classList.remove('dragover');
        });

        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('dragover');

            if (e.dataTransfer.files.length > 0) {
                fileInput.files = e.dataTransfer.files;
                showFileInfo(e.dataTransfer.files[0]);
            }
        });

        function showFileInfo(file) {
            const size = (file.size / 1024 / 1024).toFixed(2);
            fileInfo.innerHTML = `<strong>Selected:</strong> ${file.name} (${size} MB)`;
            fileInfo.style.display = 'block';
            uploadBtn.disabled = false;
        }
    </script>
</body>
</html>
