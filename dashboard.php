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
    public function open($savePath, $sessionName): bool {
        return true;
    }
    public function close(): bool {
        return true;
    }
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
$configFile = 'config.json';
$config = file_exists($configFile) ? json_decode(file_get_contents($configFile), true) : [];
$chatId = $config['chat_id'] ?? '';
$name = $config['name'] ?? '';
$authFile = 'auth.php';
$authContent = file_exists($authFile) ? file_get_contents($authFile) : '';
preg_match('/\$valid_password = "(.*?)";/', $authContent, $passwordMatch);
$authPassword = $passwordMatch[1] ?? '';
$message = '';
$messageType = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['update_config'])) {
        $newChatId = trim($_POST['chat_id']);
        $newName = trim($_POST['name']);
        if (!empty($newChatId) && !empty($newName)) {
            $config['chat_id'] = $newChatId;
            $config['name'] = $newName;
            if (file_put_contents($configFile, json_encode($config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES))) {
                $message = 'Configuration updated successfully!';
                $messageType = 'success';
                $chatId = $newChatId;
                $name = $newName;
            } else {
                $message = 'Failed to update configuration.';
                $messageType = 'danger';
            }
        } else {
            $message = 'Chat ID and Name cannot be empty.';
            $messageType = 'danger';
        }
    }
    if (isset($_POST['update_auth'])) {
        $newPassword = trim($_POST['new_password']);
        $currentPassword = trim($_POST['current_password']);
        if ($currentPassword !== $authPassword) {
            $message = 'Current password is incorrect.';
            $messageType = 'danger';
        } elseif (empty($newPassword)) {
            $message = 'New password cannot be empty.';
            $messageType = 'danger';
        } else {
            $newAuthContent = "<?php\n\$valid_password = \"" . addslashes($newPassword) . "\";\n?>";
            if (file_put_contents($authFile, $newAuthContent)) {
                $message = 'Password updated successfully!';
                $messageType = 'success';
                $authPassword = $newPassword;
            } else {
                $message = 'Failed to update password.';
                $messageType = 'danger';
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin Dashboard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;600;700&family=DM+Sans:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
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
            max-width: 1200px;
            margin: 0 auto;
        }
        .card {
            background: var(--background);
            border-radius: var(--radius);
            box-shadow: var(--shadow);
            margin-bottom: 28px;
            overflow: hidden;
            border: 1px solid var(--border);
            transition: all 0.3s ease;
        }
        .card:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-lg);
        }
        .card-header {
            background: var(--primary);
            color: var(--primary-foreground);
            padding: 20px 24px;
            font-family: 'Space Grotesk', sans-serif;
            font-weight: 600;
            font-size: 18px;
            display: flex;
            align-items: center;
            gap: 12px;
            letter-spacing: -0.01em;
        }
        .card-body {
            padding: 28px;
        }
        .form-group {
            margin-bottom: 24px;
        }
        .form-group label {
            display: block;
            margin-bottom: 10px;
            font-weight: 600;
            color: var(--foreground);
            font-size: 14px;
            letter-spacing: 0.01em;
        }
        .form-control {
            width: 100%;
            padding: 16px 18px;
            border: 2px solid var(--border);
            border-radius: var(--radius);
            font-size: 16px;
            font-weight: 500;
            color: var(--foreground);
            background: var(--input);
            transition: all 0.3s ease;
            font-family: 'DM Sans', sans-serif;
        }
        .form-control:focus {
            border-color: var(--ring);
            outline: none;
            box-shadow: 0 0 0 3px rgba(139, 92, 246, 0.1);
            background: var(--background);
        }
        .btn {
            padding: 16px 28px;
            border: none;
            border-radius: var(--radius);
            font-size: 16px;
            font-weight: 600;
            font-family: 'DM Sans', sans-serif;
            cursor: pointer;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 10px;
            justify-content: center;
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
        }
        .btn-info {
            background: var(--accent);
            color: var(--accent-foreground);
        }
        .btn-info:hover {
            background: #7c3aed;
            transform: translateY(-2px);
            box-shadow: var(--shadow);
        }
        .btn-dark {
            background: #374151;
            color: var(--primary-foreground);
        }
        .btn-dark:hover {
            background: #4b5563;
            transform: translateY(-2px);
            box-shadow: var(--shadow);
        }
        .btn-full {
            width: 100%;
        }
        .message {
            padding: 20px;
            border-radius: var(--radius);
            margin-bottom: 28px;
            display: flex;
            align-items: center;
            gap: 12px;
            animation: slideIn 0.4s ease-out;
            font-weight: 500;
            border: 1px solid;
        }
        @keyframes slideIn {
            from { opacity: 0; transform: translateX(-20px); }
            to { opacity: 1; transform: translateX(0); }
        }
        .message.success {
            background: #f0fdf4;
            color: #059669;
            border-color: #bbf7d0;
        }
        .message.danger {
            background: #fef2f2;
            color: var(--destructive);
            border-color: #fecaca;
        }
        .view-data-section {
            text-align: center;
            margin: 40px 0;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 24px;
            margin-bottom: 40px;
        }
        .stat-card {
            background: var(--background);
            padding: 28px;
            border-radius: var(--radius);
            box-shadow: var(--shadow);
            text-align: center;
            border: 1px solid var(--border);
            transition: all 0.3s ease;
        }
        .stat-card:hover {
            transform: translateY(-4px);
            box-shadow: var(--shadow-lg);
        }
        .stat-card i {
            font-size: 40px;
            color: var(--accent);
            margin-bottom: 16px;
            background: linear-gradient(135deg, var(--primary) 0%, var(--accent) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        .stat-card h3 {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 20px;
            font-weight: 600;
            color: var(--foreground);
            margin-bottom: 8px;
            letter-spacing: -0.01em;
        }
        .stat-card p {
            color: var(--muted);
            font-size: 14px;
            font-weight: 500;
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
            .card-body {
                padding: 24px;
            }
        }
    </style>
</head>
<body>
<div class="header">
    <h1><i class="fas fa-tachometer-alt"></i> Admin Panel</h1>
    <a href="logout.php" class="logout-btn">
        <i class="fas fa-sign-out-alt"></i> Logout
    </a>
</div>
<div class="main-content">
    <?php if ($message): ?>
        <div class="message <?php echo $messageType; ?>">
            <i class="fas fa-<?php echo $messageType === 'success' ? 'check-circle' : 'exclamation-circle'; ?>"></i>
            <?php echo $message; ?>
        </div>
    <?php endif; ?>
    <div class="stats-grid">
        <div class="stat-card">
            <i class="fas fa-cog"></i>
            <h3>Configuration</h3>
            <p>Manage app settings</p>
        </div>
        <div class="stat-card">
            <i class="fas fa-database"></i>
            <h3>Data Management</h3>
            <p>View stored data</p>
        </div>
        <div class="stat-card">
            <i class="fas fa-shield-alt"></i>
            <h3>Security</h3>
            <p>Update credentials</p>
        </div>
    </div>
    <div class="card">
        <div class="card-header">
            <i class="fas fa-comment-dots"></i>
            Update Configuration
        </div>
        <div class="card-body">
            <form method="POST">
                <div class="form-group">
                    <label>Name</label>
                    <input type="text" name="name" class="form-control" value="<?php echo htmlspecialchars($name); ?>" required>
                </div>
                <div class="form-group">
                    <label>Chat ID</label>
                    <input type="text" name="chat_id" class="form-control" value="<?php echo htmlspecialchars($chatId); ?>" required>
                </div>
                <button type="submit" name="update_config" class="btn btn-primary btn-full">
                    <i class="fas fa-save"></i> Update Configuration
                </button>
            </form>
        </div>
    </div>
    <div class="view-data-section">
        <a href="view_data.php" class="btn btn-info">
            <i class="fas fa-database"></i> View Data
        </a>
    </div>
    <div class="card">
        <div class="card-header" style="background: var(--accent);">
            <i class="fas fa-user-lock"></i>
            Update Password
        </div>
        <div class="card-body">
            <form method="POST">
                <div class="form-group">
                    <label>Current Password</label>
                    <input type="password" name="current_password" class="form-control" required>
                </div>
                <div class="form-group">
                    <label>New Password</label>
                    <input type="password" name="new_password" class="form-control" required>
                </div>
                <button type="submit" name="update_auth" class="btn btn-dark btn-full">
                    <i class="fas fa-key"></i> Update Password
                </button>
            </form>
        </div>
    </div>
</div>
</body>
</html>