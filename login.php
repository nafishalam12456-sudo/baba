<?php
$customSessionPath = __DIR__ . '/sessions';
if (!is_dir($customSessionPath)) {
    mkdir($customSessionPath, 0700, true);
    file_put_contents($customSessionPath . '/index.php', "<?php http_response_code(403); exit(); ?>");
}
session_save_path($customSessionPath);
define('ENCRYPTION_KEY', hash('sha512', __DIR__ . php_uname() . phpversion()));
define('ENCRYPTION_METHOD', 'aes-256-gcm');
class EncryptedSessionHandler implements SessionHandlerInterface
{
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
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Strict-Transport-Security: max-age=31536000; includeSubDomains");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: no-referrer");
require_once 'auth.php';
$real_password = $valid_password;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $password = $_POST['password'] ?? '';
    if (!isset($_SESSION['login_attempts'])) {
        $_SESSION['login_attempts'] = 0;
        $_SESSION['last_login_attempt'] = time();
    }
    if (time() - $_SESSION['last_login_attempt'] > 300) {
        $_SESSION['login_attempts'] = 0;
    }
    if ($_SESSION['login_attempts'] >= 5) {
        $error_message = "Too many failed attempts. Please try again later.";
    } elseif (hash_equals($real_password, $password)) {
        $_SESSION['loggedin'] = true;
        $_SESSION['login_attempts'] = 0;
        $_SESSION['user_agent'] = hash('sha256', $_SERVER['HTTP_USER_AGENT']);
        $_SESSION['ip_address'] = hash('sha256', $_SERVER['REMOTE_ADDR']);
        session_regenerate_id(true);
        header('Location: dashboard.php');
        exit();
    } else {
        $_SESSION['login_attempts']++;
        $_SESSION['last_login_attempt'] = time();
        $error_message = "Incorrect access key. Please try again.";
    }
}
if (isset($_GET['error'])) {
    $error_message = htmlspecialchars($_GET['error'], ENT_QUOTES, 'UTF-8');
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>ROMEO WEBS | LOGIN</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/animate.min.css">
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        :root {
            --neon-cyan: #00ffff;
            --neon-pink: #ff00ff;
            --neon-red: #ff0000;
            --dark-bg: #081828;
            --darker-bg: #0d1117;
            --input-bg: #0f172a;
            --box-bg: #111827;
        }
        
        body {
            background: linear-gradient(145deg, var(--dark-bg), var(--darker-bg));
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            overflow-x: hidden;
        }
        
        .neon-text {
            color: var(--neon-cyan);
            font-size: 2rem;
            text-align: center;
            margin-bottom: 1.5rem;
            text-shadow: 0 0 5px var(--neon-cyan), 0 0 10px var(--neon-cyan);
            animation: pulse 2s infinite alternate;
            letter-spacing: 1px;
        }
        
        .login-box {
            background: var(--box-bg);
            padding: 2rem;
            border-radius: 12px;
            box-shadow: 0 0 30px rgba(0, 255, 255, 0.1);
            text-align: center;
            width: 90%;
            max-width: 360px;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            border: 1px solid rgba(0, 255, 255, 0.1);
            position: relative;
            overflow: hidden;
        }
        
        .login-box::before {
            content: '';
            position: absolute;
            top: -2px;
            left: -2px;
            right: -2px;
            bottom: -2px;
            background: linear-gradient(45deg, var(--neon-cyan), var(--neon-pink), var(--neon-cyan));
            z-index: -1;
            filter: blur(5px);
            opacity: 0;
            transition: opacity 0.3s ease;
        }
        
        .login-box:hover::before {
            opacity: 0.3;
        }
        
        .login-box:hover {
            transform: translateY(-5px);
            box-shadow: 0 0 40px rgba(0, 255, 255, 0.2);
        }
        
        .login-box input {
            width: 100%;
            padding: 12px 15px;
            margin: 0.8rem 0;
            border-radius: 8px;
            border: 1px solid rgba(0, 255, 255, 0.3);
            background: var(--input-bg);
            color: #ffffff;
            font-size: 1rem;
            transition: all 0.3s ease;
            outline: none;
        }
        
        .login-box input:focus {
            border-color: var(--neon-cyan);
            box-shadow: 0 0 10px rgba(0, 255, 255, 0.3);
        }
        
        .login-box input::placeholder {
            color: rgba(255, 255, 255, 0.5);
        }
        
        .login-btn {
            width: 100%;
            padding: 12px;
            background: linear-gradient(45deg, var(--neon-red), #e60000);
            color: #ffffff;
            border: none;
            border-radius: 8px;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
            font-size: 1rem;
            margin-top: 1rem;
            box-shadow: 0 4px 15px rgba(255, 0, 0, 0.3);
        }
        
        .login-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(255, 0, 0, 0.4);
        }
        
        .login-btn:active {
            transform: translateY(1px);
        }
        
        .login-btn::after {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
            transition: 0.5s;
        }
        
        .login-btn:hover::after {
            left: 100%;
        }
        
        .links-container {
            margin-top: 1.5rem;
            display: flex;
            flex-direction: column;
            gap: 0.8rem;
        }
        
        .link-item {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
            transition: transform 0.3s ease;
        }
        
        .link-item:hover {
            transform: translateX(5px);
        }
        
        .link-text {
            color: white;
            transition: color 0.3s ease;
        }
        
        .link-item:hover .link-text {
            color: var(--neon-cyan);
        }
        
        .link-highlight {
            color: var(--neon-pink);
            font-weight: bold;
            transition: all 0.3s ease;
        }
        
        .link-item:hover .link-highlight {
            color: white;
            text-shadow: 0 0 5px var(--neon-pink);
        }
        
        .message {
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 1rem;
            font-weight: bold;
            position: relative;
            overflow: hidden;
            animation: fadeIn 0.5s ease-out;
        }
        
        .error-message {
            background-color: rgba(255, 77, 77, 0.2);
            color: #ff4d4d;
            border: 1px solid #ff4d4d;
        }
        
        .success-message {
            background-color: rgba(76, 175, 80, 0.2);
            color: #4caf50;
            border: 1px solid #4caf50;
        }
        
        @keyframes pulse {
            0% {
                text-shadow: 0 0 5px var(--neon-cyan), 0 0 10px var(--neon-cyan);
            }
            100% {
                text-shadow: 0 0 10px var(--neon-cyan), 0 0 20px var(--neon-cyan), 0 0 30px var(--neon-cyan);
            }
        }
        
        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(-10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        /* Responsive adjustments */
        @media (max-width: 480px) {
            .login-box {
                padding: 1.5rem;
                width: 85%;
            }
            
            .neon-text {
                font-size: 1.8rem;
            }
            
            .login-box input, .login-btn {
                padding: 10px 12px;
            }
        }
        
        /* Floating animation for the box */
        @keyframes float {
            0% {
                transform: translateY(0px);
            }
            50% {
                transform: translateY(-10px);
            }
            100% {
                transform: translateY(0px);
            }
        }
        
        .login-box {
            animation: float 6s ease-in-out infinite;
        }
    </style>
</head>
<body>
    <div class="login-box animate__animated animate__fadeIn">
        <h2 class="neon-text">ROMEO WEBS</h2>

        <?php if (isset($error_message)): ?>
            <div class="message error-message animate__animated animate__shakeX">
                <?php echo htmlspecialchars($error_message, ENT_QUOTES, 'UTF-8'); ?>
            </div>
        <?php endif; ?>

        <form method="POST" action="">
            <input id="password" name="password" type="password" placeholder="Enter Access Key" required
                   autocomplete="current-password" autocapitalize="off" autocorrect="off">
            <button type="submit" class="login-btn">LOGIN</button>
        </form>

        <div class="links-container">
            <a href="https://t.me/ROMEO_PRIMES" class="link-item" target="_blank" rel="noopener noreferrer">
                <span class="link-text">Forgot Password?</span>
                <span class="link-highlight">Click here</span>
            </a>
            <a href="https://t.me/+hwbCBy6HxU1iOGE9" class="link-item" target="_blank" rel="noopener noreferrer">
                <span class="link-text">Our Channel:</span>
                <span class="link-highlight">Click here</span>
            </a>
        </div>
    </div>

    <script>
        // Add interactive effects
        document.addEventListener('DOMContentLoaded', function() {
            const inputs = document.querySelectorAll('input');
            
            inputs.forEach(input => {
                // Add focus/blur effects
                input.addEventListener('focus', function() {
                    this.parentElement.classList.add('animate__animated', 'animate__pulse');
                });
                
                input.addEventListener('blur', function() {
                    this.parentElement.classList.remove('animate__animated', 'animate__pulse');
                });
            });
            
            // Prevent form resubmission on refresh
            if (window.history.replaceState) {
                window.history.replaceState(null, null, window.location.href);
            }
        });
    </script>
</body>
</html>