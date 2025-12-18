<?php
session_start();
session_destroy();
header('Location: index.php?success=You+have+logged+out');
exit;
?>