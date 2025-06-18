<?php
/**
 * Security Test File - Safe PHP Upload Check
 * Outputs success message if executed
 */
header('Content-Type: text/plain');
echo "ZS_PHP_TEST_SUCCESS\n";
echo "SERVER: " . $_SERVER['SERVER_SOFTWARE'] . "\n";
echo "UPLOAD_VULNERABLE: YES\n";
echo "TEST_ID: ZS-PHP-" . bin2hex(random_bytes(4)) . "\n";

// Safe cleanup - attempts to delete itself after execution
register_shutdown_function(function() {
    @unlink(__FILE__);
});
?>