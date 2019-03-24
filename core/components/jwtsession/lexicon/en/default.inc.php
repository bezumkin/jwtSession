<?php

$_lang['area_jwtsession_main'] = 'Main';

$_lang['setting_jwt_cookie_secret'] = 'Token Signature Key';
$_lang['setting_jwt_cookie_secret_desc'] = 'The secret phrase that will sign token.';
$_lang['setting_jwt_session_encrypt'] = 'Enable session encryption';
$_lang['setting_jwt_session_encrypt_desc'] = 'When enabled, the session inside the token will be encrypted via "openssl_encrypt", using "jwt_session_secret" as the secret key.';
$_lang['setting_jwt_session_secret'] = 'Session encryption key';
$_lang['setting_jwt_session_secret_desc'] = 'The secret phrase by which the session is encrypted in the token, if the "jwt_session_encrypt" setting is enabled.';