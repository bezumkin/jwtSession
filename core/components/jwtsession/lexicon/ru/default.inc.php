<?php

$_lang['area_jwtsession_main'] = 'Основные';

$_lang['setting_jwt_cookie_secret'] = 'Ключ подписи токена';
$_lang['setting_jwt_cookie_secret_desc'] = 'Секретная фраза, которой будет подписан токен.';
$_lang['setting_jwt_session_encrypt'] = 'Включить шифрование сессии';
$_lang['setting_jwt_session_encrypt_desc'] = 'При активации этой настройки, сессия внутри токена будет зашифрона через "openssl_encrypt", используя "jwt_session_secret" в качестве секретного ключа.';
$_lang['setting_jwt_session_secret'] = 'Ключ шифрования сессии';
$_lang['setting_jwt_session_secret_desc'] = 'Секретная фраза, которой шифруется сессия в токене, если включена настройка "jwt_session_encrypt".';