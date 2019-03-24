<?php

if (!class_exists('Firebase\JWT\JWT')) {
    require dirname(dirname(__DIR__)) . '/vendor/autoload.php';
}

use Firebase\JWT\JWT;

class jwtSession
{
    /** @var modX $modx */
    public $modx;
    /** @var array $config */
    public $config;
    public $max = 3968; // Max length of cookie chunk
    const cipher = 'AES-256-CBC';


    /**
     * jwtSession constructor.
     *
     * @param modX $modx
     * @param array $config
     */
    public function __construct(modX &$modx, array $config = [])
    {
        ini_set('session.use_cookies', 0);
        $this->modx = $modx;

        $this->config = array_merge($config, [
            'session_host' => $_SERVER['HTTP_HOST'],
            'session_name' => $this->modx->getOption('session_name', null, 'JWT_TOKEN', true),
            'session_lifetime' => $this->modx->getOption('session_cookie_lifetime'),
            'session_domain' => $this->modx->getOption('session_cookie_domain'),
            'session_path' => $this->modx->getOption('session_cookie_path', null, MODX_BASE_URL, true),
            'session_secret' => $this->modx->getOption('session_cookie_secret', null, $this->modx->site_id, true),
        ]);
    }


    /**
     * @param string $data
     * @param string $key
     *
     * @return string
     */
    protected function encode($data, $key)
    {
        $ivLen = openssl_cipher_iv_length($this::cipher);
        $iv = openssl_random_pseudo_bytes($ivLen);
        if (function_exists('gzcompress')) {
            $data = gzcompress($data, 9);
        }
        $cipher_raw = openssl_encrypt($data, $this::cipher, $key, OPENSSL_RAW_DATA, $iv);
        $data = base64_encode($iv . $cipher_raw);

        return $data;
    }


    /**
     * @param string $string
     * @param string $key
     *
     * @return string
     */
    protected function decode($string, $key)
    {
        $ivLen = openssl_cipher_iv_length($this::cipher);
        $encoded = base64_decode($string);
        if (ini_get('mbstring.func_overload')) {
            $strLen = mb_strlen($encoded, '8bit');
            $iv = mb_substr($encoded, 0, $ivLen, '8bit');
            $cipher_raw = mb_substr($encoded, $ivLen, $strLen, '8bit');
        } else {
            $iv = substr($encoded, 0, $ivLen);
            $cipher_raw = substr($encoded, $ivLen);
        }
        $data = openssl_decrypt($cipher_raw, $this::cipher, $key, OPENSSL_RAW_DATA, $iv);
        if (function_exists('gzuncompress')) {
            $data = gzuncompress($data);
        }

        return $data;
    }


    /**
     * @return string
     */
    public function read()
    {
        $data = '';
        try {
            if (isset($_COOKIE[$this->config['session_name']])) {
                $chunks = $_COOKIE[$this->config['session_name']];
                $idx = 1;
                while (isset($_COOKIE[$this->config['session_name'] . '_' . $idx])) {
                    $chunks .= $_COOKIE[$this->config['session_name'] . '_' . $idx];
                    $idx++;
                }

                $token = JWT::decode($chunks, $this->config['session_secret'], ['HS256']);
                if (!$data = $this->decode($token->data, $this->config['session_secret'])) {
                    $data = '';
                }
            }
        } catch (Exception $e) {
            $this->modx->log(modX::LOG_LEVEL_ERROR, '[jwtSession] exception: ' . $e->getMessage());
        }

        return $data;
    }


    /**
     * @param $session_id
     * @param $data
     *
     * @return bool
     */
    public function write($session_id, $data)
    {
        $token = [
            'iat' => time(),
            'jti' => $session_id,
            'iss' => $this->config['session_host'],
            'exp' => time() + $this->config['session_lifetime'],
            'data' => $this->encode($data, $this->config['session_secret']),
        ];
        $data = JWT::encode($token, $this->config['session_secret'], 'HS256');

        $chunks = str_split($data, $this->max);
        $idx = 0;
        foreach ($chunks as $idx => $chunk) {
            $name = $this->config['session_name'];
            if ($idx) {
                $name .= '_' . $idx;
            }
            if (!headers_sent()) {
                setcookie(
                    $name,
                    $chunk,
                    time() + $this->config['session_lifetime'],
                    $this->config['session_path'],
                    $this->config['session_domain'],
                    false,
                    true
                );
            }
        }

        // Remove old chunks
        $idx += 1;
        while (isset($_COOKIE[$this->config['session_name'] . '_' . $idx])) {
            if (!headers_sent()) {
                setcookie(
                    $this->config['session_name'] . '_' . $idx,
                    null,
                    time() - 3000,
                    $this->config['session_path'],
                    $this->config['session_domain']
                );
            }
            $idx++;
        }

        return true;
    }


    /**
     * @return bool
     */
    public function destroy()
    {
        if (!headers_sent()) {
            setcookie(
                $this->config['session_name'],
                null,
                time() - 3000,
                $this->config['session_path'],
                $this->config['session_domain']
            );
            $idx = 1;
            while (isset($_COOKIE[$this->config['session_name'] . '_' . $idx])) {
                if (!headers_sent()) {
                    setcookie(
                        $this->config['session_name'] . '_' . $idx,
                        null,
                        time() - 3000,
                        $this->config['session_path'],
                        $this->config['session_domain']
                    );
                }
                $idx++;
            }
        }

        return true;
    }


    /**
     * @return bool
     */
    public function gc()
    {
        return true;
    }


    /**
     * @return bool
     */
    public function open()
    {
        return true;
    }


    /**
     * @return bool
     */
    public function close()
    {
        return true;
    }

}