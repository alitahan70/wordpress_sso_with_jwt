<?php
/**
 * Plugin Name: AT JWT Auth RS256
 * Description: Issue JWT signed with RS256 (private key). Also sets WP auth cookie.
 * Version: 1.0
 * Author: Ali Tahan
 */

if (!defined('ABSPATH')) {
    exit;
}
define('JWT_RS256_PRIVATE_KEY', file_get_contents(plugin_dir_path(__FILE__) . '/sign/jwt_private.pem'));
define('JWT_ALLOWED_ORIGINS', '*');

/**
 * Helpers: base64url encode
 */
function cjrs_base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

/**
 * Create JWT signed with RS256 using OpenSSL
 * $payload: associative array
 * $private_key_pem: PEM string (private key)
 * $exp_seconds: expiration seconds
 */
function cjrs_make_jwt_rs256($payload, $private_key_pem, $exp_seconds = 3600) {
    $header = ['alg' => 'RS256', 'typ' => 'JWT'];
    $iat = time();
    $exp = $iat + $exp_seconds;
    $payload = array_merge($payload, ['iat' => $iat, 'exp' => $exp]);

    $b64_header = cjrs_base64url_encode(json_encode($header));
    $b64_payload = cjrs_base64url_encode(json_encode($payload));

    $unsigned = $b64_header . '.' . $b64_payload;

    // sign with private key (PEM)
    $private_key = openssl_pkey_get_private($private_key_pem);
    if ($private_key === false) {
        return new WP_Error('invalid_private_key', 'Invalid private key');
    }

    $signature = '';
    $ok = openssl_sign($unsigned, $signature, $private_key, OPENSSL_ALGO_SHA256);
    openssl_free_key($private_key);

    if (!$ok) {
        return new WP_Error('sign_failed', 'Signing failed');
    }

    $b64_sig = cjrs_base64url_encode($signature);

    return $unsigned . '.' . $b64_sig;
}

/**
 * Register REST route: POST /wp-json/at-jwt-rs256/v1/token
 */
add_action('rest_api_init', function() {
    register_rest_route('at-jwt-login/v1', '/token', [
        'methods' => 'POST',
        'callback' => 'cjrs_handle_token_request',
        'permission_callback' => '__return_true',
    ]);
}, 10);
add_action('rest_api_init', function() {
    register_rest_route('at-jwt-login/v1', '/sso-login', [
        'methods' => 'GET',
        'callback' => 'sso_login_with_jwt',
        'permission_callback' => '__return_true',
    ]);
});
function cjrs_get_private_key_pem() {
    if (defined('JWT_RS256_PRIVATE_KEY') && !empty(JWT_RS256_PRIVATE_KEY)) {
        return JWT_RS256_PRIVATE_KEY; // full PEM string
    }

    if (defined('JWT_RS256_PRIVATE_KEY_PATH') && !empty(JWT_RS256_PRIVATE_KEY_PATH)) {
        $path = JWT_RS256_PRIVATE_KEY_PATH;
        if (file_exists($path)) {
            return file_get_contents($path);
        }
    }

    return false;
}
function verify_jwt_rs256($jwt, $public_key_path) {
    $parts = explode('.', $jwt);
    if (count($parts) !== 3) {
        throw new Exception('Invalid token format');
    }

    [$encoded_header, $encoded_payload, $encoded_signature] = $parts;

    // Base64URL decode
    $header = json_decode(base64_decode(strtr($encoded_header, '-_', '+/')), true);
    $payload = json_decode(base64_decode(strtr($encoded_payload, '-_', '+/')), true);
    $signature = base64_decode(strtr($encoded_signature, '-_', '+/'));

    if (empty($header['alg']) || $header['alg'] !== 'RS256') {
        throw new Exception('Invalid algorithm');
    }

    $public_key = file_get_contents($public_key_path);
    if (!$public_key) {
        throw new Exception('Cannot read public key');
    }

    $data = "$encoded_header.$encoded_payload";

    $ok = openssl_verify($data, $signature, $public_key, OPENSSL_ALGO_SHA256);
    if ($ok !== 1) {
        throw new Exception('Invalid signature');
    }

    // بررسی انقضا
    if (isset($payload['exp']) && time() >= $payload['exp']) {
        throw new Exception('Token expired');
    }

    return $payload;
}

function cjrs_handle_token_request(\WP_REST_Request $request) {
    header('Access-Control-Allow-Credentials: true');

    $params = json_decode($request->get_body(), true);
    $username = isset($params['username']) ? sanitize_text_field($params['username']) : '';
    $password = isset($params['password']) ? $params['password'] : '';

    if (empty($username) || empty($password)) {
        return new WP_REST_Response(['error' => 'missing_credentials'], 400);
    }

    // authenticate user
    $user = wp_authenticate($username, $password);
    if (is_wp_error($user)) {
        return new WP_REST_Response(['error' => 'invalid_credentials'], 401);
    }

    $user_id = $user->ID;

    // get private key PEM
    $private_pem = cjrs_get_private_key_pem();
    if ($private_pem === false) {
        return new WP_REST_Response(['error' => 'server_misconfigured', 'message' => 'Private key not configured'], 500);
    }

    $payload = [
        'sub' => (string)$user_id,
        'user_login' => $user->user_login,
        'email' => $user->user_email,
        // any other claims you need
    ];

    $token_or_err = cjrs_make_jwt_rs256($payload, $private_pem, 3600);
    if (is_wp_error($token_or_err)) {
        return new WP_REST_Response(['error' => 'token_generation_failed', 'message' => $token_or_err->get_error_message()], 500);
    }

    $token = $token_or_err;

   
    $resp = [
        'token' => $token,
        'user' => [
            'id' => $user_id,
            'username' => $user->user_login,
            'display_name' => $user->display_name,
            'email' => $user->user_email,
        ],
        'expires_in' => 3600,
        'alg' => 'RS256',
    ];

    return new WP_REST_Response($resp, 200);
}

function sso_login_with_jwt(\WP_REST_Request $request) {
    $token = $request->get_param('token');
    if (!$token) {
        return new WP_Error('no_token', 'JWT missing', ['status' => 400]);
    }

    try {
        $payload = verify_jwt_rs256($token, __DIR__ . '/sign/jwt_public.pem');
        $user_id = $payload['sub']; 

        $user = get_user_by('ID', $user_id);
        if (!$user) {
            throw new Exception('User not found');
        }

        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID, true);

        wp_redirect(home_url());
        exit;
    } catch (Exception $e) {
        return new WP_Error('invalid_token', $e->getMessage(), ['status' => 401]);
    }
}
