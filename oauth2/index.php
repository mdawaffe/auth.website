<?php

header( 'Expires: Wed, 11 Jan 1984 05:00:00 GMT' );
header( 'Last-Modified: ' . gmdate( 'D, d M Y H:i:s' ) . ' GMT' );
header( 'Cache-Control: no-cache, must-revalidate, max-age=0' );
header( 'Pragma: no-cache' );
header( "Content-Security-Policy: default-src 'none'; img-src 'self'; style-src 'self'; sandbox allow-forms allow-scripts; form-action 'self'; frame-ancestors 'none';" );
header( 'X-Frame-Options: DENY' );

$fields = [
	'authorization_url' => 'Authorization URL',
	'token_url'         => 'Token URL',
	'client_id'         => 'Client ID',
	'client_secret'     => 'Client Secret',
	'scope'             => 'Scope',
	'extra'             => 'Extra',
];

if ( isset( $_COOKIE['csrf'] ) ) {
	$csrf = $_COOKIE['csrf'];
} elseif ( empty( $_GET ) ) {
	$csrf = strtr( base64_encode( random_bytes( 12 ) ), '+/', '-_' );
	set_cookie( 'csrf', $csrf );
} else {
	$csrf = '';
}

if ( isset( $_COOKIE['hmac'] ) ) {
	$hmac = $_COOKIE['hmac'];
} elseif ( empty( $_GET ) ) {
	$hmac = strtr( base64_encode( random_bytes( 12 ) ), '+/', '-_' );
	set_cookie( 'hmac', $hmac );
} else {
	$hmac = '';
}

function hmac( $data ) {
	global $hmac;

	return hash_hmac( 'sha256', $data, $hmac );
}

function esc_html( $string ) {
	return htmlspecialchars( $string, ENT_QUOTES );
}

function set_cookie( $name, $value ) {
	header( sprintf( 'Set-Cookie: %s=%s; Secure; HttpOnly; SameSite=Strict', rawurlencode( $name ), rawurlencode( $value ) ), false );
}

function clear_cookie( $name ) {
	header( sprintf( 'Set-Cookie: %s=.; Secure; HttpOnly; SameSite=Strict; Expires=Thu, 01 Jan 1970 00:00:00 GMT', rawurlencode( $name ) ), false );
}

function clear_all_cookies() {
	foreach ( $fields as $field_name => $_ ) {
		clear_cookie( "oauth2_{$field_name}" );
	}
}

function my_url() {
	return sprintf( 'https://%s%s', $_SERVER['HTTP_HOST'], explode( '?', $_SERVER['REQUEST_URI'] )[0] );
}

function template( $template, $redirect_or_scope ) {
	global $script_nonce;

	if ( is_string( $redirect_or_scope ) ) {
		$redirect = '<meta http-equiv="refresh" content="0; url=' . esc_html( $redirect_or_scope ) . '" />';
	} else {
		$redirect = '';
	}

	if ( is_array( $redirect_or_scope ) ) {
		extract( $redirect_or_scope );
	}
?>
<!DOCTYPE html>
<html>
	<head>
		<meta charset="utf-8" />
		<title>Auth.Website: OAuth2</title>
		<?php echo $redirect; ?>
		<link rel="icon" href="/auth.website-32.png" />
		<link href="/style.css" rel="stylesheet" />
	</head>
	<body>
		<h1>🔐Auth.Website: OAuth2</h1>
		<?php require( __DIR__ . "/views/{$template}.php" ); ?>
	</body>
</html>
<?php
	exit;
}

if ( 'POST' === strtoupper( $_SERVER['REQUEST_METHOD'] ) ) {
	if ( $_POST['csrf'] !== $_COOKIE['csrf'] ) {
		die( 'CSRF MISMATCH!' );
	}

	// Don't support foo[]=bar&foo[]=lol in extra.
	// http_build_query() (when constructing the authorization URL)
	// won't put them back together correctly anyway.
	parse_str( $_POST['extra'], $extra );
	$extra = array_map( function( $string ) { return (string) $string; }, $extra );
	$_POST['extra'] = http_build_query( $extra, '', '&', PHP_QUERY_RFC3986 );

	foreach ( $fields as $field_name => $_ ) {
		if ( false !== strpos( $field_name, 'url' ) ) {
			if ( 0 !== strpos( $_POST[$field_name], 'https://' ) ) {
				die( "URLs must begin with 'https://'" );
			}
		}
		set_cookie( "oauth2_{$field_name}", $_POST[$field_name] );
	}

	$url = $_POST['authorization_url'];

	if ( false === strpos( $url, '?' ) ) {
		$url .= '?';
	} else {
		$url .= '&';
	}

	$url .= http_build_query( array_merge( $extra, [
		'redirect_uri' => my_url(),
		'response_type' => 'code',
		'client_id' => $_POST['client_id'],
		'scope' => $_POST['scope'],
		'state' => hmac( "$csrf|{$_POST['client_id']}|{$_POST['authorization_url']}" ),
	] ), '', '&', PHP_QUERY_RFC3986 );

	// We can't just redirect. Chrome (and others?) will bail
	// since it will interpret the redirect (even a 303) as a
	// form submission (to authorization_url), which is forbidden
	// by our Content-Security-Policy header.
	template( 'loading', $url );
}

if ( isset( $_GET['code'] ) ) {
	$action = isset( $_GET['action'] ) ? $_GET['action'] : 'receive';

	switch ( $action ) {
	case 'receive' :
		// We can't just retrieve the token in one step.
		// The redirect from authorization_url to here
		// means Chrome (and others?) won't send our SameSite=Strict
		// cookies during this request (I think this is a bug).
		// Instead, we meta-refresh to another URL on our site
		// The cookies will be sent on that next request.
		template( 'loading', $_SERVER['REQUEST_URI'] . '&action=retrieve' );
	case 'retrieve' :
		if ( ! $csrf || ! $hmac || hmac( "$csrf|{$_COOKIE['oauth2_client_id']}|{$_COOKIE['oauth2_authorization_url']}" ) !== $_GET['state'] ) {
			die( 'STATE MISMATCH!' );
		}

		$post = stream_context_create( [
			'http' => [
				'method'  => 'POST',
				'header'  => 'Content-type: application/x-www-form-urlencoded',
				'content' => http_build_query( [
					'client_id' => $_COOKIE['oauth2_client_id'],
					'client_secret' => $_COOKIE['oauth2_client_secret'],
					'grant_type' => 'authorization_code',
					'code' => $_GET['code'],
					'redirect_uri' => my_url(),
				] ),
				'ignore_errors' => true,
			],
		] );

		$response = file_get_contents(
			$_COOKIE['oauth2_token_url'],
			false,
			$post
		);

		template( 'response', compact( 'response' ) );
	default :
		die( 'Huh?' );
	}
}

template( 'form', compact( 'fields', 'csrf' ) );
