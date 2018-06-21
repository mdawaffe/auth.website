<?php

require( dirname( __DIR__ ) . '/functions.php' );

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
	$hmac_key = $_COOKIE['hmac'];
} elseif ( empty( $_GET ) ) {
	$hmac_key = strtr( base64_encode( random_bytes( 12 ) ), '+/', '-_' );
	set_cookie( 'hmac', $hmac_key );
} else {
	$hmac_key = '';
}

function template( $template, $redirect_or_scope ) {
	template_with_dir_and_title( __DIR__ . '/views/', 'Auth.Website: OAuth2', $template, $redirect_or_scope );
}

if ( 'POST' === strtoupper( $_SERVER['REQUEST_METHOD'] ) ) {
	if ( ! hash_equals( $_POST['csrf'], $_COOKIE['csrf'] ) ) {
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
		'state' => hmac( "$csrf|{$_POST['client_id']}|{$_POST['authorization_url']}", $hmac_key ),
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
		if (
			! $csrf
		||
			! $hmac_key
		||
			! hash_equals(
				hmac( "$csrf|{$_COOKIE['oauth2_client_id']}|{$_COOKIE['oauth2_authorization_url']}", $hmac_key ),
				$_GET['state']
			)
		) {
			die( 'STATE MISMATCH!' );
		}

		$token_url = $_COOKIE['oauth2_token_url'];
		$token_url_host = parse_url( $token_url, PHP_URL_HOST );

		$token_url = wp_http_validate_url( $token_url );

		if ( ! $token_url_host || ! $token_url ) {
			die( 'INVALID TOKEN URL' );
		}

		$post = stream_context_create( [
			'http' => [
				'method'  => 'POST',
				'header'  => [
					"Host: $token_url_host",
					'Content-type: application/x-www-form-urlencoded',
				],
				'follow_location' => 0,
				'content' => http_build_query( [
					'client_id' => $_COOKIE['oauth2_client_id'],
					'client_secret' => $_COOKIE['oauth2_client_secret'],
					'grant_type' => 'authorization_code',
					'code' => $_GET['code'],
					'redirect_uri' => my_url(),
				] ),
				'ignore_errors' => true,
			],
			'ssl' => [
				'peer_name' => $token_url_host,
			],
		] );

		$response = file_get_contents(
			$token_url,
			false,
			$post
		);

		template( 'response', compact( 'response' ) );
	default :
		die( 'Huh?' );
	}
}

template( 'form', compact( 'fields', 'csrf' ) );
