<?php

require( dirname( __DIR__ ) . '/functions.php' );

header( 'Expires: Wed, 11 Jan 1984 05:00:00 GMT' );
header( 'Last-Modified: ' . gmdate( 'D, d M Y H:i:s' ) . ' GMT' );
header( 'Cache-Control: no-cache, must-revalidate, max-age=0' );
header( 'Pragma: no-cache' );
header( "Content-Security-Policy: default-src 'none'; img-src 'self'; style-src 'self'; sandbox allow-forms; form-action 'self'; frame-ancestors 'none';" );
header( 'X-Frame-Options: DENY' );

$grant_types = [
	'authorization_code' => 'Authorization Code',
	'password' => 'Password',
	'implicit' => 'Implicit',
];

$grant_type_fields = [
	'authorization_code' => [
		'authorization_url' => 'Authorization URL',
		'token_url'         => 'Token URL',
		'client_id'         => 'Client ID',
		'client_secret'     => 'Client Secret',
		'scope'             => 'Scope',
		'extra'             => 'Extra',
	],
	'implicit' => [
		'authorization_url' => 'Authorization URL',
		'client_id'         => 'Client ID',
		'scope'             => 'Scope',
		'extra'             => 'Extra',
	],
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

function template( string $template = '', array $scope = [], string $redirect = '' ) {
	template_with_title(
		'Auth.Website: OAuth2',
		$template ? __DIR__ . "/views/{$template}.php" : '',
		$scope,
		$redirect
	);
}

$redirect_uri = my_url() . '?action=receive';

if ( 'POST' === strtoupper( $_SERVER['REQUEST_METHOD'] ) ) {
	if (
		empty( $_POST['csrf'] )
	||
		empty( $_COOKIE['csrf'] )
	||
		! hash_equals( $_POST['csrf'], $_COOKIE['csrf'] )
	) {
		die( 'CSRF MISMATCH!' );
	}

	// Don't support foo[]=bar&foo[]=lol in extra.
	// http_build_query() (when constructing the authorization URL)
	// won't put them back together correctly anyway.
	parse_str( $_POST['extra'], $extra );
	$extra = array_map( function( $string ) { return (string) $string; }, $extra );
	$_POST['extra'] = http_build_query( $extra, '', '&', PHP_QUERY_RFC3986 );

	$grant_type = $_POST['grant_type'];
	if ( ! array_key_exists( $grant_type, $grant_types ) ) {
		die( "NO" );
	}
	set_cookie( 'oauth2_grant_type', $grant_type );

	foreach ( $grant_type_fields[$grant_type] as $field_name => $_ ) {
		if ( false !== strpos( $field_name, 'url' ) ) {
			if ( 0 !== strpos( $_POST[$field_name], 'https://' ) ) {
				die( "URLs must begin with 'https://'" );
			}
		}
		set_cookie( "oauth2_{$field_name}", $_POST[$field_name] );
	}

	$state = hmac( "$csrf|{$_POST['client_id']}|{$_POST['authorization_url']}", $hmac_key );

	switch ( $grant_type ) {
	case 'authorization_code' :
		$url = $_POST['authorization_url'];

		$parameters = [
			'redirect_uri' => $redirect_uri,
			'response_type' => 'code',
			'client_id' => $_POST['client_id'],
			'scope' => $_POST['scope'],
			'state' => $state,
		];
		break;

	case 'implicit' :
		$url = $_POST['authorization_url'];

		$parameters = [
			'redirect_uri' => $redirect_uri,
			'response_type' => 'token',
			'client_id' => $_POST['client_id'],
			'scope' => $_POST['scope'],
			'state' => $state,
		];
		break;

	default :
		die( 'NO' );
	}

	if ( false === strpos( $url, '?' ) ) {
		$url .= '?';
	} else {
		$url .= '&';
	}

	$url .= http_build_query( array_merge( $extra, $parameters ), '', '&', PHP_QUERY_RFC3986 );

	// We can't just redirect. Chrome (and others?) will bail
	// since it will interpret the redirect (even a 303) as a
	// form submission (to authorization_url), which is forbidden
	// by our Content-Security-Policy header.
	// Instead, send a Refresh header and output a meta-refresh
	// element.
	template( 'loading', [], $url );
	exit;
}

if ( isset( $_GET['code'] ) ) {
	$action = isset( $_GET['action'] ) ? $_GET['action'] : 'receive';

	switch ( $action ) {
	case 'receive' :
		// We can't just retrieve the token in one step.
		// The redirect from authorization_url to here
		// means Chrome (and others?) won't send our SameSite=Strict
		// cookies during this request (I think this is a bug).
		// Instead, Refresh/meta-refresh to another URL on our
		// site. The cookies will be sent on that next request.

		$retrieve_url = str_replace( '?action=receive', '?action=retrieve', $_SERVER['REQUEST_URI'] );
		if ( false === strpos( $retrieve_url, 'action=retrieve' ) ) {
			$retrieve_url .= '&action=retrieve';
		}

		template( 'loading', [], $retrieve_url );
		exit;
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
		exit;
	default :
		die( 'Huh?' );
	}
}

template(); // output the header

echo "<div id='grant-type-forms'><span>Grant Type:</span>\n";
foreach ( $grant_type_fields as $grant_type => $fields ) {
	$grant_type_label = $grant_types[$grant_type];
	template( 'form', compact( 'fields', 'grant_type', 'grant_type_label', 'csrf' ) );
}
echo "</div>\n";

template( 'warning' );
