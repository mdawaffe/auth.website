<?php

require( dirname( __DIR__ ) . '/functions.php' );

headers( $script_nonce );

$grant_types = [
	'authorization_code' => 'Authorization Code',
	'password' => 'Password',
	'implicit' => 'Implicit',
];

$grant_type_fields = [
	'authorization_code' => [
		'authorization_url' => 'Authorization URL',
		'token_url'         => 'Token URL',
		'redirect_uri'      => 'Client Redirect URI',
		'client_id'         => 'Client ID',
		'client_secret'     => 'Client Secret',
		'scope'             => 'Scope',
		'extra'             => 'Extra',
	],
	'password' => [
		'token_url'         => 'Token URL',
		'client_id'         => 'Client ID',
		'client_secret'     => 'Client Secret',
		'username'          => 'Username',
		'password'          => 'Password',
		'scope'             => 'Scope',
		'extra'             => 'Extra',
	],
	'implicit' => [
		'authorization_url' => 'Authorization URL',
		'redirect_uri'      => 'Client Redirect URI',
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

function post_to_url( string $url, array $body = [], array $headers = [] ) {
	$url_host = parse_url( $url, PHP_URL_HOST );

	$url = wp_http_validate_url( $url );

	if ( ! $url_host || ! $url ) {
		die( 'INVALID TOKEN URL' );
	}

	$post = stream_context_create( [
		'http' => [
			'method'  => 'POST',
			'header'  =>
				array_merge( [
					"Host: $url_host",
					'Content-type: application/x-www-form-urlencoded',
				], $headers ),
			'follow_location' => 0,
			'content' => http_build_query( $body ),
			'ignore_errors' => true,
		],
		'ssl' => [
			'peer_name' => $url_host,
		],
	] );

	return file_get_contents(
		$url,
		false,
		$post
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
		if ( isset( $_POST[$field_name] ) ) {
			set_cookie( "oauth2_{$field_name}", $_POST[$field_name] );
		}
	}

	$state = hmac( "$csrf|{$_POST['client_id']}", $hmac_key );

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

	case 'password' :
		$token_url = $_POST['token_url'];

		$parameters = [
			'grant_type' => 'password',
			'client_id' => $_POST['client_id'],
			'client_secret' => $_POST['client_secret'],
			'username' => $_POST['username'],
			'password' => $_POST['password'],
			'scope' => $_POST['scope'],
			'state' => $state,
		];

		$basic = base64_encode( rawurlencode( $_POST['client_id'] ) . ':' . rawurlencode( $_POST['client_secret'] ) );

		$response = post_to_url(
			$token_url,
			array_merge( $extra, $parameters ),
			[ "Authorization: Basic $basic" ]
		);

		template( 'response', compact( 'response' ) );
		exit;

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

if ( isset( $_GET['action'] ) ) {
	switch ( $_GET['action'] ) {
	case 'receive' :
		// grant_type=authorization_code
		if ( isset( $_GET['code'] ) ) {
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
		}

		// grant_type=implicit

		template( 'response', compact( 'script_nonce' ) );
		exit;
	case 'retrieve' :
		if ( !isset( $_GET['code'] ) ) {
			die( 'Missing code' );
		}

		if (
			! $csrf
		||
			! $hmac_key
		||
			! hash_equals(
				hmac( "$csrf|{$_COOKIE['oauth2_client_id']}", $hmac_key ),
				$_GET['state']
			)
		) {
			die( 'STATE MISMATCH!' );
		}

		$token_url = $_COOKIE['oauth2_token_url'];

		$response = post_to_url(
			$token_url,
			[
				'client_id' => $_COOKIE['oauth2_client_id'],
				'client_secret' => $_COOKIE['oauth2_client_secret'],
				'grant_type' => 'authorization_code',
				'code' => $_GET['code'],
				'redirect_uri' => $redirect_uri,
			]
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
	template( 'form', compact( 'fields', 'grant_type', 'grant_type_label', 'redirect_uri', 'csrf' ) );
}
echo "</div>\n";

template( 'warning' );
