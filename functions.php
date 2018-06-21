<?php

function hmac( $data, $hmac_key ) {
	return hash_hmac( 'sha256', $data, $hmac_key );
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

function my_url() {
	return sprintf( 'https://%s%s', $_SERVER['HTTP_HOST'], explode( '?', $_SERVER['REQUEST_URI'] )[0] );
}

function template_with_dir_and_title( $dir, $title, $template, $redirect_or_scope ) {
	if ( is_string( $redirect_or_scope ) ) {
		$redirect = '<meta http-equiv="refresh" content="0; url=' . esc_html( $redirect_or_scope ) . '" />';
		header( "Refresh: 0; url=$redirect_or_scope" );
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
		<title><?php echo esc_html( $title ); ?></title>
		<?php echo $redirect; ?>
		<link rel="icon" href="/auth.website-32.png" />
		<link href="/style.css" rel="stylesheet" />
	</head>
	<body>
		<h1>🔐<?php echo esc_html( $title ); ?></h1>
		<?php require( $dir . "{$template}.php" ); ?>
	</body>
</html>
<?php
	exit;
}

/**
 * Validate a URL for safe use in the HTTP API.
 *
 * Modified version of WordPress' function
 * https://core.trac.wordpress.org/browser/trunk/src/wp-includes/http.php?rev=42894#L515
 *
 * @since 3.5.2
 *
 * @param string $url
 * @return false|string URL or false on failure.
 */
function wp_http_validate_url( $url ) {
	if ( 0 !== strpos( $url, 'https://' ) ) {
		return false;
	}

	$parsed_url = @parse_url( $url );
	if ( ! $parsed_url || empty( $parsed_url['host'] ) ) {
		return false;
	}

	if ( isset( $parsed_url['user'] ) || isset( $parsed_url['pass'] ) ) {
		return false;
	}

	if ( false !== strpbrk( $parsed_url['host'], ':#?[]' ) ) {
		return false;
	}

	$host = trim( $parsed_url['host'], '.' );

	if ( $host === $_SERVER['HTTP_HOST'] ) {
		return false;
	}

	$ip_regex = '#^(([1-9]?\d|1\d\d|25[0-5]|2[0-4]\d)\.){3}([1-9]?\d|1\d\d|25[0-5]|2[0-4]\d)$#';

	if ( preg_match( $ip_regex, $host ) ) {
		$ips = [ $host ];
	} else {
		$ips = gethostbynamel( $host );
	}

	if ( ! $ips ) {
		return false;
	}

	if ( preg_match( $ip_regex, $_SERVER['HTTP_HOST'] ) ) {
		$my_ips = [ $_SERVER['HTTP_HOST'] ];
	} else {
		$my_ips = gethostbynamel( $_SERVER['HTTP_HOST'] );
	}

	if ( ! $my_ips ) {
		return false;
	}

	if ( array_intersect( $ips, $my_ips ) ) {
		return false;
	}

	// Just pin to the first IP
	$ip = $ips[0];

	$parts = array_map( 'intval', explode( '.', $ip ) );
	if ( 127 === $parts[0] || 10 === $parts[0] || 0 === $parts[0]
		|| ( 172 === $parts[0] && 16 <= $parts[1] && 31 >= $parts[1] )
		|| ( 192 === $parts[0] && 168 === $parts[1] )
	) {
		// If host appears local, reject unless specifically allowed.
		return false;
	}

	return preg_replace( sprintf( '#^https://%s(:|/|$)#', preg_quote( $host, '#' ) ), "https://$ip\\1", $url );
}
