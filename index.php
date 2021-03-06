<?php

header( "Content-Security-Policy: default-src 'none'; img-src 'self'; style-src 'self'; sandbox allow-same-origin allow-forms; form-action 'self'; frame-ancestors 'none'; base-uri 'self'; upgrade-insecure-requests;" );
header( 'X-Frame-Options: DENY' );

require __DIR__ . '/functions.php';

template_with_title( 'Auth.Website', function() {
?>
	<ul>
		<li><a href="./oauth2/">OAuth2</a></li>
	</ul>
<?php
} );
