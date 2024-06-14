<?php

require __DIR__ . '/functions.php';

csp_header( 'basic' );

template_with_title( 'Auth.Website', function() {
?>
	<ul>
		<li><a href="./oauth2/">OAuth2</a></li>
	</ul>
<?php
} );
