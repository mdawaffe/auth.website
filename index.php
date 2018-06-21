<?php

header( "Content-Security-Policy: default-src 'none'; img-src 'self'; style-src 'self'; sandbox allow-forms allow-scripts; form-action 'self'; frame-ancestors 'none';" );
header( 'X-Frame-Options: DENY' );

?>
<!DOCTYPE html>
<html>
	<head>
		<meta charset="utf-8" />
		<title>Auth.Website</title>
		<link rel="stylesheet" href="/style.css" />
	</head>
	<body>
		<h1>🔐Auth.Website</h1>
		<ul>
			<li><a href="/oauth2/">OAuth2</a></li>
		</ul>
	</body>
</html>
