<?php

if ( isset( $response ) ) {
	$formatted = 'RESPONSE: ' . json_encode(
		json_decode( $response ),
		JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
	);

	$formatted = '<span>' . join( "</span>\n<span>", array_map( 'esc_html', explode( "\n", $formatted ) ) ) . '</span>';
} else {
	$formatted = '';
}

?>
<pre id="response"><?php echo $formatted; ?></pre>

<p><a href="oauth2/">Go Back</a></p>

<?php

if ( ! isset( $script_nonce ) ) {
	return;
}

?>
<script nonce="<?php echo esc_html( $script_nonce ); ?>">
	function receiveImplicit() {
		const responseQuery = new URLSearchParams( document.location.hash.slice( 1 ) );
		const responseObject = [...responseQuery.entries()].reduce( ( formatted, [ key, value ] ) => ({...formatted, [key]: value}), {} );
		const formatted = JSON.stringify( responseObject, null, '    ' )
		const contents = document.createDocumentFragment();

		formatted.split( '\n' ).reduce( ( contents, line, i ) => {
			const span = document.createElement( 'span' );
			span.textContent = i ? line : `RESPONSE: ${line}`
			contents.appendChild( span );
			contents.appendChild( document.createTextNode( '\n' ) );
			return contents;
		}, contents );

		document.getElementById( 'response' ).appendChild( contents );
	}

	function clearURL() {
		window.history.replaceState( {}, '', document.location.toString().split( '?' )[0] );
	}

	if ( document.location.hash ) {
		receiveImplicit();
	}

	clearURL();
</script>
