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
	function getTokenData() {
		const responseQuery = new URLSearchParams( document.location.hash.slice( 1 ) );
		return [...responseQuery.entries()].reduce( ( formatted, [ key, value ] ) => ({...formatted, [key]: value}), {} );
	}
</script>
<?php

if ( isset( $retrieve_url ) && $retrieve_url ) :
	// Since we have to redirect to the retrieve URL anyway,
	// we may as well pass along `state` so we can verify it server-side
?>
<script nonce="<?php echo esc_html( $script_nonce ); ?>">
(function() {
	const retrieveURL = JSON.parse( decodeURIComponent( '<?php echo rawurlencode( json_encode( $retrieve_url ) ); ?>' ) );
	const tokenData = getTokenData();
	document.location = retrieveURL + '&state=' + encodeURIComponent( tokenData.state ) + document.location.hash;
})();
</script>
<?php

exit;
endif;

?>
<script nonce="<?php echo esc_html( $script_nonce ); ?>">
(function() {
	function receiveImplicit() {
		const tokenData = getTokenData();
		delete tokenData.state;

		const formatted = JSON.stringify( tokenData, null, '    ' )
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
})();
</script>
