<?php

$formatted = 'RESPONSE: ' . json_encode(
	json_decode( $response ),
	JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
);

$formatted = '<span>' . join( "</span>\n<span>", array_map( 'esc_html', explode( "\n", $formatted ) ) ) . '</span>';

?>
<pre><?php echo $formatted; ?></pre>

<p><a href="./">Go Back</a></p>
