<div id='grant-type-forms'>
	<span>Grant Type:</span>

<?php

	foreach ( $grant_type_fields as $grant_type => $fields ) {
		$grant_type_label = $grant_types[$grant_type];
		template( 'form', compact( 'fields', 'grant_type', 'grant_type_label', 'redirect_uri', 'csrf' ) );
	}

?>

</div>
