<?php

$current_form = isset( $_COOKIE['oauth2_grant_type'] ) && array_key_exists( $_COOKIE['oauth2_grant_type'], $grant_type_fields )
	? $_COOKIE['oauth2_grant_type']
	: array_keys( $grant_type_fields )[0];

function select( array $grant_types, string $the_grant_type ) {
?>
	<select id="grant_type-<?php echo esc_html( $the_grant_type ); ?>" name="grant_type">
<?php
	foreach ( $grant_types as $grant_type => $grant_type_label ) :
		$selected = $grant_type === $the_grant_type ? 'selected="selected"' : ''
?>
		<option <?php echo $selected; ?> value="<?php echo esc_html( $grant_type ); ?>"><?php echo esc_html( $grant_type_label ); ?></option>
	<?php endforeach; ?>
	</select>
<?php
}

foreach ( $grant_type_fields as $grant_type => $fields ) :
	$active = $grant_type === $current_form ? 'active' : '';
?>
<form class="<?php echo $active; ?>" id="<?php echo esc_html( $grant_type ); ?>" action="" method="post">
	<ul>
		<li>
			<label for="grant_type-<?php echo esc_html( $grant_type ); ?>">Grant Type</label>
			<?php select( $grant_types, $grant_type ); ?>
		</li>
<?php
	foreach ( $fields as $field_name => $field_label ) :
		$placeholder = 'extra' === $field_name ? 'foo=bar&doughnut=delicious' : '';
		if ( 'redirect_uri' === $field_name ) {
			$disabled = 'disabled="disabled"';
			$value = $redirect_uri;
		} else {
			$disabled = '';
			$value = isset( $_COOKIE['oauth2_' . $field_name] ) ? $_COOKIE['oauth2_' . $field_name] : '';
		}
?>
		<li>
			<label for="<?php echo esc_html( $field_name ); ?>"><?php echo esc_html( $field_label ); ?></label>
			<input
				type="text" id="<?php echo esc_html( $field_name ); ?>"
				<?php echo $disabled; ?>
				name="<?php echo esc_html( $field_name ); ?>"
				value="<?php echo esc_html( $value ); ?>"
				placeholder="<?php echo esc_html( $placeholder ); ?>"
			/>
		</li>
<?php
	endforeach;
?>
		<li>
			<input type="hidden" name="csrf" value="<?php echo esc_html( $csrf ); ?>" />
			<input type="submit" />
		</li>
	</ul>
</form>

<?php

endforeach;

?>

<script nonce="<?php echo esc_html( $script_nonce ); ?>">
(function(){
	const selects = document.querySelectorAll( 'select[name=grant_type]' );
	let currentForm = document.querySelector( 'form.active' );
	let currentSelect;

	function initSelect() {
		currentSelect = currentForm.querySelector( 'select[name=grant_type]' );
		currentSelect.addEventListener( 'change', handleChange, false );
	}

	function handleChange( event ) {
		currentSelect.removeEventListener( 'change', handleChange, false );

		selects.forEach( select => { select.value = currentSelect.value } )

		currentForm.className = '';
		currentForm = document.getElementById( currentSelect.value );
		currentForm.className = 'active';
		initSelect();
		currentSelect.focus();
	}

	initSelect();
})();
</script>
