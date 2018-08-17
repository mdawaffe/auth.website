<?php

printf(
	'<input id="radio-%1$s" type="radio" %3$s name="grant_type" /><label for="radio-%1$s">%2$s</label>',
	esc_html( $grant_type ),
	esc_html( $grant_type_label ),
	$grant_type === ( $_COOKIE['oauth2_grant_type'] ?? false ) ? 'checked="checked"' : ''
);

?>
<form id="<?php echo esc_html( $grant_type ); ?>" action="" method="post">
	<ul>
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
			<input type="hidden" name="grant_type" value="<?php echo esc_html( $grant_type ); ?>" />
			<input type="submit" />
		</li>
	</ul>
</form>
