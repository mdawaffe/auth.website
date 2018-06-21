<form action="" method="post">
	<table>
		<?php foreach ( $fields as $field_name => $field_label ) : ?>
		<tr>
			<th scope="row"><label for="<?php echo esc_html( $field_name ); ?>"><?php echo esc_html( $field_label ); ?></label></th>
			<td><input type="text" id="<?php echo esc_html( $field_name ); ?>" name="<?php echo esc_html( $field_name ); ?>" value="<?php echo esc_html(
				isset( $_COOKIE['oauth2_' . $field_name] ) ? $_COOKIE['oauth2_' . $field_name] : ''
			); ?>" /></td>
		</tr>
		<?php endforeach; ?>
		<tr>
			<td colspan="2">
				<input type="hidden" name="csrf" value="<?php echo esc_html( $csrf ); ?>" />
				<input type="submit" />
			</td>
		</tr>
	</table>
</form>
