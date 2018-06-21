<form action="" method="post">
	<ul>
<?php
	foreach ( $fields as $field_name => $field_label ) :
		$placeholder = 'extra' === $field_name ? 'foo=bar&doughnut=delicious' : '';
?>
		<li>
			<label for="<?php echo esc_html( $field_name ); ?>"><?php echo esc_html( $field_label ); ?></label>
			<input
				type="text" id="<?php echo esc_html( $field_name ); ?>"
				name="<?php echo esc_html( $field_name ); ?>"
				value="<?php echo esc_html( isset( $_COOKIE['oauth2_' . $field_name] ) ? $_COOKIE['oauth2_' . $field_name] : '' ); ?>"
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

<p><small>Only supports <codE>grant_type=authorization_code</code>.</small></p>

<dl>
	<dt>Is this secure?</dt>
	<dd>No :) Why would you trust this site with your OAuth credentials and tokens?</dd>
	<dt>Is it convenient?</dt>
	<dd>Reasonably so.</dd>
</dl>
