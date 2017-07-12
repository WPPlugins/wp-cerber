<?php
/*
 	Copyright (C) 2015-17 Gregory Markov, http://wpcerber.com

    Licenced under the GNU GPL

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

/*

*========================================================================*
|                                                                        |
|	       ATTENTION!  Do not change or edit this file!                  |
|                                                                        |
*========================================================================*

*/

/**
 * Display Tools admin page
 *
 */
function cerber_tools_page() {
	?>
	<div class="wrap">

		<h2><?php _e( 'Tools', 'wp-cerber' ) ?></h2>

		<?php
		cerber_show_aside( 'tools' );
		cerber_show_tools();
		?>
	</div>
	<?php
}

/*
	Show Tools screen
*/
function cerber_show_tools(){
	global $wpdb;
	$form = '<h3>'.__('Export settings to the file','wp-cerber').'</h3>';
	$form .= '<p>'.__('When you click the button below you will get a configuration file, which you can upload on another site.','wp-cerber').'</p>';
	$form .= '<p>'.__('What do you want to export?','wp-cerber').'</p><form action="" method="get">';
	$form .= '<input id="exportset" name="exportset" value="1" type="checkbox" checked> <label for="exportset">'.__('Settings','wp-cerber').'</label>';
	$form .= '<p><input id="exportacl" name="exportacl" value="1" type="checkbox" checked> <label for="exportacl">'.__('Access Lists','wp-cerber').'</label>';
	$form .= '<p><input type="submit" name="cerber_export" id="submit" class="button button-primary" value="'.__('Download file','wp-cerber').'"></form>';

	$form .= '<h3 style="margin-top:2em;">'.__('Import settings from the file','wp-cerber').'</h3>';
	$form .= '<p>'.__('When you click the button below, file will be uploaded and all existing settings will be overridden.','wp-cerber').'</p>';
	$form .= '<p>'.__('Select file to import.','wp-cerber').' '. sprintf( __( 'Maximum upload file size: %s.'), esc_html(size_format(wp_max_upload_size())));
	$form .= '<form action="" method="post" enctype="multipart/form-data">'.wp_nonce_field( 'crb_import', 'crb_field');
	$form .= '<p><input type="file" name="ifile" id="ifile" required="required">';
	$form .= '<p>'.__('What do you want to import?','wp-cerber').'</p><p><input id="importset" name="importset" value="1" type="checkbox" checked> <label for="importset">'.__('Settings','wp-cerber').'</label>';
	$form .= '<p><input id="importacl" name="importacl" value="1" type="checkbox" checked> <label for="importacl">'.__('Access Lists','wp-cerber').'</label>';
	$form .= '<p><input type="submit" name="cerber_import" id="submit" class="button button-primary" value="'.__('Upload file','wp-cerber').'"></p></form>';
	echo $form;

	?>
	<h3 style="margin-top: 3em;">Diagnostic and maintenance</h3>
	<a href="#"  onclick="toggle_visibility('diagnostic'); return false;">Show diagnostic information</a>
	<form id="diagnostic" style="display: none; margin-top: 2em;">
		<div>
			<h3>Cerber's database info</h3>
			<?php echo cerber_db_diag(); ?>
			<?php echo '<p style="text-align: right;"><a class="button button-secondary" href="' . wp_nonce_url( add_query_arg( array( 'force_repair_db' => 1 ) ), 'control', 'cerber_nonce' ) . '"><span class="dashicons dashicons-admin-tools" style="vertical-align: middle;"></span> Force repair tables</a></p>'; ?>
		</div>
		<div>
			<h3>Server info</h3>
			<textarea name="dia"><?php
				global $wp_version;

				echo 'WordPress version: ' . $wp_version . "\n";
                echo 'WordPress options table: '.$wpdb->prefix.'options'."\n";
				echo 'PHP version: ' . phpversion() . "\n";
				foreach ( $_SERVER as $key => $value ) {
					if ( $key == 'HTTP_COOKIE' ) {
						continue;
					}
					//echo '['.$key.'] => '. htmlspecialchars($value)."\n";
					echo '[' . $key . '] => ' . strip_tags( $value ) . "\n";
				}
				?>
			</textarea>
		</div>
		<div>
			<h3>Cerber Lab status</h3>
			<?php
			echo lab_status();
			echo '<p style="text-align: right;"><a class="button button-secondary" href="'.wp_nonce_url(add_query_arg(array('force_check_nodes'=>1)),'control','cerber_nonce').'">Force recheck nodes</a></p>';
			?>
		</div>
	</form>
	<script type="text/javascript">
	function toggle_visibility(id) {
       var e = document.getElementById(id);
       if(e.style.display === 'block')
          e.style.display = 'none';
       else
          e.style.display = 'block';
    }
	</script>
	<?php
}
/*
	Create export file
*/
add_action('admin_init','cerber_export');
function cerber_export(){
	global $wpdb;
	if ($_SERVER['REQUEST_METHOD']!='GET' || !isset($_GET['cerber_export'])) return;
	if (!current_user_can('manage_options')) wp_die('Error!');
	$p = cerber_plugin_data();
	$data = array('cerber_version' => $p['Version'],'home'=> get_home_url(),'date'=>date('d M Y H:i:s'));
	if (!empty($_GET['exportset'])) $data ['options'] = cerber_get_options(); // @since 2.0
	if (!empty($_GET['exportacl']))	$data ['acl'] = cerber_acl_all('ip,tag,comments');
	$file = json_encode($data);
	$file .= '==/'.strlen($file).'/'.crc32($file).'/EOF';
	header($_SERVER["SERVER_PROTOCOL"].' 200 OK');
	header("Content-type: application/force-download");
	header("Content-Type: application/octet-stream");
	header("Content-Disposition: attachment; filename=wpcerber.config");
	echo $file;
	exit;
}
/*
	Load and Parse file and import settings
*/
add_action('admin_init','cerber_import');
function cerber_import(){
	global $wpdb, $wp_cerber;
	if (!isset($_POST['cerber_import']) || $_SERVER['REQUEST_METHOD']!='POST') return;
	check_admin_referer('crb_import','crb_field');
	if (!current_user_can('manage_options')) wp_die('Upload failed.');
	$ok = true;
	if (!is_uploaded_file($_FILES['ifile']['tmp_name'])) {
		cerber_admin_notice( __('No file was uploaded or file is corrupted','wp-cerber'));
		return;
	}
	elseif ($file = file_get_contents($_FILES['ifile']['tmp_name'])) {
		$p = strrpos($file,'==/');
		$data = substr($file,0,$p);
		$sys = explode('/',substr($file,$p));
		if ($sys[3] == 'EOF' && crc32($data) == $sys[2] && ($data = json_decode($data, true))) {

			if ($_POST['importset'] && $data['options'] && !empty($data['options']) && is_array($data['options'])) {
				$data['options']['loginpath'] = urldecode($data['options']['loginpath']); // needed to work filter cerber_sanitize_options()
				if ($data['home'] != get_home_url()) {
					$data['options']['sitekey'] = $wp_cerber->getSettings('sitekey');
					$data['options']['secretkey'] = $wp_cerber->getSettings('secretkey');
				}
				cerber_save_options($data['options']); // @since 2.0
			}

			if ($_POST['importacl'] && $data['acl'] && is_array($data['acl']) && !empty($data['acl'])) {
				$acl_ok = true;
				if (false === $wpdb->query("DELETE FROM ".CERBER_ACL_TABLE)) $acl_ok = false;
				foreach($data['acl'] as $row) {
					// if (!$wpdb->query($wpdb->prepare('INSERT INTO '.CERBER_ACL_TABLE.' (ip,tag,comments) VALUES (%s,%s,%s)',$row[0],$row[1],$row[2]))) $acl_ok = false;
					// @since 3.1 if (!$wpdb->insert(CERBER_ACL_TABLE,array('ip'=>$row[0],'tag'=>$row[1],'comments'=>$row[2]),array('%s','%s','%s'))) $acl_ok = false;
					$ip = cerber_parse_ip($row[0]);
					if (!cerber_acl_add($ip,$row[1])){
						$acl_ok = false;
						break;
					}
				}
				if (!$acl_ok) cerber_admin_notice(__('Error while updating','wp-cerber').' '.__('Access Lists','wp-cerber'));
			}

			cerber_admin_message( __('Settings has imported successfully from','wp-cerber').' '.$_FILES['ifile']['name']);
		}
		else $ok = false;
	}
	if (!$ok) cerber_admin_notice(__('Error while parsing file','wp-cerber'));
}

/**
 * Display reCAPTCHA admin page
 *
 */
function cerber_recaptcha_page() {
	?>
	<div class="wrap">
		<h2><?php _e( 'reCAPTCHA settings', 'wp-cerber' ) ?></h2>
			<?php
			cerber_show_aside( 'recaptcha' );
				echo '<div class="crb-main">';
				cerber_show_settings( 'recaptcha' );
				echo '</div';
			?>
	</div>
	<?php
}