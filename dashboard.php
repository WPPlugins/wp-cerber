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











if ( ! defined( 'WPINC' ) ) { exit; }

require_once( dirname( __FILE__ ) . '/cerber-tools.php' );

/*
	Display lockouts in dashboard for admins
*/
function cerber_show_lockouts($args = array(), $echo = true){
	global $wpdb, $wp_cerber;

	//$wp_cerber->deleteGarbage();

	if (!empty($args['per_page'])) $per_page = $args['per_page'];
	else $per_page = cerber_get_per_page();

	$limit = (cerber_get_pn() - 1) * $per_page.','.$per_page;

	if ($rows = $wpdb->get_results('SELECT * FROM '. CERBER_BLOCKS_TABLE . ' ORDER BY block_until DESC LIMIT '.$limit)) {
		//$total=$wpdb->get_var('SELECT count(ip) FROM '. CERBER_BLOCKS_TABLE);
		$total= cerber_blocked_num();
		$list=array();
		$base_url = cerber_admin_link('activity');
		$assets_url = plugin_dir_url(CERBER_FILE).'assets/';
		foreach ($rows as $row) {
			$ip = '<a href="'.$base_url.'&filter_ip='.$row->ip.'">'.$row->ip.'</a>';
			$ip_info = cerber_get_ip_info($row->ip,true);
			if (isset($ip_info['hostname'])) $hostname = $ip_info['hostname'];
			else {
				$ip_id = cerber_get_id_ip($row->ip);
				$hostname = '<img data-ip-id="'.$ip_id .'" class="crb-no-hn" src="'.$assets_url.'ajax-loader-ip.gif" />'."\n";
			}

			$list[]='<td>'.$ip.'</td><td>'.$hostname.'</td><td>'.cerber_date($row->block_until).'</td><td>'.$row->reason.'</td><td><a href="'.wp_nonce_url(add_query_arg(array('lockdelete'=>$row->ip)),'control','cerber_nonce').'">'.__('Remove','wp-cerber').'</a></td>';

		}
		$titles = '<tr><th>'.__('IP','wp-cerber').'</th><th>'.__('Hostname','wp-cerber').'</th><th>'.__('Expires','wp-cerber').'</th><th>'.__('Reason','wp-cerber').'</th><th>'.__('Action','wp-cerber').'</th></tr>';
		$table = '<table class="widefat crb-table cerber-margin"><thead>'.$titles.'</thead><tfoot>'.$titles.'</tfoot>'.implode('</tr><tr>',$list).'</tr></table>';

		if (empty($args['no_navi'])) $table .= cerber_page_navi($total,$per_page);

		//echo '<h3>'.sprintf(__('Showing last %d records from %d','wp-cerber'),count($rows),$total).'</h3>';
		$showing = '<h3>'.sprintf(__('Showing last %d records from %d','wp-cerber'),count($rows),$total).'</h3>';

		$view = '<p><b>'.__('Hint','wp-cerber').':</b> ' . __('To view activity, click on the IP','wp-cerber').'</p>';
	}
	else {
		$table = '';
		$view = '<p>'.sprintf(__('No lockouts at the moment. The sky is clear.','wp-cerber')).'</p>';
	}
	$ret = $table.'<div class="cerber-margin">'.$view.'</div>';

	if ($echo) echo $ret;
	else return $ret;
}

/*
	ACL management form in dashboard
*/
function cerber_acl_form(){
	global $wp_cerber;
	echo '<h2>'.__('White IP Access List','wp-cerber').'</h2><p><span style="color:green;" class="dashicons-before dashicons-thumbs-up"></span> '.__('These IPs will never be locked out','wp-cerber').' - <a target="_blank" href="http://wpcerber.com/using-ip-access-lists-to-protect-wordpress/">Know more</a></p>'.
	     cerber_acl_get_table('W');
	echo '<h2>'.__('Black IP Access List','wp-cerber').'</h2><p><span style="color:red;" class="dashicons-before dashicons-thumbs-down"></span> '.__('Nobody can log in or register from these IPs','wp-cerber').' - <a target="_blank" href="http://wpcerber.com/using-ip-access-lists-to-protect-wordpress/">Know more</a></p>'.
	     cerber_acl_get_table('B');
	echo '<p><b><span class="dashicons-before dashicons-star-filled"></span> '.__('Your IP','wp-cerber').': '.$wp_cerber->getRemoteIp().'</b></p>';
	echo '<h4 style="margin-top: 2em;"><span class="dashicons-before dashicons-info"></span> Possible values for entries in the access lists with examples</h4>
	<p>Single IPv6 address: <b>2001:0db8:85a3:0000:0000:8a2e:0370:7334</b>
	<p>Single IPv4 address: <b>192.168.5.22</b>
	<p>IPv4 addresses range with dash: <b>192.168.1.45 - 192.168.22.165</b>
	<p>IPv4 CIDR: <b>192.168.128.0/24</b>
	<p>IPv4 subnet Class A: <b>192.*.*.*</b>
	<p>IPv4 subnet Class B: <b>192.168.*.*</b>
	<p>IPv4 subnet Class C: <b>192.168.77.*</b>';
}
/*
	Create HTML to display ACL area: table + form
*/
function cerber_acl_get_table($tag){
	global $wpdb;
	$activity_url = cerber_admin_link('activity');
	if ($rows = $wpdb->get_results('SELECT * FROM '. CERBER_ACL_TABLE . " WHERE tag = '".$tag."' ORDER BY ip_long_begin, ip")) {
		foreach ($rows as $row) $list[]='<td>'.$row->ip.'</td><td><a class="delete_entry" href="javascript:void(0)" data-ip="'.$row->ip.'">'.__('Remove','wp-cerber').'</a></td><td><a href="'.$activity_url.'&filter_ip='.urlencode($row->ip).'">'.__('Check for activity','wp-cerber').'</a></td>';
		$ret = '<table id="acl_'.$tag.'" class="acl-table"><tr>'.implode('</tr><tr>',$list).'</tr></table>';
	}
	else $ret='<p style="text-align: center;">- <i>'.__('List is empty','wp-cerber').'</i> -</p>';
	$ret = '<div class="acl-wrapper"><div class="acl-items">'
	       .$ret.'</div><form action="" method="post">
	       <table><tr><td><input type="text" name="add_acl_'.$tag.'" required placeholder="Enter IP address, IPv4 addresses range or subnet"> 
	       </td><td><input type="submit" class="button button-primary" value="'.__('Add IP to the list','wp-cerber').'" ></td></tr></table>'
	       .wp_nonce_field('cerber_dashboard','cerber_nonce')
	       .'</form></div>';
	return $ret;
}
/*
	Handle actions with items in ACLs in the dashboard
*/
add_action('admin_init','cerber_acl_form_process');
function cerber_acl_form_process(){

	if ( $_SERVER['REQUEST_METHOD'] != 'POST' || !isset( $_POST['cerber_nonce'] ) ) return;
	if ( !current_user_can( 'manage_options' ) || !wp_verify_nonce( $_POST['cerber_nonce'], 'cerber_dashboard' ) ) return;

	//if (!current_user_can('manage_options')) return;
	//if (!isset($_POST['cerber_nonce']) || !wp_verify_nonce($_POST['cerber_nonce'],'cerber_dashboard')) return;

	if ($_SERVER['REQUEST_METHOD']=='POST') {
		if (!empty($_POST['add_acl_W'])) {
			$ip = cerber_parse_ip($_POST['add_acl_W']);
			if (!$ip) cerber_admin_notice( __('Incorrect IP address or IP range','wp-cerber'));
			elseif (cerber_add_white($ip)) {
				if (is_array($ip)) $ip = $ip['range'];
				cerber_admin_message( sprintf(__('Address %s was added to White IP Access List','wp-cerber'),$ip));
			}
		}
		if (!empty($_POST['add_acl_B'])) {
			$ip = cerber_parse_ip($_POST['add_acl_B']);
			if (!$ip) cerber_admin_notice( __('Incorrect IP address or IP range','wp-cerber'));
			else {
				if ( cerber_is_myip( $ip ) || cerber_is_ip_in_range( $ip ) ) {
					if (is_array($ip)) $ip = $ip['range'];
					cerber_admin_notice( __( "You can't add your IP address", 'wp-cerber' ) . ' ' . $ip );
				}
				elseif (cerber_add_black($ip)) {
					if (is_array($ip)) $ip = $ip['range'];
					cerber_admin_message(sprintf(__('Address %s was added to Black IP Access List','wp-cerber'),$ip));
				}
			}
		}
	}
}
/*
	Get all entries from access lists
*/
function cerber_acl_all($fields='*'){
	global $wpdb;
	return $wpdb->get_results('SELECT '.$fields.' FROM '. CERBER_ACL_TABLE , ARRAY_N);
}

/*
	AJAX admin requests is landing here
*/
add_action('wp_ajax_cerber_ajax', 'cerber_admin_ajax');
function cerber_admin_ajax() {
	global $wpdb;
	if (!current_user_can('manage_options')) return;
	$response = array();
	if (isset($_REQUEST['acl_delete'])){
		check_ajax_referer('delete-ip','ajax_nonce');
		$ip = $_REQUEST['acl_delete'];
		if (!$ip = cerber_parse_ip($ip)) wp_die();
		if (cerber_acl_remove($ip)) {
			if (is_string($ip)) $deleted = $ip;
			else $deleted = $ip['range'];
			$response['deleted_ip'] = $deleted;
		}
		else $response['error'] = 'Unable to delete';
	}
	elseif (isset($_REQUEST['get_hostnames'])){
		$list = array_unique($_REQUEST['get_hostnames']);
		foreach ($list as $ip_id) {
			$ip = cerber_get_ip_id($ip_id);
			$ip_info = cerber_get_ip_info($ip);
			$response[$ip_id] = $ip_info['hostname'];
		}
	}
	elseif (isset($_REQUEST['dismiss_info'])){
		if (isset($_REQUEST['button_id']) && ($_REQUEST['button_id'] == 'lab_ok' || $_REQUEST['button_id'] == 'lab_no')){
			lab_user_opt_in($_REQUEST['button_id']);
		}
		else update_site_option('cerber_admin_info','');
	}
	echo json_encode($response);
	wp_die();
}
/*
 * Retrieve extended IP information
 * @since 2.2
 *
 */
function cerber_get_ip_info($ip, $cache_only = false){

	//$ip_id = str_replace('.','-',$ip);
	//$ip_id = str_replace(':','_',$ip_id); // IPv6

	$ip_id = cerber_get_id_ip($ip);

	$ip_info = @unserialize(get_transient($ip_id)); // lazy way
	if ($cache_only) return $ip_info;

	if (empty($ip_info['hostname'])) {
		$ip_info = array();
		$hostname = @gethostbyaddr( $ip );
		if ( $hostname ) {
			$ip_info['hostname'] = $hostname;
		} else {
			$ip_info['hostname'] = __( 'unknown', 'wp-cerber' );
		}
		set_transient( $ip_id, serialize( array( 'hostname' => $hostname ) ), 24 * 3600 );
	}
	return $ip_info;
}


/*
	Admin's actions with GET requests are handled here
*/
add_action('admin_init','cerber_admin_request');
function cerber_admin_request(){

	if ( $_SERVER['REQUEST_METHOD'] != 'GET' || !isset( $_GET['cerber_nonce'] ) ) return;
	if ( !current_user_can( 'manage_options' ) || !wp_verify_nonce( $_GET['cerber_nonce'], 'control' ) ) return;

	if (isset($_GET['testnotify'])) {
		//$to = implode(', ',cerber_get_email());
		$to = cerber_get_email();
		if (cerber_send_notify($_GET['testnotify'])) {
			cerber_admin_message( __( 'Message has been sent to ', 'wp-cerber' ) . ' ' . $to );
		}
		else {
			cerber_admin_notice( __('Unable to send notification email','wp-cerber').' '. $to);
		}
		wp_safe_redirect(remove_query_arg('testnotify')); // mandatory!
		exit; // mandatory!
	}
	elseif (isset($_GET['lockdelete'])) {
		$ip = $_GET['lockdelete'];
		if (cerber_block_delete($ip)) cerber_admin_message(sprintf(__('Lockout for %s was removed','wp-cerber'),$ip));
	}
	elseif (isset($_GET['export_activity'])) {
		cerber_export_activity();
	}
	elseif (isset($_GET['subscribe'])) {
		$mode = ( 'on' == $_GET['subscribe'] ) ? 'on' : 'off';
		cerber_subscribe($mode);
		wp_safe_redirect(remove_query_arg('subscribe')); // mandatory!
		exit; // mandatory!
	}
	elseif (isset($_GET['citadel']) && $_GET['citadel']=='deactivate') {
		cerber_disable_citadel();
	}
	elseif (isset($_GET['load_settings']) && $_GET['load_settings']=='default') {
		cerber_load_defaults();
		cerber_admin_message(__('Settings saved','wp-cerber'));
		wp_safe_redirect(remove_query_arg(array('load_settings','cerber_nonce'))); // mandatory!
		exit; // mandatory!
	}
	elseif (isset($_GET['force_repair_db'])) {
		cerber_create_db();
		cerber_upgrade_db(true);
		cerber_admin_message('Cerber\'s tables has been upgraded');
		wp_safe_redirect(remove_query_arg(array('force_repair_db','cerber_nonce'))); // mandatory!
		exit; // mandatory!
	}
	elseif (isset($_GET['force_check_nodes'])) {
		$best = lab_check_nodes(true);
		cerber_admin_message('Cerber Lab\'s nodes has been checked. The closest node: '.$best);
		wp_safe_redirect(remove_query_arg(array('force_check_nodes','cerber_nonce'))); // mandatory!
		exit; // mandatory!
	}
}

/**
 * Generate export CSV file using $_GET parameters (via cerber_activity_query())
 *
 * @since 4.16
 *
 */
function cerber_export_activity() {
	global $wpdb;

	//'per_page' = 0 means retrieve full data set, is used for export
	list( $query, $per_page, $falist, $ip, $filter_login, $user_id, $search ) = cerber_activity_query( array('per_page' => 0) );

	if ( $rows = $wpdb->get_results( $query ) ) {
		$total = $wpdb->get_var( "SELECT FOUND_ROWS()" );

		$fname = rawurlencode('wp-cerber-activity'); // encode non-ASCII symbols

		header($_SERVER["SERVER_PROTOCOL"].' 200 OK');
		header("Content-type: application/force-download");
		header("Content-Type: application/octet-stream");
		header("Content-Disposition: attachment; filename*=UTF-8''{$fname}.csv");

		echo '"Generated by:","WP Cerber security plugin"'."\r\n";
		echo '"Date:","'.cerber_date(time()).'"'."\r\n";
		echo '"Total rows:","'.$total.'"'."\r\n";
		echo '"Website:","'.get_option( 'blogname' ).'"'."\r\n";
		if ($ip) echo '"Filter by IP:","'.$ip.'"'."\r\n";
		elseif (!empty($_GET['filter_ip'])) echo '"Filter by IP:","'.$_GET['filter_ip'].'"'."\r\n"; // workaround
		if ($user_id) {
			$user = get_userdata($user_id);
			echo '"Filter by user:","'.$user->display_name.'"'."\r\n";
		}
		if ($search) echo '"Search results for:","'.$search.'"'."\r\n";

		echo "\r\n";

		$heading = array(__('IP address','wp-cerber'),__('Date','wp-cerber'),__('Activity','wp-cerber'),__('Local User','wp-cerber'),__('User login','wp-cerber'),__('User ID','wp-cerber'),__('Username used','wp-cerber'),'Unix timestamp');
		foreach ($heading as &$item) {
			$item = '"' . str_replace('"', '""', trim($item)) . '"';
		}
		echo implode(',', $heading) . "\r\n";

		$labels = cerber_get_labels('activity');

		foreach ($rows as $row) {
			$values = array();
			$values[] = $row->ip;
			$values[] = cerber_date($row->stamp);
			$values[] = $labels[$row->activity];
			$values[] = $row->display_name;
			$values[] = $row->ulogin;
			$values[] = $row->user_id;
			$values[] = $row->user_login;
			$values[] = $row->stamp;
			foreach ($values as &$value) {
				$value = '"' . str_replace('"', '""', trim($value)) . '"';
			}
			$line = implode(',', $values) . "\r\n";
			echo $line;
		}
		exit;
	}
	else wp_die('Nothing to export');
}
/*
 * Display activities in the WP Dashboard
 * @since 1.0
 *
 */
function cerber_show_activity($args = array(), $echo = true){
	global $wpdb, $wp_cerber, $wp_roles;

	$labels = cerber_get_labels('activity');
	$base_url = cerber_admin_link('activity');
	$right_links = '';
	$export_link = '';
	$table = '';
	$ret = '';

	list( $query, $per_page, $falist, $filter_ip, $filter_login, $user_id, $search ) = cerber_activity_query( $args );

	$ip_text = cerber_ip_extra_view( $filter_ip );
	$user_cache = array();

	if ( $rows = $wpdb->get_results( $query ) ) {

		$total      = $wpdb->get_var( "SELECT FOUND_ROWS()" );
		$assets_url = plugin_dir_url( CERBER_FILE ) . 'assets/';
		$list       = array();
		$roles = $wp_roles->roles;

		foreach ($rows as $row) {

			$activity = $labels[ $row->activity ];
			/*
			if ($row->activity == 50 ) {
				$activity .= ' <b>'.htmlspecialchars($row->user_login).'</b>';
            }*/

			if ( $row->user_id ) {
				if ( isset( $user_cache[ $row->user_id ] ) ) {
					$name = $user_cache[ $row->user_id ];
				} elseif ( $u = get_userdata( $row->user_id ) ) {

					if ( ! is_multisite() && $u->roles ) {
						$r = array();
						foreach ( $u->roles as $role ) {
							$r[] = $roles[ $role ]['name'];
						}
						$r = '<span style="color:#888;">' . implode( ', ', $r ) . '</span>';
					}

					$name = '<a href="' . $base_url . '&filter_user=' . $row->user_id . '"><b>' . $u->display_name . '</b></a><p>' . $r . '</p>';

					if ( 1 == 1 ) {
						$avatar = get_avatar( $row->user_id, 32 );
						$name   = '<table class="crb-avatar"><tr><td>' . $avatar . '</td><td>' . $name . '</td></tr></table>';
					}
				} else {
					$name = '';
				}

				$user_cache[ $row->user_id ] = $name;
			} else {
				$name = '';
			}

			$ip = '<a href="'.$base_url.'&filter_ip='.$row->ip.'">'.$row->ip.'</a>';
			$username = '<a href="'.$base_url.'&filter_login='.urlencode($row->user_login).'">'.$row->user_login.'</a>';

			$ip_info = cerber_get_ip_info($row->ip,true);
			if (isset($ip_info['hostname'])) $hostname = $ip_info['hostname'];
			else {
				$ip_id = cerber_get_id_ip($row->ip);
				$hostname = '<img data-ip-id="'.$ip_id .'" class="crb-no-hn" src="'.$assets_url.'ajax-loader-ip.gif" />'."\n";
			}

			$tip='';

			$acl = cerber_acl_check($row->ip);
			if ($acl == 'W') $tip = __('White IP Access List','wp-cerber');
			elseif ($acl == 'B') $tip = __('Black IP Access List','wp-cerber');

			if ( cerber_block_check( $row->ip ) ) {
				$block = ' color-blocked ';
				$tip .= ' ' . __( 'Locked out', 'wp-cerber' );
			}
			else $block='';

			if ( ! empty( $args['date'] ) && $args['date'] == 'ago' ) {
				$date = cerber_ago_time( $row->stamp );
			} else {
				$date = cerber_date( $row->stamp );
			}

			$list[] = '<td><div class="act-icon ip-acl' . $acl . ' ' . $block . '" title="' . $tip . '"></div>' . $ip . '</td><td>' . $hostname . '</td><td>' . $date . '</td><td><span class="actv' . $row->activity . '">' . $activity . '</span></td><td>' . $name . '</td><td>' . $username . '</td>';
		}

		$titles = '<tr><th><div class="act-icon"></div>' . __( 'IP', 'wp-cerber' ) . '</th><th>' . __( 'Hostname', 'wp-cerber' ) . '</th><th>' . __( 'Date', 'wp-cerber' ) . '</th><th>' . __( 'Activity', 'wp-cerber' ) . '</th><th>' . __( 'Local User', 'wp-cerber' ) . '</th><th>' . __( 'Username used', 'wp-cerber' ) . '</th></tr>';
		$table  = '<table id="crb-activity" class="widefat crb-table cerber-margin"><thead>' . $titles . '</thead><tfoot>' . $titles . '</tfoot><tbody><tr>' . implode( '</tr><tr>', $list ) . '</tr></tbody></table>';

		if (empty($args['no_navi'])) $table .= cerber_page_navi($total, $per_page);

		//$legend  = '<p>'.sprintf(__('Showing last %d records from %d','wp-cerber'),count($rows),$total);

		$info = $ip_text;

		if (empty($args['no_export'])) $export_link = '<a class="button button-secondary cerber-button" href="'.wp_nonce_url(add_query_arg('export_activity',1),'control','cerber_nonce').'"><span class="dashicons dashicons-download" style="vertical-align: middle;"></span> '.__('Export','wp-cerber').'</a>';
	}
	else {
		$info = '';
		$table = '<p class="cerber-margin">'.__('No activity has been logged.','wp-cerber').'</p>';
	}

	if (empty($args['no_navi'])) {

		$labels = array( 0 => __( 'All activities', 'wp-cerber' ) ) + $labels;

		if (!empty($_GET['filter_activity'])) $selected = absint($_GET['filter_activity']);
		else $selected = 0;

		$filters = '<form style="float: left; width: auto;" action="">'
		           . cerber_select('filter_activity', $labels, $selected)
		           .'<input type="text" value="'.$search.'" name="search_activity" placeholder="'.__('Search for IP or username','wp-cerber').'"><input type="submit" value="'.__('Filter','wp-cerber').'" class="button">'
		           .'
		           <!-- Preserve values -->
		           <input type="hidden" name="filter_ip" value="'.htmlspecialchars($filter_ip).'" >
		           <input type="hidden" name="filter_user" value="'.$user_id.'" >
		           <input type="hidden" name="filter_login" value="'.$filter_login.'" >
		           
		           <input type="hidden" name="page" value="cerber-security" >
		           <input type="hidden" name="tab" value="activity">
		           </form>';

		$right_links = '<div style="float: right; width: auto; line-height: 26px;">'.cerber_subscribe_link().$export_link.'</div>';

		$top_bar = '<div id = "activity-filter">'.$filters.$right_links.'</div><br style="clear: both;">';

		$ret = '<div class="cerber-margin">' . $top_bar . $info . '</div>'.$ret;
	}

	$ret .= $table;

	if ($echo) echo $ret;
	else return $ret;

}

/**
 * Parse arguments and create SQL query for retrieving rows from activity log
 *
 * @param array $args Optional arguments to use them instead of using $_GET
 *
 * @return array
 * @since 4.16
 */
function cerber_activity_query($args = array()){
	global $wpdb;

	$ret = array_fill( 0, 7, '' );
	$where = array();
	$falist = array();

	$filter = null;
	if (!empty($args['filter_activity'])) $filter = $args['filter_activity'];
	elseif (isset($_GET['filter_activity'])) $filter = $_GET['filter_activity'];

	if ($filter) { // Multiple activities can be requested this way: &filter_activity[]=11&filter_activity[]=7
		if (is_array($filter)) {
			$falist = array_filter(array_map('absint',$filter));
			$filter = implode(',',$falist);
		}
		else {
			$filter = absint($filter);
			$falist = array($filter); // for further using in links
		}
		$where[] = 'log.activity IN ('.$filter.')';
	}
	$ret[2] = $falist;

	if ( ! empty( $_GET['filter_ip'] ) ) {
		$filter = trim( $_GET['filter_ip'] );
		$range = cerber_any2range( $filter );
		if ( is_array( $range ) ) {
			$where[] = $wpdb->prepare( '(log.ip_long >= %d AND log.ip_long <= %d)', $range['begin'], $range['end'] );
		} elseif ( cerber_is_ip_or_net( $filter ) ) {
			$where[] = $wpdb->prepare( 'log.ip = %s', $filter );
			//$ip_extra = $filter;
		} else {
			$where[] = "ip = 'produce-no-result'";
		}
		$ret[3] = $_GET['filter_ip'];
	}

	if (!empty($_GET['filter_login'])) {
		$where[] = $wpdb->prepare('log.user_login = %s',$_GET['filter_login']);
		$ret[4] = htmlspecialchars($_GET['filter_login']);
	}
	if (!empty($_GET['filter_user'])) {
		$user_id = absint($_GET['filter_user']);
		$ret[5] = $user_id;
		$where[] = 'log.user_id = '.$user_id;
	}
	if (!empty($_GET['search_activity'])) {
		$search = stripslashes_deep($_GET['search_activity']);
		$ret[6] = htmlspecialchars($search);
		$search = '%'.$search.'%';
		$where[] = $wpdb->prepare('(log.ip LIKE %s OR log.user_login LIKE %s)', $search, $search);
	}

	if (!empty($where)) $where = 'WHERE '.implode(' AND ',$where);
	else $where = '';

	// Limits, if specified
	if (isset($args['per_page'])) $per_page = $args['per_page'];
	else $per_page = cerber_get_per_page();
	$per_page = absint($per_page);
	$ret[1] = $per_page;

	if ( $per_page ) {
		$limit = ' LIMIT ' . ( cerber_get_pn() - 1 ) * $per_page . ',' . $per_page;
		$ret[0] = 'SELECT SQL_CALC_FOUND_ROWS * FROM ' . CERBER_LOG_TABLE . " log {$where} ORDER BY stamp DESC {$limit}";
	}
	else {
		$ret[0] = 'SELECT SQL_CALC_FOUND_ROWS log.*,u.display_name,u.user_login ulogin FROM ' . CERBER_LOG_TABLE . ' log LEFT JOIN '.$wpdb->users . " u ON (log.user_id = u.ID) {$where} ORDER BY stamp DESC";
	}

	//$ret[0] = 'SELECT SQL_CALC_FOUND_ROWS log.*,u.display_name,u.user_login ulogin FROM ' . CERBER_LOG_TABLE . ' log LEFT JOIN ' . $wpdb->users . " u ON (log.user_id = u.ID) {$where} ORDER BY stamp DESC {$limit}";

	return $ret;
/*
	return array(
		//'SELECT SQL_CALC_FOUND_ROWS * FROM ' . CERBER_LOG_TABLE . " {$where} ORDER BY stamp DESC {$limit}",
		'SELECT SQL_CALC_FOUND_ROWS log.*,u.display_name,u.user_login ulogin FROM ' . CERBER_LOG_TABLE . ' log LEFT JOIN '.$wpdb->users . " u ON (log.user_id = u.ID) {$where} ORDER BY stamp DESC {$limit}",
		$per_page,
		$falist,
		$ip_extra,
		$user_id,
	);
*/
}
/*
 * Detailed information about IP address
 * @since 2.7
 *
 */
function cerber_ip_extra_view($ip){
	global $wp_cerber;
	//if (!cerber_is_ip_or_net($ip)) return '';
	if ( !@inet_pton( $ip ) ) {
		return '';
	}
	$tip = ' ';
	$acl = cerber_acl_check( $ip );
	if ( $acl == 'W' ) {
		$tip .= '<span class="color-green ip-info-label">'.__( 'White IP Access List', 'wp-cerber' ).'</span> ';
	} elseif ( $acl == 'B' ) {
		$tip .= '<span class="color-black ip-info-label">'.__( 'Black IP Access List', 'wp-cerber' ).'</span> ';
	}
	if ( cerber_block_check( $ip ) ) {
		$tip .= '<span class="color-blocked ip-info-label">'.__( 'Locked out', 'wp-cerber' ).'</span> ';
	}

	// Filter activity by ...

	/*$labels = cerber_get_labels('activity');
	foreach ($labels as $tag => $label) {
		//if (in_array($tag,$falist)) $links[] = '<b>'.$label.'</b>';
		$links[] = '<a href="'.$base_url.'&filter_activity='.$tag.'">'.$label.'</a>';
	}
	$filters = implode(' | ',$links);*/

	$whois = '';
	$country = '';
	$abuse = '';
	$network = '';
	$network_info = '';

	if (cerber_get_options('ip_extra')) {
		$ip_info = cerber_ip_whois_info($ip);
		if (isset($ip_info['whois'])) $whois = '<div id="whois">' . $ip_info['whois'] . '</div>';
		if (isset($ip_info['error'])) $whois = '<div id="whois">' . $ip_info['error'] . '</div>';
		if (isset($ip_info['country'])) $country = $ip_info['country'];
		if (!empty($ip_info['data']['abuse-mailbox'])) $abuse = '<p>'.__('Abuse email:','wp-cerber').' <a href="mailto:'.$ip_info['data']['abuse-mailbox'].'">'.$ip_info['data']['abuse-mailbox'].'</a></p>';
		if (!empty($ip_info['data']['network'])) {
			$network = $ip_info['data']['network'];
			$range = cerber_any2range($network);
			$network_info = '<p>'.__('Network:','wp-cerber').' '.$network.' &nbsp; <a href="'.cerber_activity_link(array('filter_ip'=>$range['range'])).'">'.__('Check for activity','wp-cerber').'</a></p>';
		}
	}

	$form = '';
	//if (!cerber_is_myip($ip) && !cerber_acl_check($ip)) $form = '<form action="" method="post"><input type="hidden" name="add_acl_B" value="'.$ip.'"><input type="submit" class="button button-primary cerber-button" value="'.__('Add IP to the Black List','wp-cerber').'" >'.wp_nonce_field('cerber_dashboard','cerber_nonce').'</form>';

	if (!cerber_is_myip($ip) && !cerber_acl_check($ip)) {

		if ( $network ) {
			$net_button = '<button type="submit" value="' . $network . '" name="add_acl_B" class="button button-primary cerber-button">';
		} else {
			$net_button = '<button disabled="disabled" class="button button-secondary cerber-button">';
		}
		$net_button .= '<span class="dashicons-before dashicons-networking"></span> ' . __( 'Add network to the Black List', 'wp-cerber' ) . '</button> ';

		$form = '<form id="add-acl-black" action="" method="post">
				<!-- <input type="hidden" name="add_acl_B" value=""> -->
				<button type="submit" value="'.$ip.'" name="add_acl_B" class="button button-primary cerber-button"><span class="dashicons-before dashicons-desktop"></span> '.__('Add IP to the Black List','wp-cerber').'</button> '.
		        $net_button.
		        wp_nonce_field('cerber_dashboard','cerber_nonce').
		        '</form>';
	}

	$ret = '<div id="ip-extra">
			<table>
			<tr><td><p><span id = "ip-address">' . $ip . '</span><span id = "ip-country">' . $country .'</span>'. $tip .'</p>' . $network_info . $abuse . '</td><td>' . $form . '</td></tr>
			</table>
			</div>';

	return $ret.$whois;
}

/*
	Add admin menu, init admin stuff
*/
if (!is_multisite()) add_action('admin_menu', 'cerber_admin_menu');
else add_action('network_admin_menu', 'cerber_admin_menu'); // only network wide menu allowed in multisite mode
function cerber_admin_menu() {

	if (cerber_is_admin_page()) cerber_self_diagnostic();

	$hook = add_menu_page( __( 'WP Cerber Security', 'wp-cerber' ), __( 'WP Cerber', 'wp-cerber' ), 'manage_options', 'cerber-security', 'cerber_settings_page', 'dashicons-shield', '100' );
	add_action( 'load-' . $hook, "cerber_screen_options" );
	add_submenu_page( 'cerber-security', __( 'Cerber Dashboard', 'wp-cerber' ), __( 'Dashboard' ), 'manage_options', 'cerber-security', 'cerber_settings_page' );

	add_submenu_page( 'cerber-security', __( 'Cerber reCAPTCHA settings', 'wp-cerber' ), __( 'reCAPTCHA', 'wp-cerber' ), 'manage_options', 'cerber-recaptcha', 'cerber_recaptcha_page' );
	add_submenu_page( 'cerber-security', __( 'Cerber tools', 'wp-cerber' ), __( 'Tools', 'wp-cerber' ), 'manage_options', 'cerber-tools', 'cerber_tools_page' );
	
}

add_action( 'admin_bar_menu', 'cerber_admin_bar' );
function cerber_admin_bar( $wp_admin_bar ) {
	if (!is_multisite()) return;
	$args = array(
		'parent' => 'network-admin',
		'id'    => 'cerber_admin',
		'title' => __('WP Cerber','wp-cerber'),
		'href'  => cerber_admin_link(),
	);
	$wp_admin_bar->add_node( $args );
}

/*
	Check if currently displayed page is a Cerber admin dashboard page with optional checking a set of GET params
*/
function cerber_is_admin_page($force = true, $params = array()){

	if (!is_admin()) return false;

	$ret = false;

	if (isset($_GET['page']) && false !== strpos($_GET['page'],'cerber-')) {
		$ret = true;
		if ($params) {
			foreach ( $params as $param => $value) {
				if (!isset($_GET[$param]) || $_GET[$param] != $value){
					$ret = false;
					break;
				}
			}
		}
	}
	if (!$force || $ret) return $ret;

	if (!$screen = get_current_screen()) return false;
	if ($screen->base == 'plugins') return true;
	/*
	if ($screen->parent_base == 'options-general') return true;
	if ($screen->parent_base == 'settings') return true;
	*/
	return false;
}

/*
	Add custom columns to the Users screen
*/
add_filter('manage_users_columns' , 'cerber_u_columns');
function cerber_u_columns($columns) {
	return array_merge( $columns,
          	array('cbcc' => __('Comments','wp-cerber'),
          	'cbla' => __('Last login','wp-cerber') ,
          	'cbfl' => __('Failed attempts in last 24 hours','wp-cerber'),
          	'cbdr' => __('Date of registration','wp-cerber')) );
}
add_filter( 'manage_users_sortable_columns','cerber_u_sortable');
function cerber_u_sortable($sortable_columns) {
	$sortable_columns['cbdr']='user_registered';
	return $sortable_columns;
}
/*
	Display custom columns on the Users screen
*/
add_filter( 'manage_users_custom_column' , 'cerber_show_u_columns', 10, 3 );
function cerber_show_u_columns($value, $column, $user_id) {
	global $wpdb,$current_screen,$user_login;
	$ret = $value;
	switch ($column) {
		case 'cbcc' : // to get this work we need add filter 'preprocess_comment'
			if ($com = get_comments(array('author__in' => $user_id)))	$ret = count($com);
			else $ret = 0;
		break;
		case 'cbla' :
			$ret = $wpdb->get_var('SELECT MAX(stamp) FROM '.CERBER_LOG_TABLE.' WHERE user_id = '.$user_id);
			if ($ret) {
				$act_link = cerber_activity_link();
				$ret = '<a href="'.$act_link.'&filter_user='.$user_id.'">'.cerber_date($ret).'</a>';
			}
			else $ret=__('Never','wp-cerber');
		break;
		case 'cbfl' :
			$act_link = cerber_admin_link('activity');
			$u=get_userdata($user_id);
			$failed = $wpdb->get_var('SELECT count(user_id) FROM '.CERBER_LOG_TABLE.' WHERE user_login = \''.$u->user_login.'\' AND activity = 7 AND stamp > ' . (time() - 24 * 3600));
			$ret = '<a href="'.$act_link.'&filter_login='.$u->user_login.'&filter_activity=7">'.$failed.'</a>';
		break;
		case 'cbdr' :
			$time = strtotime($wpdb->get_var("SELECT user_registered FROM  $wpdb->users WHERE id = ".$user_id));
			$ret = cerber_date($time);
		break;
	}
	return $ret;
}

/*
 	Registering admin widgets
*/
if (!is_multisite()) add_action( 'wp_dashboard_setup', 'cerber_widgets' );
else add_action( 'wp_network_dashboard_setup', 'cerber_widgets' );
function cerber_widgets() {
	if (!current_user_can('manage_options')) return;
	if (current_user_can( 'manage_options')) {
		wp_add_dashboard_widget( 'cerber_quick', __('Cerber Quick View','wp-cerber'), 'cerber_quick_w');
	}
}
/*
	Cerber Quick View widget
*/
function cerber_quick_w(){
	global $wpdb,$wp_cerber;

	$dash = cerber_admin_link();
	$act = cerber_admin_link('activity');
	$acl = cerber_admin_link('acl');
	$loc = cerber_admin_link('lockouts');

	$failed = $wpdb->get_var('SELECT count(ip) FROM '. CERBER_LOG_TABLE .' WHERE activity IN (7) AND stamp > '.(time() - 24 * 3600));
	$failed_prev = $wpdb->get_var('SELECT count(ip) FROM '. CERBER_LOG_TABLE .' WHERE activity IN (7) AND stamp > '.(time() - 48 * 3600).' AND stamp < '.(time() - 24 * 3600));

	$failed_ch = cerber_percent($failed_prev,$failed);

	$locked = $wpdb->get_var('SELECT count(ip) FROM '. CERBER_LOG_TABLE .' WHERE activity IN (10,11) AND stamp > '.(time() - 24 * 3600));
	$locked_prev = $wpdb->get_var('SELECT count(ip) FROM '. CERBER_LOG_TABLE .' WHERE activity IN (10,11) AND stamp > '.(time() - 48 * 3600).' AND stamp < '.(time() - 24 * 3600));

	$locked_ch = cerber_percent($locked_prev,$locked);

	//$lockouts = $wpdb->get_var('SELECT count(ip) FROM '. CERBER_BLOCKS_TABLE);

    $lockouts = cerber_blocked_num(); 
	if ($last = $wpdb->get_var('SELECT MAX(stamp) FROM '.CERBER_LOG_TABLE.' WHERE  activity IN (10,11)')) {
		//$last = cerber_date($last);
		$last = cerber_ago_time( $last );
	}
	else $last = __('Never','wp-cerber');
	$w_count = $wpdb->get_var('SELECT count(ip) FROM '. CERBER_ACL_TABLE .' WHERE tag ="W"' );
	$b_count = $wpdb->get_var('SELECT count(ip) FROM '. CERBER_ACL_TABLE .' WHERE tag ="B"' );

	if (cerber_is_citadel()) $citadel = '<span style="color:#FF0000;">'.__('active','wp-cerber').'</span> (<a href="'.wp_nonce_url(add_query_arg(array('citadel' => 'deactivate')),'control','cerber_nonce').'">'.__('deactivate','wp-cerber').'</a>)';
	else {
		if ($wp_cerber->getSettings('ciperiod')) $citadel = __('not active','wp-cerber');
		else $citadel = __('disabled','wp-cerber');
	}

	echo '<div class="cerber-widget">';

	echo '<table style="width:100%;"><tr><td style="width:50%; vertical-align:top;"><table><tr><td class="bigdig">'.$failed.'</td><td class="per">'.$failed_ch.'</td></tr></table><p>'.__('failed attempts','wp-cerber').' '.__('in 24 hours','wp-cerber').'<br/>(<a href="'.$act.'&filter_activity=7">'.__('view all','wp-cerber').'</a>)</p></td>';
	echo '<td style="width:50%; vertical-align:top;"><table><tr><td class="bigdig">'.$locked.'</td><td class="per">'.$locked_ch.'</td></tr></table><p>'.__('lockouts','wp-cerber').' '.__('in 24 hours','wp-cerber').'<br/>(<a href="'.$act.'&filter_activity[]=10&filter_activity[]=11">'.__('view all','wp-cerber').'</a>)</p></td></tr></table>';

	echo '<table id="quick-info"><tr><td>'.__('Lockouts at the moment','wp-cerber').'</td><td>'.$lockouts.'</td></tr>';
	echo '<tr><td>'.__('Last lockout','wp-cerber').'</td><td>'.$last.'</td></tr>';
	echo '<tr><td style="padding-top:15px;">'.__('White IP Access List','wp-cerber').'</td><td style="padding-top:15px;"><b>'.$w_count.' '._n('entry','entries',$w_count,'wp-cerber').'</b></td></tr>';
	echo '<tr><td>'.__('Black IP Access List','wp-cerber').'</td><td><b>'.$b_count.' '._n('entry','entries',$b_count,'wp-cerber').'</b></td></tr>';
	echo '<tr><td style="padding-top:15px;">'.__('Citadel mode','wp-cerber').'</td><td style="padding-top:15px;"><b>'.$citadel.'</b></td></tr>';
	$dev = $wp_cerber->getSettings('pbdevice');
	if (!$dev || $dev == 'N') echo '<tr><td style="padding-top:15px;">'.__('Push notifications','wp-cerber').'</td><td style="padding-top:15px;"><b>not configured</b></td></tr>';
	echo '</table></div>';

	echo '<div class="wilinks">
	<a href="'.$dash.'"><span class="dashicons dashicons-dashboard"></span> ' . __('Dashboard','wp-cerber').'</a> |
	<a href="'.$act.'"><span class="dashicons dashicons-welcome-view-site"></span> ' . __('Activity','wp-cerber').'</a> |
	<a href="'.$loc.'"><span class="dashicons dashicons-shield"></span> ' . __('Lockouts','wp-cerber').'</a> |
	<a href="'.$acl.'"><span class="dashicons dashicons-admin-network"></span> ' . __('Access Lists','wp-cerber').'</a>
	</div>';
	if ($msg = cerber_update_check())	echo '<div class="up-cerber">'.$msg.'</div>';
}

/*
	Show Help tab screen
*/
function cerber_show_help() {

	$assets_url = plugin_dir_url( CERBER_FILE ) . 'assets';

	?>
	<div id="crb-help">

		<h3>Do you have a question or need help?</h3>

		<p>Support is provided on the WordPress forums for free, though please note that it is free support hence it is
			not always possible to answer all questions on a timely manner, although I do try.</p>

		<p><span class="dashicons-before dashicons-controls-play" style="vertical-align: middle;"></span> <a
				href="http://wordpress.org/support/plugin/wp-cerber">Get answer on the support forum</a>.</p>


		<h3>Mobile and browser notifications with Pushbullet</h3>

		<p>
			WP Cerber allows you to easily enable desktop and mobile notifications and get notifications instantly and for free. In a desktop browser, you will get popup messages even if you logged out of your WordPress.
			Before you start receiving notifications you need to install a free Pushbullet mobile application on your mobile device or free browser extension available for Chrome, Firefox and Opera.
		</p>
		<p><span class="dashicons-before dashicons-controls-play" style="vertical-align: middle;"></span>
			<a href="http://wpcerber.com/wordpress-mobile-and-browser-notifications-pushbullet/">A three steps instruction how to set up push notifications</a>
		</p>
		<p><span class="dashicons-before dashicons-controls-play" style="vertical-align: middle;"></span>
			<a href="http://wpcerber.com/wordpress-notifications-made-easy/">How to get alerts for specific activity on your website</a>
		</p>

		<h3>What is Drill down IP?</h3>

		<p>
			To get extra information like country, company, network info, abuse contact etc. for a specific IP address,
			the plugin makes requests to a limited set of external WHOIS servers which are maintained by appropriate
			Registry. All Registry are accredited by ICANN, so there are no reasons for security concerns. Retrieved
			information isn't storing in the database, but it is caching for 24 hours to avoid excessive requests and
			get faster response.
		</p>
		<p><span class="dashicons-before dashicons-controls-play" style="vertical-align: middle;"></span> <a
				href="http://wpcerber.com?p=194">Read more in the Security Blog</a></p>

		<h3>What is Cerber Lab?</h3>

		<p>
			Cerber Laboratory is a forensic team behind the WP Cerber security plugin. The team studies and analyzes
			patterns of hacker and botnet attacks, malware, vulnerabilities in major plugins and how they are
			exploitable on WordPress powered websites.
		</p>
			<p><span class="dashicons-before dashicons-controls-play" style="vertical-align: middle;"></span>
			<a href="http://wpcerber.com/cerber-laboratory/">Know more</a>
			</p>

		<h3>Do you have an idea for a cool new feature that you would love to see in WP Cerber?</h3>

		<p>
			Feel free to submit your ideas here: <a href="http://wpcerber.com/new-feature-request/">New Feature
				Request</a>.
		</p>

		<h3>Are you ready to translate this plugin into your language?</h3>

		<p>I would appreciate that! Please, <a href="http://wpcerber.com/support/">notify me</a></p>

		<h3 style="margin: 40px 0 40px 0;">Check out other plugins from the trusted author</h3>

		<div>

			<a href="https://wordpress.org/plugins/plugin-inspector/">

				<img src="<?php echo $assets_url . '/inspector.png' ?>"
				     style="float: left; width: 128px; margin-right: 20px;"/>
			</a>
			<h3>Plugin for inspecting code of plugins on your site: <a
					href="https://wordpress.org/plugins/plugin-inspector/">Plugin Inspector</a></h3>
			<p style="font-size: 110%">The Plugin Inspector plugin is an easy way to check plugins installed on your
				WordPress and make sure
				that plugins does not use deprecated WordPress functions and some unsafe functions like eval,
				base64_decode, system, exec etc. Some of those functions may be used to load malicious code (malware)
				from the external source directly to the site or WordPress database.
			</p>
			<p style="font-size: 110%">Plugin Inspector allows you to view all the deprecated functions complete with
				path, line number,
				deprecation function name, and the new recommended function to use. The checks are run through a simple
				admin page and all results are displayed at once. This is very handy for plugin developers or anybody
				who want to know more about installed plugins.
			</p>
		</div>

		<div style="margin: 40px 0 40px 0;">
			<a href="https://wordpress.org/plugins/goo-translate-widget/">
				<img src="<?php echo $assets_url . '/goo-translate.png' ?>"
				     style="float: left; width: 128px; margin-right: 20px;"/>
			</a>

			<h3>Plugin to quick translate site: <a href="https://wordpress.org/plugins/goo-translate-widget/">Google
					Translate Widget</a></h3>
			<p style="font-size: 110%">Google Translate Widget expands your global reach quickly and easily. Google Translate is a free
				multilingual machine translation service provided by Google to translate websites. And now you can allow
				visitors around of the world to get your site in their native language. Just put widget on the sidebar
				with one click.</p>

		</div>

	</div>
	<?php
}

/**
 *
 * Dashboard v.1
 *
 * @since 4.0
 *
 */
function cerber_show_dashboard() {
	global $wpdb;

	$num = 10;

	echo '<div style="padding-right: 30px;">';
	/*
	echo '<div class="cerber-margin">

<table id = "crb-dashboard"><tr>
<td>84</td>
<td><span>Incidents detected (in the last 24 hours)</span></td>
<td>38</td>
<td>Malicious IP addresses detected</td>
<td>12</td>
<td>Locked out IP now</td>
<td>0</td>
<td>Locked out IP now</td>

</tr></table>

    </div>'; */

	//$total = $wpdb->get_var( 'SELECT count(ip) FROM ' . CERBER_LOG_TABLE );
	//if ($total > $num) $l1 = 'Last ' . $num . ' suspect events are displayed';

	$view = '<a href="' . cerber_admin_link( 'activity' ) . '">' . __( 'View all', 'wp-cerber' ) . '</a>';
	echo '<table class="cerber-margin"><tr><td><h2 style="margin-bottom:0.5em;">' . __( 'Activity', 'wp-cerber' ) . '</h2></td><td> | ' . $view . '</td></tr></table>';

	cerber_show_activity( array(
		'filter_activity' => array( 1, 2, 5, 10, 12, 11, 41, 42, 50, 51, 52 ),
		'per_page'        => $num,
		'no_navi'         => true,
		'no_export'         => true,
		'date'            =>'ago'
	) );


	//$total = $wpdb->get_var( 'SELECT count(ip) FROM ' . CERBER_BLOCKS_TABLE );
	//if ($total > $num) $l2 = '<p>Last ' . $num . ' lockouts of '.$total.' are displayed</p>';

	$view = '<a href="' . cerber_admin_link( 'lockouts' ) . '">' . __( 'View all', 'wp-cerber' ) . '</a>';
	echo '<table class="cerber-margin" style="margin-top:2em;"><tr><td><h2 style="margin-bottom:0.5em;">' . __( 'Recently locked out IP addresses', 'wp-cerber' ) . '</h3></td><td> | ' . $view . '</td></tr></table>';

	cerber_show_lockouts( array(
		'per_page' => $num,
		'no_navi'  => true
	) );

	echo '</div>';
}


/*
	Admin aside bar
*/
function cerber_show_aside($page){

	if (in_array($page,array('activity','lockouts'))) return;

	$aside = array();

	if (in_array($page,array('main'))) {
		$aside[]='<div class="crb-box">
			<h3>'.__('Confused about some settings?','wp-cerber').'</h3>'
			.__('You can easily load default recommended settings using button below','wp-cerber').'
			<p style="text-align:center;">
				<input type="button" class="button button-primary" value="'.__('Load default settings','wp-cerber').'" onclick="button_default_settings()" />
				<script type="text/javascript">function button_default_settings(){
					if (confirm("'.__('Are you sure?','wp-cerber').'")) {
						click_url = "'.wp_nonce_url(add_query_arg(array('load_settings'=>'default')),'control','cerber_nonce').'";
						window.location = click_url.replace(/&amp;/g,"&");
					}
				}</script>
			</p>
			<p><i>* '.__("doesn't affect Custom login URL and Access Lists",'wp-cerber').'</i></p>
		</div>';
	}

	$aside[] = '<div class="crb-box" id = "crb-subscribe">
			<div class="crb-box-inner">
			<h3>Be in touch with developer</h3>
			<p>Receive updates and helpful ideas to protect your website, blog, or business online.</p>
			<p>
			<span class="dashicons-before dashicons-email-alt"></span> &nbsp; <a href="http://wpcerber.com/subscribe-newsletter/" target="_blank">Subscribe to Cerber\'s newsletter</a></br>
			<span class="dashicons-before dashicons-twitter"></span> &nbsp; <a href="https://twitter.com/wpcerber">Follow Cerber on Twitter</a></br>
			<span class="dashicons-before dashicons-facebook"></span> &nbsp; <a href="https://www.facebook.com/wpcerber/">Follow Cerber on Facebook</a>
			</p>
			</div>
			</div>
	';

	$aside[] = '<div class="crb-box" id = "crb-donate">
			<div class="crb-box-inner">
			<h3>'.__('Donate','wp-cerber').'</h3>
			<p>Hi! It\'s Gregory. I am an author of this plugin. Please consider making a donation to support the continued development and free support of this plugin because I spend my free time for that. Any help is greatly appreciated. Thanks!</p>
			
			<div style="text-align:center;">
			<form action="https://www.paypal.com/cgi-bin/webscr" method="post" target="_top">
			<input type="hidden" name="cmd" value="_s-xclick">
			<input type="hidden" name="hosted_button_id" value="SR8RJXFU35EW8">
			<input type="image" src="https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG_global.gif" border="0" name="submit" alt="PayPal – The safer, easier way to pay online.">
			<img alt="" border="0" src="https://www.paypalobjects.com/en_US/i/scr/pixel.gif" width="1" height="1">
			</form>
			</div>
			
			</div>
			</div>';

	$aside[] = '<div class="crb-box" id = "crb-jetflow">
			<div class="crb-box-inner">
			<h3>Automate WordPress</h3>
			<p>Create automation scenarios without coding knowledge with the jetFlow.io plugin. Customize your WordPress in no time. No programming knowledge needed anymore.</p>
			<p><span class="dashicons-before dashicons-layout"></span> &nbsp; <a href="http://jetflow.io/" target="_blank">Download the jetFlow.io plugin</a></p>
			</div>
			</div>
	';

	$aside[] = '<div class="crb-box" id = "crb-blog">
			<div class="crb-box-inner">
			<!-- <h3><span class="dashicons-before dashicons-lightbulb"></span> Read Cerber\'s blog</h3> --> 
			<h3>WordPress security blog</h3>
			<p><a href="http://wpcerber.com/wordpress-mobile-and-browser-notifications-pushbullet/" target="_blank">Instant mobile and browser notifications</a>
			<p><a href="http://wpcerber.com/wordpress-notifications-made-easy/" target="_blank">WordPress notifications made easy</a>
			<p><a href="http://wpcerber.com/why-its-important-to-restrict-access-to-rest-api/" target="_blank">Why it’s important to restrict access to the WP REST API</a>
			<p><a href="http://wpcerber.com/why-we-need-to-use-custom-login-url/" target="_blank">Why you need to use Custom login URL</a>
			<p><a href="http://wpcerber.com/using-ip-access-lists-to-protect-wordpress/" target="_blank">How IP Access Lists works</a>
			<p><a href="http://wpcerber.com/hardening-wordpress-with-wp-cerber/" target="_blank">Hardening WordPress with WP Cerber</a>
			<p><a href="http://wpcerber.com/hardening-wordpress-with-wp-cerber-and-nginx/" target="_blank">Hardening WordPress with WP Cerber and NGINX</a>
		
		</div>
		</div>';

	echo '<div id="crb-aside">'.implode(' ',$aside).'</div>';
}

/*
	Displaying notices in the dashboard
*/
add_action( 'admin_notices', 'cerber_show_admin_notice', 999 );
add_action( 'network_admin_notices', 'cerber_show_admin_notice', 999 );
function cerber_show_admin_notice(){
	global $cerber_shown;
	$cerber_shown = false;

	if (cerber_is_citadel() && current_user_can('manage_options')) {
		echo '<div class="update-nag crb-alarm"><p>'.
		__('Attention! Citadel mode is now active. Nobody is able to log in.','wp-cerber').
		' &nbsp; <a href="'.wp_nonce_url(add_query_arg(array('citadel' => 'deactivate')),'control','cerber_nonce').'">'.__('Deactivate','wp-cerber').'</a>'.
		' | <a href="' . cerber_admin_link('activity') . '">' . __('View Activity','wp-cerber') . '</a>' .
		     '</p></div>';
	}

	if (!cerber_is_admin_page()) return;

	cerber_update_check(); // TODO: move to cron

	//if ($notices = get_site_option('cerber_admin_notice'))
	//	echo '<div class="update-nag crb-note"><p>'.$notices.'</p></div>'; // class="updated" - green, class="update-nag" - yellow and above the page title,
	//if ($notices = get_site_option('cerber_admin_message'))
	//	echo '<div class="updated" style="overflow: auto;"><p>'.$notices.'</p></div>'; // class="updated" - green, class="update-nag" - yellow and above the page title,

	$all = array();
	if ( ! empty( $_GET['settings-updated'] ) ) {
		$all[] = array( __( 'Settings saved', 'wp-cerber' ), 'updated' );
	}

	if ( $notice = get_site_option( 'cerber_admin_notice' ) ) {
		$all[] = array( $notice, 'error' ); // red
	}
	if ( $notice = get_site_option( 'cerber_admin_message' ) ) {
		$all[] = array( $notice, 'updated' ); // green
	}


	// yellow #ffb900;
	if ($all) {
		$cerber_shown = true;
		foreach ( $all as $notice ) {
			echo '<div id="setting-error-settings_updated" class="' . $notice[1] . ' settings-error notice is-dismissible"> 
		<p>' . $notice[0] . '</p><button type="button" class="notice-dismiss"><span class="screen-reader-text">Dismiss this notice.</span></button></div>';
		}
	}

	update_site_option('cerber_admin_notice', null);
	update_site_option('cerber_admin_message', null);

	if ($notice = get_site_option('cerber_admin_info')) { // need to be dismissed manually
		$cerber_shown = true;
		echo '<div class="updated cerber-msg" style="overflow: auto;"><p>'.$notice.'</p></div>';
	}
}

/*
	Checks for a new version of WP Cerber and creates messages if needed
*/
function cerber_update_check() {
	$ret = false;
	if ( $updates = get_site_transient( 'update_plugins' ) ) {
		$key = cerber_plug_in();
		if ( isset( $updates->checked[ $key ] ) && isset( $updates->response[ $key ] ) ) {
			$old = $updates->checked[ $key ];
			$new = $updates->response[ $key ]->new_version;
			if ( 1 === version_compare( $new, $old ) ) {
				// current version is lower than latest
				$ret = __( 'New version is available', 'wp-cerber' ) . ' <span class="dashicons dashicons-arrow-right"></span>';
				if ( is_multisite() ) {
					$href = network_admin_url( 'plugins.php?plugin_status=upgrade' );
				} else {
					$href = admin_url( 'plugins.php?plugin_status=upgrade' );
				}
				$msg = '<b>' . $ret . '</b> <a href="' . $href . '">' . sprintf( __( 'Update to version %s of WP Cerber', 'wp-cerber' ), $new ) . '</a>';
				cerber_admin_message( $msg );
				$ret = '<a href="' . $href . '">' . $ret . '</a>';

				// TODO: implement as a cron task, daily
				//update_site_option('cerber_new_version',array($new, time()));
				//cerber_send_notify('new_version');
			}
		}
	}
	return $ret;
}

/**
 *
 * Generates a link for subscribing on a currently displaying Activity page
 *
 * @return string Link for using in the Dashboard, HTML
 */
function cerber_subscribe_link() {
	$args = array_values(cerber_subscribe_params());

	// All activities, without any filter is not allowed
	$empty = array_filter($args);
	if (empty($empty)) return '';

	$subs = get_site_option( '_cerber_subs' );

	// Limit on number of subscriptions
	if ( count( $subs ) > 50 ) return '';

	$mode = 'on';
	if ( $subs ) {
		$hash = sha1( json_encode( $args ) );
		if ( recursive_search_key( $subs, $hash ) ) {
			$mode = 'off';
		}
	}
	$link = wp_nonce_url( add_query_arg( 'subscribe', $mode ), 'control', 'cerber_nonce' );
	if ($mode == 'on') $text = __('Subscribe','wp-cerber');
	else $text = __('Unsubscribe','wp-cerber');

	return '<span class="dashicons dashicons-email" style="vertical-align: middle;"></span> <a id="subscribe-me" href="' . $link . '" style="margin-right: 1.5em;">'.$text.'</a>';
}

/**
 * Managing the list of subscriptions
 *
 * @param string $mode Add or delete a subscription
 * @param string $hash If specified, subscription with given hash will be removed
 */
function cerber_subscribe( $mode = 'on', $hash = null ) {
	if ($hash) {
		$mode = 'off';
	}
	else {
		$args = array_values(cerber_subscribe_params());
		$hash = sha1( json_encode( $args ) );
	}

	$subs = get_site_option( '_cerber_subs' );

	if ( ! $subs ) {
		$subs = array();
	}

	if ( $mode == 'on' ) {
		$subs[ $hash ] = $args;
		$msg           = __( "You've subscribed", 'wp-cerber' );
	} else {
		unset( $subs[ $hash ] );
		$msg = __( "You've unsubscribed", 'wp-cerber' );
	}

	if ( update_site_option( '_cerber_subs', $subs ) ) {
		cerber_admin_message( $msg );
	}
}

// Unsubscribe with hash without nonce
add_action('admin_init',function(){
	if (!empty($_GET['unsubscribeme'])){
		cerber_subscribe('off',$_GET['unsubscribeme']);
		wp_safe_redirect(remove_query_arg('unsubscribeme'));
		exit;
	}
});

/*
	Pagination
*/
function cerber_page_navi($total,$per_page = 20){
	$max_links = 10;
	$page = cerber_get_pn();
	$last_page = ceil($total / $per_page);
	$ret = '';
	if($last_page > 1){
		$start =1 + $max_links * intval(($page-1)/$max_links);
		$end = $start + $max_links - 1;
		if ($end > $last_page) $end = $last_page;
		if ($start > $max_links) $links[]='<a href="'.esc_url(add_query_arg('pagen',$start - 1)).'" class="arrows"><b>&laquo;</b></a>';
		for ($i=$start; $i <= $end; $i++) {
			if($page!=$i) $links[]='<a href="'.esc_url(add_query_arg('pagen',$i)).'" >'.$i.'</a>';
			else $links[]='<a class="active" style="font-size: 16px;">'.$i.'</a> ';
		}
		if($end < $last_page) $links[]='<a href="'.esc_url(add_query_arg('pagen',$i)).'" class="arrows">&raquo;</a>'; // &#10141;
		$ret = '<table class="cerber-margin" style="margin-top:1em; border-collapse: collapse;"><tr><td><div class="pagination">'.implode(' ',$links).'</div></td><td><span style="margin-left:2em;"><b>'.$total.' '._n('entry','entries',$total,'wp-cerber').'</b></span></td></tr></table>';
	}
	return $ret;
}
function cerber_get_pn(){
	$page = 1;
	if ( isset( $_GET['pagen'] ) ) {
		$page = absint( $_GET['pagen'] );
		if ( ! $page ) {
			$page = 1;
		}
	}
	return $page;
}
/*
	Plugins screen links
*/
add_filter('plugin_action_links','cerber_action_links',10,4);
function cerber_action_links($actions, $plugin_file, $plugin_data, $context){
	if($plugin_file == cerber_plug_in()){
		$link[] = '<a href="' . cerber_admin_link() . '">' . __('Dashboard','wp-cerber') . '</a>';
		$link[] = '<a href="' . cerber_admin_link('acl') . '">' . __('Access Lists','wp-cerber') . '</a>';
		$actions = array_merge ($link,$actions);
	}
	return $actions;
}
/*
 * Create diagnostic database report
 *
 *
 */
function cerber_db_diag(){
    global $wpdb,$wp_cerber;
	$ret = array();

	$ret[]= 'Database name: '.DB_NAME;

    $pool = $wpdb->get_row('SHOW VARIABLES LIKE "innodb_buffer_pool_size"');
	$pool_size = round($pool->Value / 1048576);
	$inno = 'InnoDB buffer pool size: <b>'.$pool_size.' MB</b>';
	if ($pool_size < 16) $inno .= ' Your pool size is extremely small!';
	elseif ($pool_size < 64) $inno .= ' It seems that your pool size is too small.';
	$ret[]= $inno;

	$ret[]= cerber_table_info(CERBER_LOG_TABLE);
	$ret[]= cerber_table_info(CERBER_ACL_TABLE);
	$ret[]= cerber_table_info(CERBER_BLOCKS_TABLE);

	if ($wp_cerber->getRemoteIp() == '127.0.0.1') $ret[] = '<p style="color: #DF0000;">It seems that we are unable to get IP addresses.</p>';

	if ($errors = get_site_option( '_cerber_db_errors')){
		$err = '<p style="color: #DF0000;">Some minor DB errors were detected</p><textarea>'.print_r($errors,1).'</textarea>';
		update_site_option( '_cerber_db_errors', '');
	}
	else $err = '';

	return $err.implode('<p>',$ret);
}

/**
 * Creates mini report about given database table
 *
 * @param $table
 *
 * @return string
 */
function cerber_table_info( $table ) {
	global $wpdb;
	if (!cerber_is_table($table)){
		return '<p style="color: #DF0000;">ERROR. Database table ' . $table . ' not found! Click repair button below.</p>';
	}
	$cols = $wpdb->get_results( "SHOW FULL COLUMNS FROM " . $table );

	$columns    = '<table><tr><th style="width: 30%">Field</th><th style="width: 30%">Type</th><th style="width: 30%">Collation</th></tr>';
	foreach ( $cols as $column ) {
		$column    = obj_to_arr_deep( $column );
		$field     = array_shift( $column );
		$type      = array_shift( $column );
		$collation = array_shift( $column );
		$columns  .= '<tr><td><b>' . $field . '<b></td><td>' . $type . '</td><td>' . $collation . '</td></tr>';
	}
	$columns .= '</table>';

	$rows = absint( $wpdb->get_var( 'SELECT COUNT(*) FROM ' . $table ) );

	$sts = $wpdb->get_row( 'SHOW TABLE STATUS WHERE NAME = "' . $table .'"');
	$status = '<table>';
	foreach ( $sts as $key => $value ) {
		$status .= '<tr><td><b>' . $key . '<b></td><td>' . $value . '</td></tr>';
	}
	$status .= '</table>';

	return '<p style="font-size: 110%;">Table: <b>' . $table . '</b>, rows: ' . $rows . '</p><table class="diag-table"><tr><td class="diag-td">' . $columns . '</td><td class="diag-td">'. $status.'</td></tr></table>';
}


/*
function add_some_pointers() {
	?>
	<script type="text/javascript">
		jQuery(document).ready( function($) {
			var options = {'content':'<h3>Info</h3><p>Cerber will request WHOIS database for extra information when you click on IP.</p>','position':{'edge':'right','align':'center'}};
			if ( ! options ) return;
			options = $.extend( options, {
				close: function() {
					//to do
				}
			});

			//$("#ip_extra").click(function(){
			//	$(this).pointer( options ).pointer('open');
			//});

			$('#subscribe-me').pointer( options ).pointer('open');

		});
	</script>
	<?php
}
add_action('admin_enqueue_scripts', 'cerber_admin_enqueue');
function cerber_admin_enqueue($hook) {
	wp_enqueue_style( 'wp-pointer' );
	wp_enqueue_script( 'wp-pointer' );
}
*/


add_action( 'admin_enqueue_scripts', 'cerber_admin_assets', 9999 );
function cerber_admin_assets() {
    /*
	if ( ! cerber_is_admin_page() ) {
		return;
	}*/

	$assets_url = plugin_dir_url( __FILE__ ) . 'assets';

	if ( ! defined( 'CERBER_BETA' ) ) {
		wp_register_style( 'cerber_css', plugin_dir_url( __FILE__ ) . 'assets/admin.css', null, CERBER_VER );
		wp_enqueue_style( 'cerber_css' );

		wp_enqueue_script( 'cerber_js', $assets_url . '/admin.js', array( 'jquery' ), CERBER_VER, true );
	}

	// Select2
	//wp_register_style( 'select2css', $assets_url . '/select2/dist/css/select2.min.css' );
	//wp_enqueue_style( 'select2css' );
	//wp_enqueue_script( 'select2js', $assets_url . '/select2/dist/js/select2.min.js', null, null, true );

}

/*
 * JS & CSS for admin head
 *
 */
add_action('admin_head','cerber_admin_head');
function cerber_admin_head(){
	//$assets_url = plugin_dir_url(CERBER_FILE).'assets';

    if (defined('CERBER_BETA')) :
	    ?>
	    <style type="text/css" media="all">
		    <?php readfile(dirname(__FILE__).'/assets/admin.css'); ?>
	    </style>
	    <?php
    endif;

	if ( ! cerber_is_admin_page() ) {
		return;
	}
	?>
    <style type="text/css" media="all">
        /* Aliens messages */
        .update-nag,
        #setting-error-tgmpa {
            display: none;
        }

        /* Cerber's messages */
        div.wrap .update-nag,
        .crb-alarm {
            /*display: initial;*/
            display: inline-block;
        }
    </style>
	<?php
}
/*
 * JS & CSS for admin footer
 *
 */
add_action('admin_footer','cerber_basement');
function cerber_basement(){
	//add_some_pointers();
	//$assets_url = plugin_dir_url(CERBER_FILE).'assets';
	$ajax_nonce = wp_create_nonce('delete-ip');
	?>
	<script type="text/javascript">
        crb_ajax_nonce = '<?php echo $ajax_nonce; ?>';
	</script>
	<?php

	if (defined('CERBER_BETA')) :
		?>
        <script type="text/javascript">
            <?php readfile(dirname(__FILE__).'/assets/admin.js'); ?>
        </script>
		<?php
	endif;

}

add_filter( 'admin_footer_text','cerber_footer_text1');
function cerber_footer_text1($text){
	if (!cerber_is_admin_page(false)) return $text;
	return 'If you like how <strong>WP Cerber</strong> protects your website, please <a target="_blank" href="https://wordpress.org/support/plugin/wp-cerber/reviews/#new-post">leave it a &#9733; &#9733; &#9733; &#9733; &#9733; rating</a>. Thanks in advance!';
}
add_filter( 'update_footer','cerber_footer_text2', 1000);
function cerber_footer_text2($text){
	if (!cerber_is_admin_page(false)) return $text;
	return '<a target="_blank" href="https://wordpress.org/support/plugin/wp-cerber">Support forum</a>';
}

