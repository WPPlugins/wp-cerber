<?php
/*
	Cerber Laboratory (cerberlab.net) specific routines.
	API to access to nodes:	node1.cerberlab.net, node2.cerberlab.net, node3.cerberlab.net etc.

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

// If this file is called directly, abort executing.
if ( ! defined( 'WPINC' ) ) { exit; }

define( 'LAB_NODE_MAX', 5 ); // Maximum node ID
define( 'LAB_DELAY_MAX', 1500 ); // milliseconds, reasonable processing time while connecting to a node
define( 'LAB_RECHECK', 15 * 60 ); // seconds, allowed interval for rechecking nodes
define( 'LAB_INTERVAL', 180 ); // seconds, push interval
define( 'LAB_DNS_TTL', 3 * 24 * 3600 ); // seconds, interval of updating DNS cache for nodes IPs

/**
 * Send data to a Cerber Lab node.
 *
 * @param array $workload   Workload
 *
 * @return array|bool
 */
function lab_api_send_request($workload = array()) {
	global $node_delay;

	$push = lab_get_push();

	if (!$workload && !$push) return false;

	$request = array(
		'key' => cerber_get_key(),
		'workload' => $workload,
		'push' => $push,
		'lang' => get_bloginfo( 'language' ),
		'version' => CERBER_VER,
	);

	$ret = lab_send_request($request);

	// If something went wrong take next closest node
	if (!$ret){
		$ret = lab_send_request($request);
	}
	elseif (($node_delay * 1000) > LAB_DELAY_MAX){
		lab_check_nodes(); // Recheck nodes for further requests
	}

	if ($ret) lab_trunc_push();

	return $ret;
}

/**
 * Send a request to a node.
 * If the previous attempt was failed and $node_id is not set, will use next closest node.
 *
 * @param $request array
 * @param null $node_id Node ID if not set, will use the last closest and active node
 * @param string $scheme http|https
 *
 * @return array|bool
 */
function lab_send_request($request, $node_id = null, $scheme = null) {
	global $node_delay, $wp_cerber;

	$node = lab_get_node($node_id);
	if (!$scheme) {
		if ($wp_cerber->getSettings('cerberproto')) $scheme = 'https';
		else $scheme = 'http';
	}
	elseif ($scheme != 'http' || $scheme != 'https') $scheme = 'https';

	$body = array();
	$body['container'] = $request;
	$body['nodes'] = lab_get_nodes();

	$request_body = json_encode($body);
	if (JSON_ERROR_NONE != json_last_error()) {
		//'Unable to encode request: '.json_last_error_msg(), array(__FUNCTION__,__LINE__));
		return false;
	}

	$headers = array(
		'Host:'.$node[2],
		'Content-Type: application/json',
		'Accept: application/json',
		'Cerber: '.CERBER_VER,
		/*	'Authorization: Bearer ' . $fields['key']*/
	);

	$curl = @curl_init(); // @since 4.32
	if (!$curl) return false;

	curl_setopt_array($curl, array(
		CURLOPT_URL => $scheme . '://' . $node[2] . '/engine/v1/',
		CURLOPT_POST => true,
		CURLOPT_HTTPHEADER => $headers,
		CURLOPT_POSTFIELDS => $request_body,
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_USERAGENT => 'Cerber Security Plugin ' . CERBER_VER,
		CURLOPT_CONNECTTIMEOUT => 2,
		CURLOPT_TIMEOUT => 4, // including CURLOPT_CONNECTTIMEOUT
		CURLOPT_DNS_CACHE_TIMEOUT => 4 * 3600,
		CURLOPT_SSL_VERIFYHOST => 2,
		CURLOPT_SSL_VERIFYPEER => true,
	));

	//curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 2);
	//curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, true);

	$start = microtime( true );
	$data = curl_exec($curl);
	$stop  = microtime( true );

	//if (!$data) // curl_error($curl) . curl_errno($curl) );

	curl_close($curl);

	$node_delay = $stop - $start;

	$response = lab_parse_response( $data );

	lab_update_node_last($node[0], array( $node_delay, $response['status'], $response['error'], time(), $scheme, $node[1] ));

	if ($response['error']) return false;
	return $response;
}

/**
 * Parse node response and detect possible errors
 *
 * @param $response
 *
 * @return array|mixed|object
 */
function lab_parse_response($response){
	$ret = array( 'status' => 1, 'error' => false );

	if (!empty($response)) {
		$ret = json_decode( $response, true );
		if ( JSON_ERROR_NONE != json_last_error() ) {
			$ret['status'] = 0;
			$ret['error'] = 'JSON ERROR: '.json_last_error_msg();
		}
		// Is everything is OK?
		if (empty($ret['key']) || !empty($ret['error'])){
			$ret['status'] = 0; // Not OK
		}
	}
	else {
		$ret['status'] = 0;
		$ret['error'] = 'No node answer';
	}

	if (!isset($ret['error'])) $ret['error'] = false;

	return $ret;
}

/**
 * Return "the best" (closest) node if $node_id is not specified
 *
 * @param $node_id integer node ID
 * @return array first element is ID of closest node, second is an IP address
 */
function lab_get_node($node_id = null){

	$node_id = absint($node_id);
	if ($node_id) $best_id = $node_id;
	else $best_id = null;

	$nodes = lab_get_nodes();

	if (!$best_id) {
		if ( $nodes && ! empty( $nodes['best'] ) ) {
			$best_id = $nodes['best'];
			if ( ! $nodes['nodes'][ $best_id ]['last'][1] ) { // this node was not active at the last request
				unset( $nodes['nodes'][ $best_id ] );
				$best_id = lab_best_node( $nodes['nodes'] );
			}
		}
	}

	if (!$best_id || $best_id > LAB_NODE_MAX) $best_id = rand(1, LAB_NODE_MAX);

	$name = 'node' . $best_id . '.cerberlab.net';

	$host = null;
	if ( ! empty( $nodes['nodes'][ $best_id ]['last'] ) ) {
		$node = $nodes['nodes'][ $best_id ]['last'];
		if ( $node[5] && ( time() - $node[3] ) < LAB_DNS_TTL ) {
			$host = $node[5];
		}
	}
	if ( ! $host ) {
		$host = @gethostbyname( $name );
	}

	return array($best_id, $host, $name);
}

/**
 * Check all nodes and find the closest and active one.
 * 
 * @param bool $force if true perform check without checking allowed interval LAB_RECHECK
 *
 * @return bool|int
 */
function lab_check_nodes($force = false) {

	$nodes = lab_get_nodes();
	if (!$force && isset($nodes['last_check']) && (time() - $nodes['last_check']) < LAB_RECHECK )  return false;

	$nodes['nodes'] = array(); // clean up before testing
	update_site_option( '_cerberlab_', $nodes );

	for ( $i = 1; $i <= LAB_NODE_MAX; $i ++ ) {
		lab_send_request( array( 'test' => 'test', 'key' => 1 ), $i );
	}

	$nodes = lab_get_nodes();
	$nodes['best'] = lab_best_node($nodes['nodes']);
	$nodes['last_check'] = time();

	update_site_option( '_cerberlab_', $nodes );

	return $nodes['best'];
}

/**
 * Find the best (closest) and active node in the list of nodes
 *
 * @param array $nodes
 *
 * @return int
 */
function lab_best_node($nodes = array()){
	$active_nodes  = array();
	foreach ( $nodes as $id => $data ) {
		if ($data['last']['1']) $active_nodes[ $id ] = $data['last']['0']; // only active nodes must be in the list
	}
	if ($active_nodes){
		asort( $active_nodes );
		reset( $active_nodes );
		$best_id = key( $active_nodes );
	}
	else $best_id = 0; // no active nodes found :-(
	return $best_id;
}
/**
 * Update node status
 *
 * @param $node_id
 * @param array $last
 *
 * @return bool
 */
function lab_update_node_last($node_id, $last = array()) {
	$nodes = lab_get_nodes();
	if ( ! $nodes ) {
		$nodes = array();
	}
	$nodes['nodes'][$node_id]['last'] = $last;
	return update_site_option('_cerberlab_', $nodes);
}

function lab_get_nodes() {
	return get_site_option( '_cerberlab_' );
}

/**
 * Small diagnostic report about nodes for admin
 *
 * @return string Report to show in Dashboard
 */
function lab_status(){
	global $wp_cerber;

	$ret = '';

	if (!$wp_cerber->getSettings('cerberlab')) $ret .= '<p><b>Cerber Lab connection is disabled</b></p>';

	$nodes = lab_get_nodes();
	if (empty($nodes['nodes'])) return $ret . '<p>No information. No request has been made yet.</p>';

	$ret .= '<table><tr><th>Node</th><th>Processing time</th><th>Operational status</th><th>Info</th><th>IP address</th><th>Last request</th><th>Protocol used</th></tr>';
	foreach ( $nodes['nodes'] as $id => $node ) {
		$delay = round(1000 * $node['last'][0]) . ' ms';
		$ago = cerber_ago_time($node['last'][3]);
		$status = $node['last'][1];
		if ($status) {
			$class = 'node-ok';
			$status = '<span style = "color:green;">'.$status.'</span>';
		}
		else {
			$class ='node-error';
			$status = 'Down';
			$delay = 'Unknown';
		}
		$ret .= '<tr class="'.$class.'"><td>'.$id.'</td><td>'.$delay.'</td><td>'.$status.'</td><td>'.$node['last'][2].'</td><td>'.$node['last'][5].'</td><td>'.$ago.'</td><td>'.$node['last'][4].'</td><td>';
	}
	$ret .= '</table>';

	if (!empty($nodes['best'])) $ret .= '<p>Closest (fastest) node: '.$nodes['best'].'</p>';
	if (!empty($nodes['last_check'])) $ret .= '<p>Last check for all nodes: '.cerber_ago_time($nodes['last_check']).'</p>';
	$key = cerber_get_key();
	$ret .= '<p>Site ID: '.$key[0].'</p>';

	return $ret;
}
/**
 * Save data for lab
 *
 * @param $ip
 * @param $reason_id
 * @param $details
 */
function lab_save_push( $ip, $reason_id, $details ) {
	global $wpdb, $wp_cerber;
	if ( $wp_cerber->getSettings( 'cerberlab' ) ) {
		$wpdb->insert( CERBER_LAB_TABLE, array(
			'ip'        => $ip,
			'reason_id' => $reason_id,
			'details'   => $details,
			'stamp'     => time(),
		), array( '%s', '%d', '%s', '%d' ) );
	}
}
/**
 * Get data for lab
 *
 * @return array|bool
 */
function lab_get_push() {
	global $wpdb;

	$result = $wpdb->get_results( 'SELECT * FROM ' . CERBER_LAB_TABLE, ARRAY_A );
	if ( $result ) {
		return array( 'type_1' => $result );
	}

	return false;
}
function lab_trunc_push(){
	global $wpdb;
	$wpdb->query( 'TRUNCATE TABLE ' . CERBER_LAB_TABLE );
}

add_action('shutdown','cerber_push_lab');
function cerber_push_lab() {
	global $wp_cerber;

	if (!$wp_cerber->getSettings('cerberlab')) return;
	if ( get_transient( '_cerberpush_' ) ) {
		return;
	}
	lab_api_send_request();
	set_transient( '_cerberpush_', 1, LAB_INTERVAL );
}

function cerber_get_key($force = false){
	$key = get_site_option( '_cerberkey_' );
	if ($force || !$key || !is_array($key)){
		if (is_multisite()){
			$home = network_home_url();
		}
		else {
			$home = home_url();
		}
		if ( $host = parse_url( $home, PHP_URL_HOST ) ) {
			$key = md5( $host );
		}
		else {
			$key = md5( $home );
		}
		update_site_option( '_cerberkey_', array( $key, time() ) );
	}
	return $key;
}

/**
 * Opt in for the connection to Cerber Lab
 *
 *
 */
add_action( 'admin_notices', 'lab_opt_in');
add_action( 'network_admin_notices', 'lab_opt_in' );
function lab_opt_in(){
	global $wp_cerber, $cerber_shown;

	if ($cerber_shown || $wp_cerber->getSettings('cerberlab')) return;
	if (!cerber_is_admin_page(false)) return;

	// Avoid more than one message on the screen
	// TODO: to many checks!
	if (get_site_option('cerber_admin_notice', null)) return;
	if (get_site_option('cerber_admin_message', null)) return;
	if (get_site_option('cerber_admin_info', null)) return;
	if ( $o = get_site_option( '_lab_o' . 'pt_in_' ) ) {
		//if ( $o[0] == 'NO' && ( $o[1] + 3600 * 24 * 30 ) > time() ) {
		if ( ($o[1] + 3600 * 24 * 30 ) > time() ) {
			return;
		}
	}
	if ($c = get_site_option('_cerber_activated')){
		$c = maybe_unserialize($c);
		if (!empty($c['time']) && ($c['time'] + 3600 * 24 * 7) > time()){
			return;
		}
	}

	$h = __('Want to make WP Cerber even more powerful?','wp-cerber');
	$text = __('Allow WP Cerber to send locked out malicious IP addresses to Cerber Lab. This helps the plugin team to develop new algorithms for WP Cerber that will defend WordPress against new threats and botnets that are appearing  everyday. You can disable the sending in the plugin settings at any time.','wp-cerber');
	$ok = __('OK, nail them all','wp-cerber');
	$no = __('NO, maybe later','wp-cerber');
	$more = '<a href="http://wpcerber.com/cerber-laboratory/" target="_blank">' . __( 'Know more', 'wp-cerber' ) . '</a>';

	$msg = '<h3>' . $h . '</h3><p>' . $text . '</p>';

	$assets_url = plugin_dir_url( CERBER_FILE ) . 'assets';
	$notice     =
		'<table><tr><td><img style="width:100px; float:left; margin-left:-10px;" src="' . $assets_url . '/icon-128x128.png"></td>' .
		'<td style ="max-width: 850px;">' . $msg .
		'<p style="float:left;">' . $more . '</p>
		<p style="text-align:right;">
		<input type="button" id = "lab_ok" class="button button-primary cerber-dismiss" value=" &nbsp; ' . $ok . ' &nbsp; "/>
		<input type="button" id = "lab_no" class="button button-primary cerber-dismiss" value=" &nbsp; ' . $no . ' &nbsp; "/>
		</p></td></tr></table>';

	echo '<div class="updated cerber-msg" style="overflow: auto;"><p>' . $notice . '</p></div>';

}

/**
 * Save a user choice
 *
 * @param string $button
 */
function lab_user_opt_in( $button = '' ) {
	$a = null;
	if ( $button == 'lab_ok' ) {
		$a     = array( 'YES', time() );
		$o     = get_site_option( CERBER_OPT );
		$o['cerberlab'] = 1;
		update_site_option( CERBER_OPT, $o );
	}
	if ( $button == 'lab_no' ) {
		$a = array( 'NO', time() );
	}
	if ( $a ) {
		update_site_option( '_lab_o' . 'pt_in_', $a );
	}
}