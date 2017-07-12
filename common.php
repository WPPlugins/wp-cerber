<?php
/*
 	Copyright (C) 2015-17 Gregory Markov, http://wpcerber.com
	Flag icons - http://www.famfamfam.com

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

function cerber_pb_get_devices($token = ''){
	global $wp_cerber;
	$ret = array();

	if (!$token){
		if (!$token = $wp_cerber->getSettings('pbtoken')) return false;
	}

	$curl = @curl_init();
	if (!$curl) return false;

	$headers = array(
		'Authorization: Bearer ' . $token
	);

	curl_setopt_array($curl, array(
		CURLOPT_URL => 'https://api.pushbullet.com/v2/devices',
		CURLOPT_HTTPHEADER => $headers,
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_CONNECTTIMEOUT => 2,
		CURLOPT_TIMEOUT => 4, // including CURLOPT_CONNECTTIMEOUT
		CURLOPT_DNS_CACHE_TIMEOUT => 4 * 3600,
	));

	$result = curl_exec($curl);
	$curl_error = curl_error($curl);
	curl_close($curl);

	$response = json_decode( $result, true );

	if ( JSON_ERROR_NONE == json_last_error() && isset( $response['devices'] ) ) {
		foreach ( $response['devices'] as $device ) {
			$ret[ $device['iden'] ] = $device['nickname'];
		}
	}
	else {
		if ($response['error']){
			$e = 'Pushbullet ' . $response['error']['message'];
		}
		elseif ($curl_error){
			$e = $curl_error;
		}
		else $e = 'Unknown cURL error';

		cerber_admin_notice( __( 'ERROR:', 'wp-cerber' ) .' '. $e);
	}

	return $ret;
}

/**
 * Send push message via Pushbullet
 *
 * @param $title
 * @param $body
 *
 * @return bool
 */
function cerber_pb_send($title, $body){
	global $wp_cerber;

	if (!$body) return false;
	if (!$token = $wp_cerber->getSettings('pbtoken')) return false;

	$params = array('type' => 'note', 'title' => $title, 'body' => $body, 'sender_name' => 'WP Cerber');

	if ($device = $wp_cerber->getSettings('pbdevice')) {
		if ($device && $device != 'all' && $device != 'N') $params['device_iden'] = $device;
	}

	$headers = array('Access-Token: '.$token,'Content-Type: application/json');

	$curl = @curl_init();
	if (!$curl) return false;

	curl_setopt_array($curl, array(
		CURLOPT_URL => 'https://api.pushbullet.com/v2/pushes',
		CURLOPT_POST => true,
		CURLOPT_HTTPHEADER => $headers,
		CURLOPT_POSTFIELDS => json_encode($params),
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_CONNECTTIMEOUT => 2,
		CURLOPT_TIMEOUT => 4, // including CURLOPT_CONNECTTIMEOUT
		CURLOPT_DNS_CACHE_TIMEOUT => 4 * 3600,
	));

	$result = curl_exec($curl);
	$curl_error = curl_error($curl);
	curl_close($curl);

	return $curl_error;
}
/**
 * Just test is cURL available
 */
function cerber_self_diagnostic(){
	if  (!in_array('curl', get_loaded_extensions())) {
		cerber_admin_notice( __( 'ERROR:', 'wp-cerber' ) . ' cURL PHP library is not enabled on your website.');
	}
	else {
		$curl = @curl_init();
		if (!$curl && ($err_msg = curl_error($curl))) cerber_admin_notice( __( 'ERROR:', 'wp-cerber' ) .' '. $err_msg);
		curl_close($curl);
	}
}
/**
 * Get ip_id for IP.
 * The ip_id can be safely used for array indexes and in any HTML code
 * @since 2.2
 *
 * @param $ip string IP address
 * @return string ID for given IP
 */
function cerber_get_id_ip( $ip ) {
	$ip_id = str_replace( '.', '-', $ip, $count );
	if ( ! $count ) {  // IPv6
		$ip_id = str_replace( ':', '_', $ip_id );
	}
	return $ip_id;
}
/**
 * Get IP from ip_id
 * @since 2.2
 *
 * @param $ip_id string ID for an IP
 *
 * @return string IP address for given ID
 */
function cerber_get_ip_id( $ip_id ) {
	$ip = str_replace( '-', '.', $ip_id, $count );
	if ( ! $count ) {  // IPv6
		$ip = str_replace( '_', ':', $ip );
	}
	return $ip;
}
/**
 * Check if given IP address is an valid single IP v4 address
 * 
 * @param $ip
 *
 * @return bool
 */
function cerber_is_ipv4($ip){
	if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return true;
	return false;
}
/**
 * Convert multilevel object or array of objects to associative array recursively
 *
 * @param $var object|array
 *
 * @return array result of conversion
 * @since 3.0
 */
function obj_to_arr_deep($var) {
	if (is_object($var)) {
		$var = get_object_vars($var);
	}
	if (is_array($var)) {
		return array_map(__FUNCTION__, $var);
	}
	else {
		return $var;
	}
}

/**
 * Search for a key in the given multidimensional array
 *
 * @param $array
 * @param $needle
 *
 * @return bool
 */
function recursive_search_key($array, $needle){
	foreach($array as $key => $value){
		if ((string)$key == (string)$needle){
			return true;
		}
		if(is_array($value)){
			$ret = recursive_search_key($value, $needle);
			if ($ret == true) return true;
		}
	}
	return false;
}

/**
 * Return true if REST API URL is requested
 *
 * @return bool
 * @since 3.0
 */
function cerber_is_rest_url(){
	if (false !== strpos($_SERVER['REQUEST_URI'], rest_get_url_prefix()) || false !== strpos($_SERVER['REQUEST_URI'], '?rest_route=')){
		if (0 === strpos(get_home_url().urldecode($_SERVER['REQUEST_URI']),get_rest_url())) {
			return true;
		}
	}
	return false;
}

/*
 * Sets of human readable labels for vary activity/logs events
 * @since 1.0
 *
 */
function cerber_get_labels($type){
	$labels = array();
	if ($type == 'activity') {

		// User actions
		$labels[1]=__('User created','wp-cerber');
		$labels[2]=__('User registered','wp-cerber');
		$labels[5]=__('Logged in','wp-cerber');
		$labels[6]=__('Logged out','wp-cerber');
		$labels[7]=__('Login failed','wp-cerber');

		// Cerber actions - IP specific - lockouts
		$labels[10]=__('IP blocked','wp-cerber');
		$labels[11]=__('Subnet blocked','wp-cerber');
		// Cerber actions - common
		$labels[12]=__('Citadel activated!','wp-cerber');
		// Cerber state
		$labels[13]=__('Locked out','wp-cerber');
		$labels[14]=__('IP blacklisted','wp-cerber');

		// Other actions
		$labels[20]=__('Password changed','wp-cerber');
		$labels[21]=__('Password reset requested','wp-cerber');

		$labels[40]=__('reCAPTCHA verification failed','wp-cerber');
		$labels[41]=__('reCAPTCHA settings are incorrect','wp-cerber');
		$labels[42]=__('Request to the Google reCAPTCHA service failed','wp-cerber');

		$labels[50]=__('Attempt to access prohibited URL','wp-cerber');
		$labels[51]=__('Attempt to log in with non-existent username','wp-cerber');
		$labels[52]=__('Attempt to log in with prohibited username','wp-cerber');

	}
	return $labels;
}

function cerber_get_reason($id){
	$labels = array();
	$ret = __('Unknown','wp-cerber');
	$labels[1]=	__('Limit on login attempts is reached','wp-cerber');
	$labels[2]= __('Attempt to access', 'wp-cerber' );
	$labels[3]= __('Attempt to log in with non-existent username','wp-cerber');
	$labels[4]= __('Attempt to log in with prohibited username','wp-cerber');
	$labels[5]=	__('Limit on failed reCAPTCHA verifications is reached','wp-cerber');

	if (isset($labels[$id])) $ret = $labels[$id];
	return $ret;
}

function cerber_admin_info($msg, $type = 'normal'){
	$assets_url = plugin_dir_url(CERBER_FILE).'assets';
	update_site_option('cerber_admin_info',
		'<table><tr><td><img style="float:left; margin-left:-10px;" src="'.$assets_url.'/icon-128x128.png"></td>'.
		'<td>'.$msg.
		'<p style="text-align:right;">
		<input type="button" class="button button-primary cerber-dismiss" value=" &nbsp; OK &nbsp; "/></p></td></tr></table>');
}

function cerber_db_error_log($msg = null){
	global $wpdb;
	if (!$msg) $msg = array($wpdb->last_error, $wpdb->last_query, date('Y-m-d H:i:s'));
	$old = get_site_option( '_cerber_db_errors');
	if (!$old) $old = array();
	update_site_option( '_cerber_db_errors', array_merge($old,$msg));
}


/**
 * Save admin error message for further displaying
 *
 * @param string $msg
 */
function cerber_admin_notice($msg){
	if (!$msg) return;
	update_site_option('cerber_admin_notice', $msg);
}

/**
 * Save admin info message for further displaying
 *
 * @param string $msg
 */
function cerber_admin_message($msg){
	if (!$msg) return;
	update_site_option('cerber_admin_message', $msg);
}
/**
 * Return human readable "ago" time
 * 
 * @param $time integer Unix timestamp - time of an event
 *
 * @return string
 */
function cerber_ago_time($time){

	return sprintf( __( '%s ago' ), human_time_diff( $time ) );
}

function cerber_percent($one,$two){
	if ($one == 0) {
		if ($two > 0) $ret = '100';
		else $ret = '0';
	}
	else {
		$ret = round (((($two - $one)/$one)) * 100);
	}
	$style='';
	if ($ret < 0) $style='color:#008000';
	elseif ($ret > 0) $style='color:#FF0000';
	if ($ret > 0)	$ret = '+'.$ret;
	return '<span style="'.$style.'">'.$ret.' %</span>';
}

/**
 * Return a user by login or email with automatic detection
 *
 * @param $login_email string login or email
 *
 * @return false|WP_User
 */
function cerber_get_user( $login_email ) {
	if ( is_email( $login_email ) ) {
		return get_user_by( 'email', $login_email );
	}

	return get_user_by( 'login', $login_email );
}

/**
 * Check if DB table exists
 *
 * @param $table
 *
 * @return bool
 */
function cerber_is_table($table){
	global $wpdb;
	if (!$wpdb->get_row( "SHOW TABLES LIKE '" . $table . "'" )){
		return false;
	}
	return true;
}

/**
 * Check if a column is defined in a DB table
 *
 * @param $table string DB table name
 * @param $column string Field name
 *
 * @return bool true if field exists
 */
function cerber_check_table( $table, $column ) {
	global $wpdb;
	$result = $wpdb->get_row( 'SHOW FIELDS FROM ' . $table . " WHERE FIELD = '" . $column . "'" );
	if ( ! $result ) {
		return false;
	}

	return true;
}