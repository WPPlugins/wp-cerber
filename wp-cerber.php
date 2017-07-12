<?php
/*
	Plugin Name: WP Cerber
	Plugin URI: http://wpcerber.com
	Description: Protects site from brute force attacks, bots and hackers. Antispam protection with reCAPTCHA. Comprehensive control of user activity. Restrict login by IP access lists. Limit login attempts. Feel free to contact developer on the site <a href="http://wpcerber.com">wpcerber.com</a>.
	Author: Gregory
	Author URI: http://wpcerber.com
	Version: 4.8.2
	Text Domain: wp-cerber
	Domain Path: /languages
	Network: true

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



 ▄████▄     ▓█████     ██▀███      ▄▄▄▄      ▓█████     ██▀███
▒██▀ ▀█     ▓█   ▀    ▓██ ▒ ██▒   ▓█████▄    ▓█   ▀    ▓██ ▒ ██▒
▒▓█    ▄    ▒███      ▓██ ░▄█ ▒   ▒██▒ ▄██   ▒███      ▓██ ░▄█ ▒
▒▓▓▄ ▄██▒   ▒▓█  ▄    ▒██▀▀█▄     ▒██░█▀     ▒▓█  ▄    ▒██▀▀█▄
▒ ▓███▀ ░   ░▒████▒   ░██▓ ▒██▒   ░▓█  ▀█▓   ░▒████▒   ░██▓ ▒██▒
░ ░▒ ▒  ░   ░░ ▒░ ░   ░ ▒▓ ░▒▓░   ░▒▓███▀▒   ░░ ▒░ ░   ░ ▒▓ ░▒▓░
  ░  ▒       ░ ░  ░     ░▒ ░ ▒░   ▒░▒   ░     ░ ░  ░     ░▒ ░ ▒░
░              ░        ░░   ░     ░    ░       ░        ░░   ░
░ ░            ░  ░      ░         ░            ░  ░      ░
░                                       ░




*========================================================================*
|                                                                        |
|	       ATTENTION!  Do not change or edit this file!                  |
|                                                                        |
*========================================================================*

*/

// If this file is called directly, abort executing.
if ( ! defined( 'WPINC' ) ) { exit; }

define( 'CERBER_VER', '4.8.2' );
define( 'CERBER_LOG_TABLE', 'cerber_log' );
define( 'CERBER_ACL_TABLE', 'cerber_acl' );
define( 'CERBER_BLOCKS_TABLE', 'cerber_blocks' );
define( 'CERBER_LAB_TABLE', 'cerber_lab' );

define( 'WP_LOGIN_SCRIPT', 'wp-login.php' );
define( 'WP_REG_SCRIPT', 'wp-register.php' );
define( 'WP_XMLRPC_SCRIPT', 'xmlrpc.php' );
define( 'WP_TRACKBACK_SCRIPT', 'wp-trackback.php' );
define( 'WP_PING_SCRIPT', 'wp-trackback.php' );
define( 'WP_SIGNUP_SCRIPT', 'wp-signup.php' );

define( 'GOO_RECAPTCHA_URL', 'https://www.google.com/recaptcha/api/siteverify' );

define( 'CERBER_REQ_PHP', '5.3.0' );
define( 'CERBER_REQ_WP', '4.4' );
define( 'CERBER_FILE', __FILE__ );
define( 'CERBER_TECH', 'https://cerber.tech/' );

require_once( dirname( __FILE__ ) . '/common.php' );
require_once( dirname( __FILE__ ) . '/settings.php' );
require_once( dirname( __FILE__ ) . '/cerber-lab.php' );
require_once( dirname( __FILE__ ) . '/whois.php' );
require_once( dirname( __FILE__ ) . '/jetflow.php' );
require_once( dirname( __FILE__ ) . '/cerber-news.php' );

if ( defined( 'WP_ADMIN' ) || defined( 'WP_NETWORK_ADMIN' ) ) {
	// Load dashboard stuff
	require_once( dirname( __FILE__ ) . '/dashboard.php' );
}

cerber_upgrade();

class WP_Cerber {
	private $remote_ip;
	private $status;
	private $options;
	private $processed = null; // Important, that allows Cerber not to process an IP twice

	private $recaptcha = null; // Can recaptcha be verified with a current request
	private $recaptcha_verified = null; // Is recaptcha successfully verified with a current request
	public $recaptcha_here = null; // Is recaptcha widget enabled on the currently displayed page

	public $garbage = false; // Garbage has been deleted

	final function __construct() {

		// Load settings with filling missing (not-set) array keys
		$this->options = cerber_get_options();
		$keys = array();
		//$defaults = array();
		foreach ( cerber_get_defaults() as $item ) {
			$keys = array_merge( $keys, array_keys( $item ) );
			//$defaults = array_merge( $defaults, $item );
		}
		foreach ( $keys as $key ) {
			if ( ! isset( $this->options[ $key ] ) ) {
				$this->options[ $key ] = null;
			}
		}

		if ( defined( 'CERBER_IP_KEY' ) ) {
			$this->remote_ip = filter_var( $_SERVER[ CERBER_IP_KEY ], FILTER_VALIDATE_IP );
		}
		elseif ( $this->options['proxy'] && isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			$list = explode( ',', $_SERVER['HTTP_X_FORWARDED_FOR'] );
			foreach ( $list as $maybe_ip ) {
				$this->remote_ip = filter_var( trim( $maybe_ip ), FILTER_VALIDATE_IP );
				if ( $this->remote_ip ) {
					break;
				}
			}
			if ( ! $this->remote_ip && isset( $_SERVER['HTTP_X_REAL_IP'] ) ) {
				$this->remote_ip = filter_var( $_SERVER['HTTP_X_REAL_IP'], FILTER_VALIDATE_IP );
			}
		} else {
			if ( isset( $_SERVER['REMOTE_ADDR'] ) ) {
				$this->remote_ip = $_SERVER['REMOTE_ADDR'];
			} elseif ( isset( $_SERVER['HTTP_X_REAL_IP'] ) ) {
				$this->remote_ip = $_SERVER['HTTP_X_REAL_IP'];
			} elseif ( isset( $_SERVER['HTTP_CLIENT_IP'] ) ) {
				$this->remote_ip = $_SERVER['HTTP_CLIENT_IP'];
			} elseif ( isset( $_SERVER['SERVER_ADDR'] ) ) {
				$this->remote_ip = $_SERVER['SERVER_ADDR'];
			}
			$this->remote_ip = filter_var( $this->remote_ip, FILTER_VALIDATE_IP );
		}
		// No IP address was found? Roll back to localhost.
		if ( ! $this->remote_ip ) {
			$this->remote_ip = '127.0.0.1';
		} // including WP-CLI, other way is: if defined('WP_CLI')


		$this->status = 0; // Default

        if ( cerber_is_citadel() ) {
			$this->status = 3;
		}
		else {
	        if ( ! cerber_is_allowed( $this->remote_ip ) ) {
		        $this->status = 2;
	        }
	        $tag = cerber_acl_check( $this->remote_ip );
	        if ( $tag == 'B' ) {
		        $this->status = 1;
	        }
	        elseif ( $tag == 'W' ) {
		        //$this->status = 4;
	        }
        }

		$this->reCaptchaInit();

		$this->deleteGarbage();

		// Condition to check reCAPTCHA

		add_action( 'login_init', array( $this, 'reCaptchaNow' ) );

	}

	final public function getRemoteIp() {
		return $this->remote_ip;
	}

	final public function getStatus() {
		return $this->status;
	}

	/*
		Return Error message in context
	*/
	final public function getErrorMsg() {
		switch ( $this->status ) {
			case 1:
			case 3:
				return __( 'You are not allowed to log in. Ask your administrator for assistance.', 'wp-cerber' );
			case 2:
				$block = cerber_get_block();
				$min   = 1 + ( $block->block_until - time() ) / 60;

				return apply_filters( 'cerber_msg_reached',
					sprintf( __( 'You have reached the login attempts limit. Please try again in %d minutes.', 'wp-cerber' ), $min ),
					$min );
				break;
			default:
				return '';
		}
	}

	/*
		Return Remain message in context
	*/
	final public function getRemainMsg() {
		$acl = !$this->options['limitwhite'];
		$remain = cerber_get_remain_count($this->remote_ip, $acl);
		if ( $remain < $this->options['attempts'] ) {
			if ( $remain == 0 ) {
				$remain = 1;  // with some settings or when lockout was manually removed, we need to have 1 attempt.
			}
			return apply_filters( 'cerber_msg_remain',
				sprintf( _n( 'You have only one attempt remaining.', 'You have %d attempts remaining.', $remain, 'wp-cerber' ), $remain ),
				$remain );
		}

		return false;
	}

	final public function getSettings( $name = null ) {
		if ( ! empty( $name ) ) {
			if ( isset( $this->options[ $name ] ) ) {
				return $this->options[ $name ];
			} else {
				return false;
			}
		}

		return $this->options;
	}

	final public function isProhibited( $username ) {
		if ( empty( $this->options['prohibited'] ) ) {
			return false;
		}

		return in_array( $username, (array) $this->options['prohibited'] );
	}

	/**
	 * Adding reCAPTCHA widgets
	 *
	 */
	final public function reCaptchaInit(){

		if ( $this->status == 4 || empty( $this->options['sitekey'] ) || empty( $this->options['secretkey'] )) return;

		// Native WP forms
		add_action( 'login_form', function () {
			global $wp_cerber;
			$wp_cerber->reCaptcha( 'widget', 'recaplogin' );
		} );
		add_filter( 'login_form_middle', function ( $value ) {
			global $wp_cerber;
			$value .= $wp_cerber->reCaptcha( 'widget', 'recaplogin', false );
			return $value;
		});
		add_action( 'lostpassword_form', function () {
			global $wp_cerber;
			$wp_cerber->reCaptcha( 'widget', 'recaplost' );
		} );
		add_action( 'register_form', function () {
			global $wp_cerber;
			if ( !did_action( 'woocommerce_register_form_start' ) ) {
				$wp_cerber->reCaptcha( 'widget', 'recapreg' );
			}
		} );

		add_filter( 'comment_form_submit_field', function ( $value ) {
			global $wp_cerber, $post;
			$au = $wp_cerber->getSettings('recapcomauth');
			if (!$au || ($au && !is_user_logged_in())) {
				if (!empty($_COOKIE["cerber-recaptcha-id"]) && $_COOKIE["cerber-recaptcha-id"] == $post->ID){
				    echo '<div id="cerber-recaptcha-msg">'. __( 'ERROR:', 'wp-cerber' ) .' '. $wp_cerber->reCaptchaMsg('comment').'</div>';
				    echo '<script type="text/javascript">document.cookie = "the-recaptcha-id=0";</script>';
                }
			    $wp_cerber->reCaptcha( 'widget', 'recapcom' );
            }
			return $value;
		} );
		// $approved = apply_filters( 'pre_comment_approved', $approved, $commentdata );
		add_action( 'pre_comment_on_post', function ( $comment_post_ID ) {
			global $wp_cerber;

			if ($wp_cerber->getSettings('recapcomauth') && is_user_logged_in()) return;

			if ( ! $wp_cerber->reCaptchaValidate('comment', true) ) {
				setcookie('cerber-recaptcha-id', $comment_post_ID, time() + 60, '/');
				$comments = get_comments( array( 'number' => '1', 'post_id' => $comment_post_ID ) );
				if ($comments) {
					$loc = get_comment_link($comments[0]->comment_ID);
				}
				else {
				    $loc = get_permalink($comment_post_ID).'#cerber-recaptcha-msg';
                }
				wp_safe_redirect( $loc );
				exit;
			}
		});

		// Support for WooCommerce forms: @since 3.8
		add_action( 'woocommerce_login_form', function () {
			global $wp_cerber;
			$wp_cerber->reCaptcha( 'widget', 'recapwoologin' );
		} );
		add_action( 'woocommerce_lostpassword_form', function () {
			global $wp_cerber;
			$wp_cerber->reCaptcha( 'widget', 'recapwoolost' );
		} );
		add_action( 'woocommerce_register_form', function () {
			global $wp_cerber;
			if ( ! did_action( 'woocommerce_register_form_start' ) ) {
				return;
			}
			$wp_cerber->reCaptcha( 'widget', 'recapwooreg' );
		} );
		add_filter( 'woocommerce_process_login_errors', function ( $validation_error ) {
			global $wp_cerber;
			//$wp_cerber->reCaptchaNow();
			if ( ! $wp_cerber->reCaptchaValidate('woologin', true) ) {

				return new WP_Error( 'incorrect_recaptcha', $wp_cerber->reCaptchaMsg('woocommerce-login'));
			}
			return $validation_error;
		});
		add_filter( 'allow_password_reset', function ( $var ) { // Note: 'allow_password_reset' also is fired in WP itself
			global $wp_cerber;
			if ( isset( $_POST['wc_reset_password'] ) && did_action( 'woocommerce_init' )) {
				//$wp_cerber->reCaptchaNow();
				if ( ! $wp_cerber->reCaptchaValidate( 'woolost' , true) ) {

					return new WP_Error( 'incorrect_recaptcha', $wp_cerber->reCaptchaMsg('woocommerce-lost'));
				}
			}
			return $var;
		});
		add_filter( 'woocommerce_process_registration_errors', function ( $validation_error ) {
			global $wp_cerber;
			//$wp_cerber->reCaptchaNow();
			if ( ! $wp_cerber->reCaptchaValidate('wooreg' , true) ) {

				return new WP_Error( 'incorrect_recaptcha', $wp_cerber->reCaptchaMsg('woocommerce-register'));
			}
			return $validation_error;
		});

	}

	/**
	 * Generates reCAPTCHA HTML
	 *
	 * @param string $part  'style' or 'widget'
	 * @param null $option  what plugin setting must be set to show the reCAPTCHA
	 * @param bool $echo    if false, return the code, otherwise show it
	 *
	 * @return null|string
	 */
	final public function reCaptcha( $part = '', $option = null, $echo = true ) {
		if ( $this->status == 4 || empty( $this->options['sitekey'] ) || empty( $this->options['secretkey'] )
		     || ( $option && empty( $this->options[ $option ] ) )
		) {
			return null;
		}

		$sitekey = $this->options['sitekey'];
		$ret     = '';

		switch ( $part ) {
			case 'style': // for default login WP form only - fit it in width nicely.
				?>
				<style type="text/css" media="all">
					#rc-imageselect, .g-recaptcha {
						transform: scale(0.9);
						-webkit-transform: scale(0.9);
						transform-origin: 0 0;
						-webkit-transform-origin: 0 0;
					}

					.g-recaptcha {
						margin: 16px 0 20px 0;
					}
				</style>
				<?php
				break;
			case 'widget':
				if ( ! empty( $this->options[ $option ] ) ) {
					$this->recaptcha_here = true;

					//if ($this->options['invirecap']) $ret = '<div data-size="invisible" class="g-recaptcha" data-sitekey="' . $sitekey . '" data-callback="now_submit_the_form" id="cerber-recaptcha" data-badge="bottomright"></div>';
					if ($this->options['invirecap']) {
					    $ret = '<span class="cerber-form-marker"></span><div data-size="invisible" class="g-recaptcha" data-sitekey="' . $sitekey . '" data-callback="now_submit_the_form" id="cerber-recaptcha" data-badge="bottomright"></div>';
					}
					else $ret = '<span class="cerber-form-marker"></span><div class="g-recaptcha" data-sitekey="' . $sitekey . '" data-callback="form_button_enabler" id="cerber-recaptcha"></div>';

					//$ret = '<span class="cerber-form-marker g-recaptcha"></span>';

				}
				break;
		}
		if ( $echo ) {
			echo $ret;
			$ret = null;
		}

		return $ret;
		/*
			<script type="text/javascript">
				var onloadCallback = function() {
					//document.getElementById("wp-submit").disabled = true;
					grecaptcha.render("c-recaptcha", {"sitekey" : "<?php echo $sitekey; ?>" });
					//document.getElementById("wp-submit").disabled = false;
				};
			</script>
			<script src = "https://www.google.com/recaptcha/api.js?onload=onloadCallback&render=explicit&hl=<?php echo $lang; ?>" async defer></script>
			*/
	}

	/**
	 * Validate reCAPTCHA by calling Google service
	 *
	 * @param string $form  Form ID (slug)
	 * @param boolean $force Force validate without pre-checks
	 *
	 * @return bool true on success false on failure
	 */
	final public function reCaptchaValidate($form = null, $force = false) {
		if (!$force) {
			if ( ! $this->recaptcha || $this->status == 4 ) {
				return true;
			}
		}

		if ($this->recaptcha_verified != null) return $this->recaptcha_verified;

		if ( ! $form ) {
			$form = isset( $_REQUEST['action'] ) ? $_REQUEST['action'] : 'login';
		}

		$forms = array( // known pairs: form => specific plugin setting
			'lostpassword' => 'recaplost',
			'register'     => 'recapreg',
			'login'        => 'recaplogin',
			'comment'      => 'recapcom',
			'woologin'     => 'recapwoologin',
			'woolost'      => 'recapwoolost',
			'wooreg'       => 'recapwooreg',
		);

		if ( isset( $forms[ $form ] ) ) {
			if ( empty( $this->options[ $forms[ $form ] ] ) ) {
				return true; // no validation is required
			}
		}
		else {
			return true; // we don't know this form
		}

		if ( empty( $_POST['g-recaptcha-response'] ) ) {
			$this->reCaptchaFailed();
			return false;
		}

		$result = $this->reCaptchaRequest($_POST['g-recaptcha-response']);
		if ( ! $result ) {
			cerber_log( 42 );
			return false;
		}

		$result  = json_decode( $result );
		$result = obj_to_arr_deep( $result );

		if ( ! empty( $result['success'] ) ) {
			$this->recaptcha_verified = true;
			return true;
		}
		$this->recaptcha_verified = false;

		if ( ! empty( $result['error-codes'] ) ) {
			if ( in_array( 'invalid-input-secret', (array) $result['error-codes'] ) ) {
				cerber_log( 41 );
			}
		}

        $this->reCaptchaFailed();

		return false;
	}

	final function reCaptchaFailed() {
		cerber_log( 40 );
		if ($this->options['recaptcha-period'] && $this->options['recaptcha-number'] && $this->options['recaptcha-within']) {
			$remain = cerber_get_remain_count($this->remote_ip , true, 40, $this->options['recaptcha-number'], $this->options['recaptcha-within']);
			if ($remain < 1) cerber_block_add( $this->remote_ip, 5 );
		}
    }

	/**
	 * A form with possible reCAPTCHA has been submitted.
	 * Allow to process reCAPTCHA by setting a global flag.
	 * Must be called before reCaptchaValidate();
	 *
	 */
	final public function reCaptchaNow() {
		if ( $_SERVER['REQUEST_METHOD'] == 'POST' && $this->options['sitekey'] && $this->options['secretkey'] ) {
			$this->recaptcha = true;
		}
	}

	/**
	 * Make a request to the Google reCaptcha web service
	 * 
	 * @param string $response Google specific field from the submitted form (widget)
	 *
	 * @return bool|string Response of the Google service or false on failure
	 */
	final public function reCaptchaRequest($response = ''){

		if (!$response) {
			if (!empty($_POST['g-recaptcha-response'])) $response = $_POST['g-recaptcha-response'];
			else return false;
		}

		$curl = @curl_init(); // @since 4.32
		if (!$curl) {
			cerber_admin_notice(__( 'ERROR:', 'wp-cerber' ) .' Unable to initialize cURL');
		    return false;
		}

		$opt = curl_setopt_array($curl, array(
			CURLOPT_URL => GOO_RECAPTCHA_URL,
			CURLOPT_POST => true,
			CURLOPT_POSTFIELDS => array( 'secret' => $this->options['secretkey'], 'response' => $response ),
			CURLOPT_RETURNTRANSFER => true,
		));

		if (!$opt) {
			cerber_admin_notice(__( 'ERROR:', 'wp-cerber' ) .' '. curl_error($curl));
			curl_close($curl);
			return false;
		}

		$result = curl_exec($curl);
		if (!$result) {
			cerber_admin_notice(__( 'ERROR:', 'wp-cerber' ) .' '. curl_error($curl));
			$result = false;
		}
		curl_close($curl);

		return $result;

	}

	final public function reCaptchaMsg($context = null){
		return apply_filters( 'cerber_msg_recaptcha', __( 'Human verification failed. Please click the square box in the reCAPTCHA block below.', 'wp-cerber' ), $context);
	}

	/**
	 * Current IP has been already logged
	 */
	final public function setProcessed() {
		if ( ! isset( $this->processed ) ) {
			$this->processed = true;
		}
	}
	/**
	 * Is current IP has been already logged?
	 */
	final public function isProcessed() {
		if ( ! empty( $this->processed ) ) {
			return true;
		}
		return false;
	}
	final public function deleteGarbage() {
		global $wpdb;
		if ($this->garbage) return;
		$wpdb->query( 'DELETE FROM ' . CERBER_BLOCKS_TABLE . ' WHERE block_until < ' . time() );
		$this->garbage = true;
	}
}

global $wp_cerber;
$wp_cerber = new WP_Cerber();


/*
 * 
 * Initialize Cerber
 *  
 */
add_action( 'plugins_loaded', 'cerber_init', 1 );
function cerber_init() {
	global $wp_cerber;
	if ( ! is_object( $wp_cerber ) ) {
		$wp_cerber = new WP_Cerber();
	}
	if ( ! wp_next_scheduled( 'cerber_hourly' ) ) {
		wp_schedule_event( time(), 'hourly', 'cerber_hourly' );
	}
	if ( ! wp_next_scheduled( 'cerber_daily' ) ) {
		wp_schedule_event( time(), 'daily', 'cerber_daily' );
	}
}

/*
	Display login form if Custom login URL has been requested

*/
add_action( 'init', 'cerber_wp_login_page', 20 );
function cerber_wp_login_page() {
	global $wp_cerber;
	if ( $path = $wp_cerber->getSettings( 'loginpath' ) ) {
		$request = $_SERVER['REQUEST_URI'];
		if ( $pos = strpos( $request, '?' ) ) {
			//$request = explode( '?', $request );
			//$request = array_shift( $request );
			$request = substr( $request, 0, $pos - 1 ); // @since 4.8
		}
		$request = explode( '/', rtrim( $request, '/' ) );
		//$request = array_pop( $request );
		$request = end($request); // @since 4.8
		if ( $path == $request ) {
			require( ABSPATH . WP_LOGIN_SCRIPT ); // load default wp-login form
			exit;
		}
	}
}

/*
	Create message to show it above login form for any simply GET
*/
add_action( 'login_head', 'cerber_login_head' );
function cerber_login_head() {
	global $error, $wp_cerber;

	$wp_cerber->reCaptcha( 'style' );

	if ( $_SERVER['REQUEST_METHOD'] != 'GET' ) {
		return;
	}
	if ( ! cerber_can_msg() ) {
		return;
	}
	if ( ! cerber_is_allowed( $wp_cerber->getRemoteIp() ) ) {
		$error = $wp_cerber->getErrorMsg();
	} elseif ( $msg = $wp_cerber->getRemainMsg() ) {
		$error = $msg;
	}
}

/**
 * Control the process of authentication
 *
 * @since 2.9
 *
 */
remove_filter( 'authenticate', 'wp_authenticate_username_password', 20 );
add_filter( 'authenticate', 'cerber_auth_control', 20, 3 );
function cerber_auth_control( $null, $username, $password ) {
	global $wp_cerber;

	if ( ! $wp_cerber->reCaptchaValidate() ) {

		return new WP_Error( 'incorrect_recaptcha',
			'<strong>' . __( 'ERROR:', 'wp-cerber' ) . ' </strong>' .
			$wp_cerber->reCaptchaMsg('login'));
	}

	// Check for prohibited username
	if ( $wp_cerber->isProhibited( $username ) ) {
		cerber_log( 52, $username );
		cerber_block_add( null, 4, $username );

		// Create with message which is identical default WP
		return new WP_Error( 'incorrect_password', sprintf(
			__( '<strong>ERROR</strong>: The password you entered for the username %s is incorrect.' ),
			'<strong>' . $username . '</strong>'
		) );
	}

	$user = wp_authenticate_username_password( $null, $username, $password );

	// @since 4.18 it is replacement for 'wp_login_failed' action hook
	// see WP function wp_authenticate()
	$ignore_codes = array('empty_username', 'empty_password');
	if (is_wp_error($user) && !in_array($user->get_error_code(), $ignore_codes) ) {
		cerber_login_failed($username);
	}

	return $user;
}

// TODO: make sure that 'authenticate' filter should be used instead
/*
	Block authentication for existing user if IP is not allowed (blocked or locked out)
*/
add_filter( 'wp_authenticate_user', 'cerber_stop_authentication', 9999, 2 ); // fires after user found, with 'authenticate' filter
function cerber_stop_authentication( $user, $password ) {
	global $wp_cerber;
	if ( ! cerber_is_allowed() ) {
		status_header( 403 );
		$error = new WP_Error();
		$error->add( 'cerber_wp_error', $wp_cerber->getErrorMsg() );

		return $error;
	}

	return $user;
}

// Block prohibited usernames
// add_filter('illegal_user_logins',function(){ return cerber_get_options('prohibited'); });


/*
 * Handler for failed login attempts
 *
 */
//add_action( 'wp_login_failed', 'cerber_login_failed' ); // @since 4.18
function cerber_login_failed( $user_login ) {
	global $wpdb, $wp_cerber;

	$ip      = $wp_cerber->getRemoteIp();
	$acl     = cerber_acl_check( $ip );
	$no_user = false;

	if ( ! $wp_cerber->isProcessed() ) {
		if ( ! cerber_get_user( $user_login ) ) {
			$no_user = true;
		}

		if ( $no_user ) {
			$ac = 51;
		}
		elseif ( cerber_is_allowed( $ip ) ) {
			$ac = 7;
		}
		elseif ( $acl == 'B' ) {
			$ac = 14;
		}
		else {
			$ac = 13;
		}

		cerber_log( $ac, $user_login );

	}

	// White? Stop further actions.
	if ( $acl == 'W' && !$wp_cerber->getSettings( 'limitwhite' )) {
		return;
	}

	if ( $wp_cerber->getSettings( 'usefile' ) ) {
		cerber_file_log( $user_login, $ip );
	}

	if ( ! defined( 'DOING_AJAX' ) || ! DOING_AJAX ) { // Needs additional researching and, maybe, refactoring
		status_header( 403 );
	}

	// Blacklisted? No more actions are needed.
	if ( $acl == 'B' ) {
		return;
	}

	// Must the Citadel mode be activated?
	if ( $wp_cerber->getSettings( 'ciperiod' ) && ! cerber_is_citadel() ) {
		$range    = time() - $wp_cerber->getSettings( 'ciperiod' ) * 60;
		$lockouts = $wpdb->get_var( 'SELECT count(ip) FROM ' . CERBER_LOG_TABLE . ' WHERE activity IN (7,51,52) AND stamp > ' . $range );
		if ( $lockouts >= $wp_cerber->getSettings( 'cilimit' ) ) {
			cerber_enable_citadel();
		}
	}

	/*
	if ( $wp_cerber->isProcessed() ) {
		return;
	}
    */

    if ( $no_user && $wp_cerber->getSettings( 'nonusers' ) ) {
		cerber_block_add( $ip, 3, $user_login, null, false );
	}
	elseif ( cerber_get_remain_count($ip, false) < 1 ) { //Limit on the number of login attempts is reached
		cerber_block_add( $ip, 1, '', null, false);
	}

}


// Registration -----------------------------------------------------------------------

add_filter( 'registration_errors', 'cerber_reg_errors', 10, 3 );
function cerber_reg_errors( $errors, $sanitized_user_login, $user_email ) {
	global $wp_cerber;
	if ( ! $wp_cerber->reCaptchaValidate() ) {
		$error = new WP_Error();
		$error->add( 'incorrect_recaptcha', '<strong>' . __( 'ERROR:', 'wp-cerber' ) . ' </strong>' .
			$wp_cerber->reCaptchaMsg('register'));
		return $error;
	}
	if ( $wp_cerber->isProhibited( $sanitized_user_login ) ) {
		$error = new WP_Error();
		$error->add( 'incorrect_login',
			'<strong>' . __( 'ERROR:', 'wp-cerber' ) . ' </strong>' .
			apply_filters( 'cerber_msg_prohibited', __( 'Username is not allowed. Please choose another one.', 'wp-cerber' ), 'register' ) );
		return $error;
	}

	return $errors;
}

add_filter( 'option_users_can_register', function ( $value ) {
	if ( ! cerber_is_allowed() ) {
		return false;
	}

	return $value;
}, 9999 );


// Lost password form --------------------------------------------------------------------

/**
 * Validate reCAPTCHA for the WordPress lost password form
 */
add_action( 'login_form_' . 'lostpassword', 'cerber_lost_captcha' );
function cerber_lost_captcha() {
	global $wp_cerber, $cerber_lost;
	if ( ! $wp_cerber->reCaptchaValidate() ) {
		$_POST['user_login'] = null; // workaround due to lack of any way to control lost password form
		$cerber_lost = '<strong>' . __( 'ERROR:', 'wp-cerber' ) . ' </strong>' . $wp_cerber->reCaptchaMsg('lostpassword');
	}
}
/**
 * Display message on the WordPress lost password form screen
 */
add_action( 'lostpassword_form', 'cerber_lost_show_msg' );
function cerber_lost_show_msg() {
	global $cerber_lost;
	if ( ! $cerber_lost ) {
		return;
	}
	?>
	<script type="text/javascript">
		//document.getElementById('login_error').style.visibility = "hidden";
		document.getElementById('login_error').innerHTML = "<?php echo $cerber_lost; ?>";
	</script>
	<?php
}

// Messages ----------------------------------------------------------------------

/**
 * Replace ANY system messages or add notify message above login form if IP is not allowed (blocked or locked out)
 */
add_filter( 'login_errors', 'cerber_login_errors' ); // hook on POST if credentials was wrong
function cerber_login_errors( $errors ) {
	global $error, $wp_cerber;
	if ( cerber_can_msg() ) {
		if ( ! cerber_is_allowed( $wp_cerber->getRemoteIp() ) ) {
			$errors = $wp_cerber->getErrorMsg();
		} // replace for error msg
		elseif ( ( $msg = $wp_cerber->getRemainMsg() ) && ! $error ) {
			$errors .= '<p>' . $msg;
		} // add for informative msg
	}

	return $errors;
}

add_filter( 'shake_error_codes', 'cerber_login_failure_shake' ); // Shake it, baby!
function cerber_login_failure_shake( $shake_error_codes ) {
	$shake_error_codes[] = 'cerber_wp_error';

	return $shake_error_codes;
}

/*
	Replace default login/logout URL with Custom login page URL
*/
add_filter( 'site_url', 'cerber_login_logout', 9999, 4 );
add_filter( 'network_site_url', 'cerber_login_logout', 9999, 3 );
function cerber_login_logout( $url, $path, $scheme, $blog_id = 0 ) { // $blog_id only for 'site_url'
	global $wp_cerber;
	if ( $login_path = $wp_cerber->getSettings( 'loginpath' ) ) {
		$url = str_replace( WP_LOGIN_SCRIPT, $login_path . '/', $url );
	}

	return $url;
}

/*
	Replace default logout redirect URL with Custom login page URL 
*/
add_filter( 'wp_redirect', 'cerber_redirect', 9999, 2 );
function cerber_redirect( $location, $status ) {
	global $wp_cerber;
	if ( ($path = $wp_cerber->getSettings( 'loginpath' )) && ( 0 === strpos( $location, WP_LOGIN_SCRIPT . '?' ) ) ) {
		$loc      = explode( '?', $location );
		$location = get_home_url() . '/' . $path . '/?' . $loc[1];
	}

	return $location;
}

// Access control ========================================================================================

/*
	Direct access to the restricted WP php scripts - what will we do?
*/
add_action( 'init', 'cerber_access_control' );
function cerber_access_control() {
	global $wp_cerber;

	if ( is_admin() ) {
		return;
	}

	// IPs from White List are allowed
	$acl = cerber_acl_check();
	if ( $acl == 'W' ) {
		return;
	}
	elseif ( $acl == 'B' || cerber_block_check() ) {
		$deny = true;
	}
	else {
		$deny = false;
	}

	$opt    = $wp_cerber->getSettings();
	$script = substr( strrchr( $_SERVER['SCRIPT_NAME'], '/' ), 1 );

	if ( $script ) {
		if ( $script == WP_LOGIN_SCRIPT || $script == WP_SIGNUP_SCRIPT || ( $script == WP_REG_SCRIPT && ! get_option( 'users_can_register' ) ) ) { // no direct access
			if ( ! empty( $opt['wplogin'] ) ) {
				cerber_log( 50 );
				cerber_soft_block_add( $wp_cerber->getRemoteIp(), 2, $script );
				//cerber_block_add( $wp_cerber->getRemoteIp(), __( 'Attempt to access', 'wp-cerber' ) . ' ' . $script );
			}
			if ( $deny || ! empty( $opt['loginnowp'] ) ) {
				cerber_404_page();
			}
		} elseif ( $script == WP_XMLRPC_SCRIPT || $script == WP_TRACKBACK_SCRIPT ) { // no direct access
			if ( $deny || ! empty( $opt['xmlrpc'] ) ) {
				cerber_404_page();
			}
		}
	}

	if ( $deny || ! empty( $opt['norest'] ) ) {
		cerber_block_rest();
	}

	if ( $deny || ! empty( $opt['xmlrpc'] ) ) {
		add_filter( 'xmlrpc_enabled', '__return_false' );
		add_filter( 'pings_open', '__return_false' );
		add_filter( 'bloginfo_url', 'cerber_pingback_url', 10, 2 );
		remove_action( 'wp_head', 'rsd_link', 10 );
		remove_action( 'wp_head', 'wlwmanifest_link', 10 );
	}

	if ( $deny || ! empty( $opt['nofeeds'] ) ) {
		remove_action( 'wp_head', 'feed_links', 2 );
		remove_action( 'wp_head', 'feed_links_extra', 3 );

		remove_action( 'do_feed_rdf', 'do_feed_rdf', 10 );
		remove_action( 'do_feed_rss', 'do_feed_rss', 10 );
		remove_action( 'do_feed_rss2', 'do_feed_rss2', 10 );
		remove_action( 'do_feed_atom', 'do_feed_atom', 10 );
		remove_action( 'do_pings', 'do_all_pings', 10 );

		add_action( 'do_feed_rdf', 'cerber_404_page', 1 );
		add_action( 'do_feed_rss', 'cerber_404_page', 1 );
		add_action( 'do_feed_rss2', 'cerber_404_page', 1 );
		add_action( 'do_feed_atom', 'cerber_404_page', 1 );
		add_action( 'do_feed_rss2_comments', 'cerber_404_page', 1 );
		add_action( 'do_feed_atom_comments', 'cerber_404_page', 1 );
	}
}

/*
 * Disable pingback URL (hide from HEAD)
 */
function cerber_pingback_url( $output, $show ) {
	if ( $show == 'pingback_url' ) {
		$output = '';
	}

	return $output;
}

/**
 * Disable REST API
 *
 */
function cerber_block_rest() {
	// OLD
	add_filter( 'json_enabled', '__return_false' );
	add_filter( 'json_jsonp_enabled', '__return_false' );
	// 4.4
	add_filter( 'rest_enabled', '__return_false', 9999 );
	// 4.7
	add_filter( 'rest_jsonp_enabled', '__return_false' );
	// Links
	remove_action( 'wp_head', 'rest_output_link_wp_head', 10 );
	remove_action( 'template_redirect', 'rest_output_link_header', 11 );
	// Default REST API hooks from default-filters.php
	remove_action( 'init', 'rest_api_init' );
	remove_action( 'rest_api_init', 'rest_api_default_filters', 10 );
	remove_action( 'rest_api_init', 'register_initial_settings', 10 );
	remove_action( 'rest_api_init', 'create_initial_rest_routes', 99 );
	remove_action( 'parse_request', 'rest_api_loaded' );

	if ( cerber_is_rest_url() ) {
		cerber_404_page();
	}
}

/*
 * Redirection control: standard admin/login redirections
 *
 */
add_filter( 'wp_redirect', 'cerber_no_redirect', 10, 2 );
function cerber_no_redirect( $location, $status ) {
	global $current_user, $wp_cerber;
	if ( $current_user->ID == 0 && $wp_cerber->getSettings( 'noredirect' ) ) {
		$str = 'redirect_to=' . urlencode( admin_url() );
		if ( strpos( $location, $str ) ) {
			cerber_404_page();
		}
	}

	return $location;
}
/*
 * Redirection control: no default aliases for redirections
 *
 */
if ( $wp_cerber->getSettings( 'noredirect' ) ) {
	remove_action( 'template_redirect', 'wp_redirect_admin_locations', 1000 );
}
/*
 * Stop user enumeration
 *
 */
add_action( 'template_redirect', 'cerber_canonical', 1 );
function cerber_canonical() {
	global $wp_cerber;
	if ( $wp_cerber->getSettings( 'stopenum' ) ) {
		if ( ! is_admin() && ! empty( $_GET['author'] ) ) {
			cerber_404_page();
		}
	}
}
/*
if ( $wp_cerber->getSettings( 'hashauthor' ) ) {
	add_filter( 'request',
		function ( $vars ) {
			if (isset($vars['author_name']) && !is_admin()) {
				$vars['author_name'] = '><';
			}

			return $vars;
		} );
}
*/

/*
	Can login form message be shown?
*/
function cerber_can_msg() {
	if ( ! isset( $_REQUEST['action'] ) ) {
		return true;
	}
	if ( $_REQUEST['action'] == 'login' ) {
		return true;
	}

	return false;
	//if ( !in_array( $action, array( 'postpass', 'logout', 'lostpassword', 'retrievepassword', 'resetpass', 'rp', 'register', 'login' );
}


// Cookies ---------------------------------------------------------------------------------
/*
	Mark user with groove
	@since 1.3
*/
add_action( 'auth_cookie_valid', 'cerber_cookie1', 10, 2 );
function cerber_cookie1( $cookie_elements = null, $user = null ) {
	global $current_user;
	if ( ! $user ) {
		$user = wp_get_current_user();
	}
	$expire = time() + apply_filters( 'auth_cookie_expiration', 14 * 24 * 3600, $user->ID, true ) + ( 24 * 3600 );
	cerber_set_cookie( $expire );
}

/*
	Mark switched user with groove
	@since 1.6
*/
add_action( 'set_logged_in_cookie', 'cerber_cookie2', 10, 5 );
function cerber_cookie2( $logged_in_cookie, $expire, $expiration, $user_id, $logged_in ) {
	cerber_set_cookie( $expire );
}

function cerber_set_cookie( $expire ) {
	if ( ! headers_sent() ) {
		setcookie( 'cerber_groove', cerber_get_groove(), $expire + 1, COOKIEPATH );
	}
}

/*
	Mark current user when they logged out
	@since 1.0
*/
add_action( 'wp_logout', 'cerber_clear_cookie' );
function cerber_clear_cookie() {
	if ( ! headers_sent() ) {
		setcookie( 'cerber_logout', 'ok', time() + 24 * 3600, COOKIEPATH );
	}
}

/*
	Track BAD cookies with non-existence user or bad password (hash)
*/
add_action( 'auth_cookie_bad_username', 'cerber_cookie_bad' );
add_action( 'auth_cookie_bad_hash', 'cerber_cookie_bad' );
function cerber_cookie_bad( $cookie_elements ) {
	cerber_login_failed( $cookie_elements['username'] );
	wp_clear_auth_cookie();
}

/*
	Block authentication by cookie if IP is not allowed (blocked or locked out)
*/
add_action( 'plugins_loaded', 'cerber_stop_cookies' );
function cerber_stop_cookies( $cookie_elements ) {
	if ( cerber_check_groove() ) {
		return;
	} // keep already logged in users
	if ( ! cerber_is_allowed() ) {
		wp_clear_auth_cookie();
	}
}

/*
	Get special Cerber Sign for using with cookies
*/
function cerber_get_groove() {
	$groove = get_site_option( 'cerber-groove' );
	if ( empty( $groove ) ) {
		$groove = wp_generate_password( 16, false );
		update_site_option( 'cerber-groove', $groove );
	}

	return md5( $groove );
}

/*
	Check if special Cerber Sign valid
*/
function cerber_check_groove( $hash = '' ) {
	if ( ! $hash ) {
		if ( ! isset( $_COOKIE['cerber_groove'] ) ) {
			return false;
		}
		$hash = $_COOKIE['cerber_groove'];
	}
	$groove = get_site_option( 'cerber-groove' );
	if ( $hash == md5( $groove ) ) {
		return true;
	}

	return false;
}

/**
 * Set user session expiration
 *
 */
add_filter( 'auth_cookie_expiration', function ( $expire ) {
	global $wp_cerber;
	$time = $wp_cerber->getSettings( 'auth_expire' );
	if ( $time ) {
		$expire = 60 * $time;
	}

	return $expire;
} );

//  Track various activity -------------------------------------------------------------------------

add_action( 'wp_login', 'cerber_log_login', 10, 2 );
function cerber_log_login( $login, $user ) {
	if ( ! empty( $_POST['log'] ) ) { // default WP form
		$user_login = htmlspecialchars($_POST['log']);
	} else {
		$user_login = $login;
	}
	cerber_log( 5, $user_login, $user->ID, null );
}

add_action( 'wp_logout', 'cerber_log_logout' );
function cerber_log_logout() {
	global $user_ID;
	if ( ! $user_ID ) {
		$user    = wp_get_current_user();
		$user_ID = $user->ID;
	}
	cerber_log( 6, '', $user_ID, null );
}

//add_action( 'lostpassword_post', 'cerber_password_post' );
add_action( 'retrieve_password', 'cerber_password_post' );
function cerber_password_post( $user_login ) {
	cerber_log( 21, $user_login );
}

add_action( 'password_reset', 'cerber_password_reset' );
function cerber_password_reset( $user ) {
	cerber_log( 20, $user->user_login, $user->ID );
}

add_action( 'register_new_user', 'cerber_log_reg' );
function cerber_log_reg( $user_id ) {
	$user = get_user_by( 'ID', $user_id );
	cerber_log( 2, $user->user_login, $user_id );
}

add_action( 'edit_user_created_user', 'cerber_log_create', 10, 2 );
function cerber_log_create( $user_id, $notify = null ) {
	$user = get_user_by( 'ID', $user_id );
	cerber_log( 1, $user->user_login, $user_id );
}

// Lockouts routines ---------------------------------------------------------------------

/**
 * Lock out IP address if it is an alien IP only (browser does not have valid Cerber groove)
 *
 * @param $ip string IP address to block
 * @param integer $reason_id ID of reason of blocking
 * @param string $details Reason of blocking
 * @param null $duration Duration of blocking
 *
 * @return bool|false|int
 */
function cerber_soft_block_add( $ip, $reason_id, $details = '', $duration = null ) {
	if ( cerber_check_groove() ) {
		return false;
	}

	return cerber_block_add( $ip, $reason_id, $details, $duration );
}

/**
 * Lock out IP address
 *
 * @param $ip string IP address to block
 * @param integer $reason_id ID of reason of blocking
 * @param string $details Reason of blocking
 * @param int $duration Duration of blocking
 * @param bool $check_acl Check for ACL
 *
 * @return bool|false|int
 */
function cerber_block_add( $ip, $reason_id = 1, $details = '', $duration = null, $check_acl = true ) {
	global $wpdb, $wp_cerber;

	//$wp_cerber->setProcessed();

	if (cerber_get_block($ip)) return false;

	if ( empty($ip) ) {
		$ip = $wp_cerber->getRemoteIp();
	}

	if ( $check_acl && cerber_acl_check( $ip ) ) {
        return false;
	}

	$ip_address = $ip;

	if ( $wp_cerber->getSettings( 'cerberlab' ) ) {
		lab_save_push( $ip, $reason_id, $details );
	}

	if ( $wp_cerber->getSettings( 'subnet' ) ) {
		$ip       = cerber_get_subnet( $ip );
		$activity = 11;
	} else {
		$activity = 10;
	}

	if ( $wpdb->get_var( $wpdb->prepare( 'SELECT count(ip) FROM ' . CERBER_BLOCKS_TABLE . ' WHERE ip = %s', $ip ) ) ) {
		return false;
	}

	$reason = cerber_get_reason( $reason_id );
	if ($details) $reason .= ': <b>' . $details . '</b>';

	if ( ! $duration ) {
		$duration = cerber_calc_duration( $ip );
	}
	$until = time() + $duration;

	//$result = $wpdb->query($wpdb->prepare('INSERT INTO '. CERBER_BLOCKS_TABLE . ' (ip,block_until,reason) VALUES (%s,%d,%s)',$ip,$until,$reason));
	$result = $wpdb->insert( CERBER_BLOCKS_TABLE, array(
		'ip'          => $ip,
		'block_until' => $until,
		'reason'      => $reason
	), array( '%s', '%d', '%s' ) );

	if ( $result ) {
		cerber_log( $activity, null, null, $ip_address );
		do_action( 'cerber_ip_locked', array( 'IP' => $ip_address, 'reason' => $reason ) );
		$result = true;
	}
	else {
		cerber_db_error_log();
		$result = false;
	}

	if ( $wp_cerber->getSettings( 'notify' ) ) {
		//$count = $wpdb->get_var( 'SELECT count(ip) FROM ' . CERBER_BLOCKS_TABLE );
		$count = cerber_blocked_num();
		if ( $count > $wp_cerber->getSettings( 'above' ) ) {
			cerber_send_notify( 'lockout', '', $ip_address );
		}
	}

	return $result;
}

function cerber_block_delete( $ip ) {
	global $wpdb;

	return $wpdb->query( $wpdb->prepare( 'DELETE FROM ' . CERBER_BLOCKS_TABLE . ' WHERE ip = %s', $ip ) );
}


/**
 *
 * Check if an IP address is currently blocked. With C subnet also.
 *
 * @param string $ip an IP address
 *
 * @return bool true if IP is locked out
 */
function cerber_block_check( $ip = '' ) {

	// @since 4.8
	if (cerber_get_block($ip)) return true;

	return false;
}

/**
 *
 * Return the lockout row for an IP if it is blocked. With C subnet also.
 *
 * @param string $ip an IP address
 *
 * @return object|bool object if IP is locked out, false otherwise
 */
function cerber_get_block( $ip = '' ) {
	global $wpdb, $wp_cerber;
	if ( ! $ip ) {
		$ip = $wp_cerber->getRemoteIp();
	}

	// @since 4.7
	if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
		return false;
	}

	$where = ' WHERE ip = "' . $ip . '"';
	if ( cerber_is_ipv4( $ip ) ) {
		$subnet = cerber_get_subnet( $ip );
		$where  .= ' OR ip = "' . $subnet . '"';
	}
	if ( $ret = $wpdb->get_row( 'SELECT * FROM ' . CERBER_BLOCKS_TABLE . $where ) ) {
		return $ret;
	}

	return false;
}

// TODO: replace all entrance of $count = $wpdb->get_var('SELECT count(ip) FROM '. CERBER_BLOCKS_TABLE ); with this function
/**
 * Return the number of currently locked out IPs
 *
 * @return int the number of currently locked out IPs
 * @since 3.0
 */
function cerber_blocked_num(){
	global $wpdb;
	$count = $wpdb->get_var('SELECT count(ip) FROM '. CERBER_BLOCKS_TABLE );
	return absint($count);
}

/*
	Calculation duration of blocking (lockout) IP address based on settings & rules.
*/
function cerber_calc_duration( $ip ) {
	global $wpdb, $wp_cerber;
	$range    = time() - $wp_cerber->getSettings( 'aglast' ) * 3600;
	$lockouts = $wpdb->get_var( $wpdb->prepare( 'SELECT count(ip) FROM ' . CERBER_LOG_TABLE . ' WHERE ip = %s AND activity IN (10,11) AND stamp > %d', $ip, $range ) );
	if ( $lockouts >= $wp_cerber->getSettings( 'aglocks' ) ) {
		return $wp_cerber->getSettings( 'agperiod' ) * 3600;
	}

	return $wp_cerber->getSettings( 'lockout' ) * 60;
}

/**
 * Calculation of remaining attempts
 *
 * @param $ip string an IP address
 * @param $check_acl bool if true will check the White IP ACL first
 * @param $activity string  comma-separated list of activity IDs to calculate for
 * @param $allowed int  Allowed attempts within $period
 * @param $period int  Period for count attempts
 *
 * @return int Allowed attempts for now
 */
function cerber_get_remain_count( $ip = '', $check_acl = true, $activity = '7,51,52', $allowed = null, $period = null ) {
	global $wpdb, $wp_cerber;
	if ( ! $ip ) {
		$ip = $wp_cerber->getRemoteIp();
	}

	if (!$allowed) $allowed = $wp_cerber->getSettings( 'attempts' );

	if ( $check_acl && cerber_acl_check( $ip, 'W' ) ) {
		return $allowed; // whitelist = infinity attempts
	}

	//if (!is_string($activity)) $activity = (string)$activity;

	if (!$period) $period = $wp_cerber->getSettings( 'period' );

	$range    = time() - $period * 60;
	$attempts = $wpdb->get_var( $wpdb->prepare( 'SELECT count(ip) FROM ' . CERBER_LOG_TABLE . ' WHERE ip = %s AND activity IN (%s) AND stamp > %d', $ip, $activity, $range ) );

	if ( ! $attempts ) {
		return $allowed;
	}
	else {
		$ret = $allowed - $attempts;
	}
	$ret = $ret < 0 ? 0 : $ret;

	return $ret;
}

/**
 * Is a given IP is allowed to do restricted things?
 * Here Cerber makes its decision.
 *
 * @param null $ip
 *
 * @return bool
 */
function cerber_is_allowed( $ip = null ) {
	global $wp_cerber;

	if ( ! $ip ) {
		$ip = $wp_cerber->getRemoteIp();
	}
	if (!filter_var( $ip, FILTER_VALIDATE_IP )) return false;

	// @since 4.7.9
	if ( cerber_block_check( $ip ) ) {
		return false;
	}

	$tag = cerber_acl_check( $ip );
	if ( $tag == 'W' ) {
		return true;
	}
	if ( $tag == 'B' ) {
		return false;
	}

	/* @since 4.7.9
	if ( cerber_block_check( $ip ) ) {
		return false;
	}*/

	if ( cerber_is_citadel() ) {
		return false;
	}

	return true;
}

// Access lists (ACL) routines --------------------------------------------------------------------------------

/**
 * Add IP to specified access list
 *
 * @param $ip string|array single IP address, string with IP network, range or associative range array
 * @param $tag string 'B'|'W'
 *
 * @return bool|int Result of operation
 */
function cerber_acl_add( $ip, $tag ) {
	global $wpdb;
	if ( is_string( $ip ) ) {
		if ( $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(ip) FROM ' . CERBER_ACL_TABLE . ' WHERE ip = %s', $ip ) ) ) {
			return false;
		}
		$range = cerber_any2range( $ip );
		if ( is_array( $range ) ) {
			$begin = $range['begin'];
			$end   = $range['end'];
		} else {
			$begin = ip2long( $ip );
			$end   = ip2long( $ip );
		}

		return $wpdb->query( $wpdb->prepare( 'INSERT INTO ' . CERBER_ACL_TABLE . ' (ip, ip_long_begin, ip_long_end,tag) VALUES (%s,%d,%d,%s)', $ip, $begin, $end, $tag ) );
		//cerber_db_error_log();
	}
	elseif ( is_array( $ip ) ) {
		$range = $ip['range'];
		$begin = $ip['begin'];
		$end   = $ip['end'];
		if ( $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(ip) FROM ' . CERBER_ACL_TABLE . ' WHERE ip_long_begin = %d AND ip_long_end = %d', $begin, $end ) ) ) {
			return false;
		}

		return $wpdb->query( $wpdb->prepare( 'INSERT INTO ' . CERBER_ACL_TABLE . ' (ip, ip_long_begin, ip_long_end, tag) VALUES (%s,%d,%d,%s)', $range, $begin, $end, $tag ) );
	}

	return false;
}

function cerber_add_white( $ip ) {
	return cerber_acl_add( $ip, 'W' );
}

function cerber_add_black( $ip ) {
	return cerber_acl_add( $ip, 'B' );
}

function cerber_acl_remove( $ip ) {
	global $wpdb;
	if ( is_string( $ip ) ) {
		return $wpdb->query( $wpdb->prepare( 'DELETE FROM ' . CERBER_ACL_TABLE . ' WHERE ip = %s ', $ip ) );
	} elseif ( is_array( $ip ) ) {
		return $wpdb->query( $wpdb->prepare( 'DELETE FROM ' . CERBER_ACL_TABLE . ' WHERE ip_long_begin = %d AND ip_long_end = %d', $ip['begin'], $ip['end'] ) );
	}

	return false;
}

/**
 * Check ACL for given IP. Some extra lines for performance reason.
 *
 * @param string $ip
 * @param string $tag
 *
 * @return bool|string
 */
function cerber_acl_check( $ip = null, $tag = '' ) {
	global $wpdb, $wp_cerber;
	if ( ! $ip ) {
		$ip = $wp_cerber->getRemoteIp();
	}

	if ( ! cerber_is_ipv4( $ip ) ) {
		return cerber_acl_checkV6( $ip, $tag );
	}

	$long = ip2long( $ip );

	if ( $tag ) {
		if ( $tag != 'W' && $tag != 'B' ) return false;
		if ( $wpdb->get_var( 'SELECT ip FROM ' . CERBER_ACL_TABLE . ' WHERE ip_long_begin <= '.$long.' AND '.$long.' <= ip_long_end AND tag = "'.$tag.'" LIMIT 1' )  ) {
			return true;
		}
		return false;
	}
	else {
		/*if ( $ret = $wpdb->get_var( 'SELECT tag FROM ' . CERBER_ACL_TABLE . ' WHERE ip_long_begin <= ' . $long . ' AND ' . $long . ' <= ip_long_end' ) ) {
			return $ret;
		}*/
		if ( $ret = $wpdb->get_var( 'SELECT tag FROM ' . CERBER_ACL_TABLE . ' WHERE ip_long_begin <= ' . $long . ' AND ' . $long . ' <= ip_long_end AND tag = "W" LIMIT 1' ) ) {
			return $ret;
		}
		if ( $ret = $wpdb->get_var( 'SELECT tag FROM ' . CERBER_ACL_TABLE . ' WHERE ip_long_begin <= ' . $long . ' AND ' . $long . ' <= ip_long_end AND tag = "B" LIMIT 1' ) ) {
			return $ret;
		}

		return false;
	}
}

/**
 * IPv6 version of cerber_acl_check() without subnets and ranges
 *
 * @param null $ip
 * @param string $tag
 *
 * @return bool|null|string
 */
function cerber_acl_checkV6( $ip = null, $tag = '' ) {
	global $wpdb, $wp_cerber;
	if ( ! $ip ) {
		$ip = $wp_cerber->getRemoteIp();
	}
	if ( $tag ) {
		if ( $wpdb->get_var( $wpdb->prepare( 'SELECT count(ip) FROM ' . CERBER_ACL_TABLE . ' WHERE ip = %s AND tag = %s', $ip, $tag ) ) ) {
			return true;
		}

		return false;
	} else {
		if ( $ret = $wpdb->get_var( $wpdb->prepare( 'SELECT tag FROM ' . CERBER_ACL_TABLE . ' WHERE ip = %s', $ip ) ) ) {
			return $ret;
		}

		return false;
	}
}

/*
 * Logging directly to the file
 *
 * CERBER_FAIL_LOG optional, full path including filename to the log file
 * CERBER_LOG_FACILITY optional, use to specify what type of program is logging the messages
 *
 * */
function cerber_file_log( $user_login, $ip ) {
	if ( defined( 'CERBER_FAIL_LOG' ) ) {
		if ( $log = @fopen( CERBER_FAIL_LOG, 'a' ) ) {
			$pid = absint( @posix_getpid() );
			@fwrite( $log, date( 'M j H:i:s ' ) . $_SERVER['SERVER_NAME'] . ' Cerber(' . $_SERVER['HTTP_HOST'] . ')[' . $pid . ']: Authentication failure for ' . $user_login . ' from ' . $ip . "\n" );
			@fclose( $log );
		}
	} else {
		@openlog( 'Cerber(' . $_SERVER['HTTP_HOST'] . ')', LOG_NDELAY | LOG_PID, defined( 'CERBER_LOG_FACILITY' ) ? CERBER_LOG_FACILITY : LOG_AUTH );
		@syslog( LOG_NOTICE, 'Authentication failure for ' . $user_login . ' from ' . $ip );
		@closelog();
	}
}

/*
	Return wildcard - string like subnet Class C
*/
function cerber_get_subnet( $ip ) {
	return preg_replace( '/\.\d{1,3}$/', '.*', $ip );
}

/*
	Check if given IP address or wildcard or CIDR is valid
*/
function cerber_is_ip_or_net( $ip ) {
	if ( @inet_pton( $ip ) ) {
		return true;
	}
	// WILDCARD: 192.168.1.*
	$ip = str_replace( '*', '0', $ip );
	if ( @inet_pton( $ip ) ) {
		return true;
	}
	// CIDR: 192.168.1/24
	if ( strpos( $ip, '/' ) ) {
		$cidr = explode( '/', $ip );
		$net  = $cidr[0];
		$mask = absint( $cidr[1] );
		$dots = substr_count( $net, '.' );
		if ( $dots < 3 ) {
			if ( $dots == 1 ) {
				$net .= '.0.0';
			} elseif ( $dots == 2 ) {
				$net .= '.0';
			}
		}
		if ( ! cerber_is_ipv4( $net ) ) {
			return false;
		}
		if ( ! is_numeric( $mask ) ) {
			return false;
		}

		return true;
	}

	return false;
}

/**
 * Tries to recognize single IP address or IP v4 range (with dash) in a given string.
 *
 * @param string $string String to recognize IP address in
 *
 * @return array|bool|string Return single IP address or wildcard or CIDR as a string, and IP range as an array.
 */
function cerber_parse_ip( $string = '' ) {
	$string = trim( $string );
	if ( cerber_is_ip_or_net( $string ) ) {
		return $string;
	}
	$explode = explode( '-', $string );
	if ( ! is_array( $explode ) || ! $explode ) {
		return false;
	}
	$range = array();
	$count = 0;
	foreach ( $explode as $ip ) {
		$ip = trim( $ip );
		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			$range[] = $ip;
			$count ++;
			if ( $count >= 2 ) {
				break;
			}
		}
	}
	if ( count( $range ) < 2 ) {
		return false;
	}
	if ( ip2long( $range[1] ) <= ip2long( $range[0] ) ) {
		return false;
	}

	return array(
		'range'    => $range[0] . ' - ' . $range[1],
		'begin_ip' => $range[0],
		'end_ip'   => $range[1],
		'begin'    => ip2long( $range[0] ),
		'end'      => ip2long( $range[1] ),
	);
}

/**
 * Convert a network wildcard string like x.x.x.* to an IP v4 range
 *
 * @param $wildcard string
 *
 * @return array|bool|string False if no wildcard found, otherwise result of cerber_parse_ip()
 */
function cerber_wildcard2range( $wildcard = '' ) {
	$begin = str_replace( '*', '0', $wildcard );
	$end   = str_replace( '*', '255', $wildcard );
	if ( ! cerber_is_ipv4( $begin ) ) {
		return false;
	}
	if ( ! cerber_is_ipv4( $end ) ) {
		return false;
	}

	return cerber_parse_ip( $begin . ' - ' . $end );
}

/**
 * Convert a CIDR to an IP v4 range
 *
 * @param $cidr string
 *
 * @return array|bool|string
 */
function cerber_cidr2range( $cidr = '' ) {
	if ( ! strpos( $cidr, '/' ) ) {
		return false;
	}
	$cidr = explode( '/', $cidr );
	$net  = $cidr[0];
	$mask = absint( $cidr[1] );
	$dots = substr_count( $net, '.' );
	if ( $dots < 3 ) { // not completed CIDR
		if ( $dots == 1 ) {
			$net .= '.0.0';
		} elseif ( $dots == 2 ) {
			$net .= '.0';
		}
	}
	if ( ! cerber_is_ipv4( $net ) ) {
		return false;
	}
	if ( ! is_numeric( $mask ) ) {
		return false;
	}
	$begin = long2ip( ( ip2long( $net ) ) & ( ( - 1 << ( 32 - (int) $mask ) ) ) );
	$end   = long2ip( ( ip2long( $net ) ) + pow( 2, ( 32 - (int) $mask ) ) - 1 );

	return cerber_parse_ip( $begin . ' - ' . $end );
}

/**
 * Try to recognize an IP range or a single IP in a string.
 *
 * @param $string string  Network wildcard, CIDR or IP range.
 *
 * @return array|bool|string
 */
function cerber_any2range( $string = '' ) {
	// Do not change the order!
	$ret = cerber_wildcard2range( $string );
	if ( ! $ret ) {
		$ret = cerber_cidr2range( $string );
	}
	if ( ! $ret ) {
		$ret = cerber_parse_ip( $string ); // must be last due to checking for cidr and wildcard
	}

	return $ret;
}

/*
	Check for given IP address or subnet belong to this session.
*/
function cerber_is_myip( $ip ) {
	global $wp_cerber;
	if ( ! is_string( $ip ) ) {
		return false;
	}
	$remote_ip = $wp_cerber->getRemoteIp();
	if ( $ip == $remote_ip ) {
		return true;
	}
	if ( $ip == cerber_get_subnet( $remote_ip ) ) {
		return true;
	}

	return false;
}

function cerber_is_ip_in_range( $range, $ip = null ) {
	global $wp_cerber;
	if ( ! is_array( $range ) ) {
		return false;
	}
	if ( ! $ip ) {
		$ip = $wp_cerber->getRemoteIp();
	}
	$long = ip2long( $ip );
	if ( $range['begin'] <= $long && $long <= $range['end'] ) {
		return true;
	}

	return false;
}

/*
	Display 404 page to bump bots and bad guys
*/
function cerber_404_page() {
	global $wp_query, $wp_cerber;
	status_header( '404' );
	$wp_query->set_404();
	if (0 == $wp_cerber->getSettings('page404') && $template = get_404_template() ) {
		include( $template );
	}
	//if (file_exists(TEMPLATEPATH.'/404.php')) include(TEMPLATEPATH.'/404.php');
	//get_template_part('404');
	else {
		header( 'HTTP/1.0 404 Not Found', true, 404 );
		echo '<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL ' . esc_url( $_SERVER['REQUEST_URI'] ) . ' was not found on this server.</p></body></html>';
	}
	exit;
}

// Citadel mode -------------------------------------------------------------------------------------

function cerber_enable_citadel() {
	global $wp_cerber;
	if ( get_transient( 'cerber_citadel' ) ) {
		return;
	}
	set_transient( 'cerber_citadel', true, $wp_cerber->getSettings( 'ciduration' ) * 60 );
	cerber_log( 12 );

	// Notify admin
	if ( $wp_cerber->getSettings( 'cinotify' ) ) {
		cerber_send_notify( 'citadel' );
	}
}

function cerber_disable_citadel() {
	delete_transient( 'cerber_citadel' );
}

function cerber_is_citadel() {
	if ( get_transient( 'cerber_citadel' ) ) {
		return true;
	}

	return false;
}

// Hardening -------------------------------------------------------------------------------------

//if (!cerber_acl_check(cerber_get_ip(),'W') && false) {

/*
	if ($hardening['ping']) {
		add_filter( 'xmlrpc_methods', 'remove_xmlrpc_pingback' );
		function remove_xmlrpc_pingback( $methods ) {
			unset($methods['pingback.ping']);
			unset($methods['pingback.extensions.getPingbacks']);
			return $methods;
		}
		add_filter( 'wp_headers', 'remove_pingback_header' );
		function remove_pingback_header( $headers ) {
			unset( $headers['X-Pingback'] );
			return $headers;
		}
	}
*/
//pingback_ping();


/*
// Remove shortlink from HEAD <link rel='shortlink' href='http://адрес-сайта/?p=45' />
remove_action('wp_head', 'wp_shortlink_wp_head', 10, 0 );
*/

/**
 *
 * Send notification letter
 *
 * @param string $type Notification type
 * @param string $msg Additional message
 * @param string $ip Remote IP address, if applicable
 *
 * @return bool
 */
function cerber_send_notify( $type = '', $msg = '', $ip = '' ) {
	global $wpdb, $wp_cerber;
	if ( ! $type ) {
		return false;
	}

	if ( $type == 'lockout' && !is_super_admin()) {
		$rate = absint( $wp_cerber->getSettings( 'emailrate' ) );
		if ( $rate ) {
			$last   = get_transient( 'cerber_last' );
			$period = 60 * 60;  // per hour
			if ( $last ) {
				if ( $last > ( time() - $period / $rate ) ) {
					return false;
				}
			}
			set_transient( 'cerber_last', time(), $period );
		}
	}

	$to = cerber_get_email();

	$subj = '[' . get_option( 'blogname' ) . '] ' . __( 'WP Cerber notify', 'wp-cerber' ) . ': ';
	$body = '';

	switch ( $type ) {
		case 'citadel':
			$max = $wpdb->get_var( 'SELECT MAX(stamp) FROM ' . CERBER_LOG_TABLE . ' WHERE  activity = 7' );
			if ($max) {
				$last_date = cerber_date( $max );
				$last      = $wpdb->get_row( 'SELECT * FROM ' . CERBER_LOG_TABLE . ' WHERE stamp = ' . $max . ' AND activity = 7' );
			}
			else $last = null;

			if ( ! $last ) { // workaround for the empty log table
				$last             = new stdClass();
				$last->ip         = '127.0.0.1';
				$last->user_login = 'test';
			}

			$subj .= __( 'Citadel mode is activated', 'wp-cerber' );

			$body = sprintf( __( 'Citadel mode is activated after %d failed login attempts in %d minutes.', 'wp-cerber' ), $wp_cerber->getSettings( 'cilimit' ), $wp_cerber->getSettings( 'ciperiod' ) ) . "\n\n";
			$body .= sprintf( __( 'Last failed attempt was at %s from IP %s with user login: %s.', 'wp-cerber' ), $last_date, $last->ip, $last->user_login ) . "\n\n";
			$body .= __( 'View activity in dashboard', 'wp-cerber' ) . ': ' . cerber_admin_link( 'activity' ) . "\n\n";
			//$body .= __('Change notification settings','wp-cerber').': '.cerber_admin_link();
			break;
		case 'lockout':
			$max = $wpdb->get_var( 'SELECT MAX(stamp) FROM ' . CERBER_LOG_TABLE . ' WHERE  activity IN (10,11)' );
			if ($max){
				$last_date = cerber_date( $max );
				$last      = $wpdb->get_row( 'SELECT * FROM ' . CERBER_LOG_TABLE . ' WHERE stamp = ' . $max . ' AND activity IN (10,11)' );
			}
			else $last = null;
			if ( ! $last ) { // workaround for the empty log table
				$last             = new stdClass();
				$last->ip         = '127.0.0.1';
				$last->user_login = 'test';
			}

			//if ( ! $active = $wpdb->get_var( 'SELECT count(ip) FROM ' . CERBER_BLOCKS_TABLE ) ) {
			if ( ! $active = cerber_blocked_num() ) {
				$active = 0;
			}
			//if ( $ip && ( $block = cerber_get_block( $ip ) ) ) {
			if ( $last->ip && ( $block = cerber_get_block( $last->ip ) ) ) {
				$reason = $block->reason;
			}
			else {
				$reason = __( 'unspecified', 'wp-cerber' );
			}

			$subj .= __( 'Number of lockouts is increasing', 'wp-cerber' ) . ' (' . $active . ')';

			$body = __( 'Number of active lockouts', 'wp-cerber' ) . ': ' . $active . "\n\n";
			$body .= sprintf( __( 'Last lockout was added: %s for IP %s', 'wp-cerber' ), $last_date, $last->ip . ' (' . @gethostbyaddr( $last->ip ) . ')' ) . "\n\n";
			$body .= __( 'Reason', 'wp-cerber' ) . ': ' . strip_tags($reason) . "\n\n";
			$body .= __( 'View activity for this IP', 'wp-cerber' ) . ': ' . cerber_admin_link( 'activity' ) . '&filter_ip=' . $last->ip . "\n\n";
			$body .= __( 'View lockouts in dashboard', 'wp-cerber' ) . ': ' . cerber_admin_link( 'lockouts' ) . "\n\n";
			break;
		case 'new_version':
			$subj = __( 'A new version of WP Cerber is available to install', 'wp-cerber' );
			$body = __( 'Hi!', 'wp-cerber' ) . "\n\n";
			$body .= __( 'A new version of WP Cerber is available to install', 'wp-cerber' ) . "\n\n";
			$body .= __( 'Website', 'wp-cerber' ) . ': ' . get_bloginfo( 'name' ) . "\n";
			break;
		case 'shutdown':
			$subj = '[' . get_option( 'blogname' ) . '] ' . __( 'The WP Cerber security plugin has been deactivated', 'wp-cerber' );
			$body .= __( 'The WP Cerber security plugin has been deactivated', 'wp-cerber' ) . "\n\n";
			if ( ! is_user_logged_in() ) {
				$u = __( 'Not logged in', 'wp-cerber' );
			} else {
				$user = wp_get_current_user();
				$u    = $user->display_name;
			}
			$body .= __( 'Website', 'wp-cerber' ) . ': ' . get_bloginfo( 'name' ) . "\n";
			$body .= __( 'By user', 'wp-cerber' ) . ': ' . $u . "\n";
			$body .= __( 'From IP address', 'wp-cerber' ) . ': ' . $wp_cerber->getRemoteIp() . "\n";
			$whois = cerber_ip_whois_info( $wp_cerber->getRemoteIp() );
			if ( ! empty( $whois['data']['country'] ) ) {
				$body .= __( 'From country', 'wp-cerber' ) . ': ' . cerber_country_name( $whois['data']['country'] );
			}
			break;
		case 'activated':
			$subj = '[' . get_option( 'blogname' ) . '] ' . __( 'The WP Cerber security plugin is now active', 'wp-cerber' );
			$body .= __( 'WP Cerber is now active and has started protecting your site', 'wp-cerber' ) . "\n\n";
			$body .= __( 'Change notification settings', 'wp-cerber' ) . ': ' . cerber_admin_link('notifications') . "\n\n";
			$body .= 'Be in touch with the developer. Subscribe to Cerber\'s newsletter: http://wpcerber.com/subscribe-newsletter/';
			//$body .= get_bloginfo( 'name' );
			break;
		case 'newlurl':
			$subj .= __( 'New Custom login URL', 'wp-cerber' );
			$body .= $msg;
			break;
		case 'subs':
			$subj .= __( 'A new activity has been recorded', 'wp-cerber' );
			$body  = __( 'A new activity has been recorded', 'wp-cerber' ) . "\n\n";
			$body .= $msg;
			break;
	}

	$body_filtered = apply_filters( 'cerber_notify_body', $body, array( 'type'    => $type,
	                                                                    'IP'      => $ip,
	                                                                    'to'      => $to,
	                                                                    'subject' => $subj
	) );
	if ( $body_filtered && is_string( $body_filtered ) ) {
		$body = $body_filtered;
	} // correct body only allowed

	//$body .= __('This message was sent by','wp-cerber').' <a href="http://wpcerber.com">WP Cerber security plugin</a>.'."\n";
	$body .= "\n\n\n" . __( 'This message was sent by', 'wp-cerber' ) . " WP Cerber.\n";
	$body .= 'http://wpcerber.com';

	if ( $to && $subj && $body ) {
		cerber_pb_send($subj, $body);
		$result = wp_mail( $to, $subj, $body );
	} 
	else {
		$result = false;
	}

	$params = array( 'type' => $type, 'IP' => $ip, 'to' => $to, 'subject' => $subj );
	if ( $result ) {
		do_action( 'cerber_notify_sent', $body, $params );
	}
	else {
		do_action( 'cerber_notify_fail', $body, $params );
	}

	return $result;
}


/*
	TODO: Return themed page with message instead of login form.
*/
/*
function cerber_info_page(){
	global $wp_query;
	$wp_query->is_page = true;
	add_filter('the_content', 'cerber_info_page_content');
  if(!include(TEMPLATEPATH.'/page.php')) { // wow, theme does not have page.php file?
   	echo '<html><head><title>Login not permited</title></head><body><h1>Login not permited</h1><p>You not allowed to login to this site.</p></body></html>';
  }
  exit;
}
function cerber_info_page_content(){
	return 'Login not permited.';
}
*/

/*
	Hide login form for user with blocked IP
*/
add_action( 'login_head', 'cerber_lohead' );
function cerber_lohead() {
	if ( ! cerber_is_allowed() )  : ?>
		<style type="text/css" media="all">
			#loginform {
				display: none;
			}
		</style>
		<?php
	endif;
}

// Auxiliary routines ----------------------------------------------------------------

add_action( 'cerber_hourly', 'cerber_do_hourly' );
function cerber_do_hourly() {
	global $wpdb, $wp_cerber;
	$days = absint( $wp_cerber->getSettings( 'keeplog' ) );
	if ( $days > 0 ) {
		$wpdb->query( 'DELETE FROM ' . CERBER_LOG_TABLE . ' WHERE stamp < ' . ( time() - $days * 24 * 3600 ) );
		$wpdb->query( 'OPTIMIZE TABLE ' . CERBER_LOG_TABLE );
	}
	if ( $wp_cerber->getSettings( 'cerberlab' ) ) {
		cerber_push_lab();
	}
	cerber_up_data();
}

add_action( 'cerber_daily', 'cerber_do_daily' );
function cerber_do_daily() {
	global $wpdb, $wp_cerber;
	if ( $wp_cerber->getSettings( 'cerberlab' ) ) {
		lab_check_nodes();
	} else {
		lab_trunc_push();
	}
	$wpdb->query( 'OPTIMIZE TABLE ' . CERBER_ACL_TABLE );
}

/*
 * Load localization files
 *
 */
add_action( 'plugins_loaded', 'cerber_load_lang' );
function cerber_load_lang() {
	load_plugin_textdomain( 'wp-cerber', false, basename( dirname( __FILE__ ) ) . '/languages' );
}

/*
	Return system ID of the WP Cerber plugin
*/
function cerber_plug_in() {
	return plugin_basename( __FILE__ );
}

/*
	Return plugin info
*/
function cerber_plugin_data() {
	return get_plugin_data( __FILE__ );
}

/*
	Return main plugin file
*/
function cerber_plugin_file() {
	return __FILE__;
}

/*
	Format date
*/
function cerber_date( $timestamp ) {
	global $wp_cerber;
	$timestamp  = absint( $timestamp );
	$gmt_offset = get_option( 'gmt_offset' ) * 3600;
	if ($df = $wp_cerber->getSettings('dateformat')){
		return date_i18n( $df, $gmt_offset + $timestamp );
	}
	else {
		$tf = get_option( 'time_format' );
		$df = get_option( 'date_format' );
		return date_i18n( $df, $gmt_offset + $timestamp ) . ', ' . date_i18n( $tf, $gmt_offset + $timestamp );
	}
}

/**
 * Log activity
 *
 * @param int $activity Activity ID
 * @param string $login Login used or any additional information
 * @param int $user_id  User ID
 * @param null $ip  IP Address
 *
 * @return false|int
 * @since 3.0
 */
function cerber_log( $activity, $login = '', $user_id = 0, $ip = null ) {
	global $wpdb, $wp_cerber;

	$wp_cerber->setProcessed();

	if ( empty( $ip ) ) {
		$ip = $wp_cerber->getRemoteIp();
	}
	if ( cerber_is_ipv4( $ip ) ) {
		$ip_long = ip2long( $ip );
	} else {
		$ip_long = 1;
	}
	if ( empty( $user_id ) ) {
		$user_id = 0;
	}
	$stamp = microtime( true );
	$ret   = $wpdb->query( $wpdb->prepare( 'INSERT INTO ' . CERBER_LOG_TABLE . ' (ip, ip_long, user_login, user_id, stamp, activity) VALUES (%s,%d,%s,%d,%f,%d)', $ip, $ip_long, $login, $user_id, $stamp, $activity ) );
	if ( ! $ret ) {
		// workaround for a WP bugs like this: silently doesn't not insert a row into a table
		// https://core.trac.wordpress.org/ticket/32315
		$ret = $wpdb->insert( CERBER_LOG_TABLE, array(
			'ip'         => $ip,
			'ip_long'    => $ip_long,
			'user_login' => $login,
			'user_id'    => $user_id,
			'stamp'      => $stamp,
			'activity'   => $activity
		), array( '%s', '%d', '%s', '%d', '%f', '%d' ) );
	}

	// Subscriptions - notifications ---------------------------------------------------

	$subs = get_site_option( '_cerber_subs', null );

	if (!empty($subs)) {
		foreach ( $subs as $hash => $sub ) {

		    // Loop through parameters
			if ( ! empty( $sub[1] ) && $sub[1] != $user_id ) {
				continue;
			}
			if ( ! empty( $sub[3] ) && ( $ip_long < $sub[2] || $sub[3] < $ip_long ) ) {
				continue;
			}
			if ( ! empty( $sub[4] ) && $sub[4] != $ip ) {
				continue;
			}
			if ( ! empty( $sub[5] ) && $sub[5] != $login ) {
				continue;
			}
			if ( ! empty( $sub[6] ) && (false === strpos( $ip, $sub[6] )) && (false === mb_strpos( $login, $sub[6] )) ) {
				continue;
			}

			// Some parameter(s) matched, send notification

			$labels = cerber_get_labels( 'activity' );

			$msg = __( 'Activity', 'wp-cerber' ) . ': ' . $labels[$activity] . "\n\n";
			$msg .= __( 'IP', 'wp-cerber' ) . ': ' . $ip . "\n\n";

			if ( $user_id ) {
				$u = get_userdata( $user_id );
				$msg .= __( 'User', 'wp-cerber' ) . ': ' . $u->display_name . "\n\n";
			}

			if ( $login ) {
				$msg .= __( 'Username used', 'wp-cerber' ) . ': ' . $login . "\n\n";
			}

			if ( ! empty( $sub['6'] ) ) {
				$msg .= __( 'Search string', 'wp-cerber' ) . ': ' . $sub['6'] . "\n\n";
			}

			$args = cerber_subscribe_params();
			$i = 0; $str = '';
			foreach ($args as $arg => $val){
				$str .= '&'.$arg.'='.$sub[$i];
				$i++;
			}

			$link = cerber_admin_link( 'activity' ).$str;

			$msg .= __( 'View activity in dashboard', 'wp-cerber' ) . ': ' . $link;
			$msg .= "\n\n" . __( 'To unsubscribe click here', 'wp-cerber' ) .': '. cerber_admin_link( 'activity' ).'&unsubscribeme='.$hash;

			cerber_send_notify( 'subs', $msg, $ip );

			break; // Just one notification letter per event
		}
	}

	if ( $activity == 40 && $wp_cerber->getSettings( 'cerberlab' ) ) {
		lab_save_push( $ip, $activity, '' );
	}

	return $ret;
}

/**
 * Create a set of parameters for using it in Subscriptions
 * The keys are used to built an URL. Values to calculate a hash.
 *
 * @return array The set of parameters
 */
function cerber_subscribe_params() {
	$begin = 0;
	$end   = 0;
	$ip    = 0;
	if ( ! empty( $_GET['filter_ip'] ) ) {
		$ip = cerber_any2range( $_GET['filter_ip'] );
		if ( is_array( $ip ) ) {
			$begin = $ip['begin'];
			$end   = $ip['end'];
			$ip    = 0;
		} elseif ( ! $ip ) {
			$ip = 0;
		}
	}

	$filter_activity = ( empty( $_GET['filter_activity'] ) ) ? 0 : $_GET['filter_activity'];
	$filter_user     = ( empty( $_GET['filter_user'] ) ) ? 0 : $_GET['filter_user'];
	$filter_login    = ( empty( $_GET['filter_login'] ) ) ? 0 : $_GET['filter_login'];
	$search_activity = ( empty( $_GET['search_activity'] ) ) ? 0 : $_GET['search_activity'];
	$filter_role = ( empty( $_GET['filter_role'] ) ) ? 0 : $_GET['filter_role'];

	// 'begin' and 'end' array keys are not used, added for compatibility
	return array( 'filter_activity' => $filter_activity, 'filter_user' => $filter_user, 'being' => $begin, 'end' => $end, 'filter_ip' => $ip, 'filter_login' => $filter_login, 'search_activity' => $search_activity, 'filter_role' => $filter_role );
}

/*
	Plugin activation
*/
register_activation_hook( __FILE__, 'cerber_activate' );
function cerber_activate() {
	global $wp_version, $wp_cerber;
	$assets_url = plugin_dir_url( CERBER_FILE ) . 'assets';

	cerber_load_lang();

	if ( version_compare( CERBER_REQ_PHP, phpversion(), '>' ) ) {
		cerber_stop_activating( '<h3>' . sprintf( __( 'The WP Cerber requires PHP %s or higher. You are running', 'wp-cerber' ), CERBER_REQ_PHP ) . ' ' . phpversion() . '</h3>' );
	}

	if ( version_compare( CERBER_REQ_WP, $wp_version, '>' ) ) {
		cerber_stop_activating( '<h3>' . sprintf( __( 'The WP Cerber requires WordPress %s or higher. You are running', 'wp-cerber' ), CERBER_REQ_WP ) . ' ' . $wp_version . '</h3>' );
	}

	$db_errors = cerber_create_db();
	if ( $db_errors ) {
		cerber_stop_activating( '<h3>' . __( "Can't activate WP Cerber due to a database error.", 'wp-cerber' ) . '</h3><p>' . implode( '<p>', $db_errors ) );
	}

	cerber_upgrade();

	cerber_cookie1();
	cerber_disable_citadel();
	//cerber_get_groove();

	if ( ! is_object( $wp_cerber ) ) {
		$wp_cerber = new WP_Cerber();
	}
	cerber_add_white( cerber_get_subnet( $wp_cerber->getRemoteIp() ) ); // Protection for non-experienced user

	cerber_admin_message(
		'<img style="float:left; margin-left:-10px;" src="' . $assets_url . '/icon-128x128.png">' .
		'<p style="font-size:120%;">' . __( 'WP Cerber is now active and has started protecting your site', 'wp-cerber' ) . '</p>' .
		' <p>' . __( 'Your IP address is added to the', 'wp-cerber' ) . ' ' . __( 'White IP Access List', 'wp-cerber' ) .

		' <p><b>' . __( "It's important to check security settings.", 'wp-cerber' ) . '</b> &nbsp;<a href="http://wpcerber.com/" target="_blank">Read Cerber\'s blog</a> ' .
		'&nbsp; <a href="http://wpcerber.com/subscribe-newsletter/" target="_blank">Subscribe to Cerber\'s newsletter</a></p>' .

		' <p> </p><p><span class="dashicons dashicons-admin-settings"></span> <a href="' . cerber_admin_link( 'main' ) . '">' . __( 'Main Settings', 'wp-cerber' ) . '</a>' .
		' <span style="margin-left:20px;" class="dashicons dashicons-admin-network"></span> <a href="' . cerber_admin_link( 'acl' ) . '">' . __( 'Access Lists', 'wp-cerber' ) . '</a>' .
		' <span style="margin-left:20px;" class="dashicons dashicons-shield-alt"></span> <a href="' . cerber_admin_link( 'hardening' ) . '">' . __( 'Hardening', 'wp-cerber' ) . '</a>' .
		' <span style="margin-left:20px;" class="dashicons dashicons-controls-volumeon"></span> <a href="' . cerber_admin_link( 'notifications' ) . '">' . __( 'Notifications', 'wp-cerber' ) . '</a>' .
		' <span style="margin-left:20px;" class="dashicons dashicons-admin-tools"></span> <a href="' . cerber_admin_link( 'tools' ) . '">' . __( 'Import settings', 'wp-cerber' ) . '</a>' .
		'</p>' );


	// Check for existing options
	$opt = cerber_get_options();
	$opt = array_filter( $opt );
	if ( ! empty( $opt ) ) {
		return;
	}

	cerber_load_defaults();

	cerber_send_notify( 'activated' );

	$pi          = get_file_data( cerber_plugin_file(), array( 'Version' => 'Version' ), 'plugin' );
	$pi ['time'] = time();
	$pi ['user'] = get_current_user_id();
	update_site_option( '_cerber_activated', serialize( $pi ) );
}

/*
	Abort activating plugin!
*/
function cerber_stop_activating( $msg ) {
	deactivate_plugins( plugin_basename( __FILE__ ) );
	wp_die( $msg );
}

/**
 * Upgrade database tables and settings
 *
 * @since 3.0
 *
 */
function cerber_upgrade() {
	$ver = get_site_option( '_cerber_up', false );
	if ( ! $ver || $ver['v'] != CERBER_VER ) {
		cerber_create_db();
		cerber_upgrade_db();

		cerber_push_the_news( CERBER_VER );
		cerber_acl_fixer();

		// Updating  settings ----------------------------------------------

		// @since 4.4
		$main = get_site_option( CERBER_OPT );
		if (!empty($main['email']) || !empty($main['emailrate'])){
			$new = get_site_option( CERBER_OPT_N, array() );
			$new['email'] = $main['email'];
			$new['emailrate'] = $main['emailrate'];
			update_site_option( CERBER_OPT_N, $new );
			// clean up old values
			$main['email'] = '';
			$main['emailrate'] = '';
			update_site_option( CERBER_OPT, $main );
		}

		// @since 4.8
		$settings = get_site_option( CERBER_OPT_C );
        $new_fields = array('recaptcha-period', 'recaptcha-number', 'recaptcha-within');
		foreach ( $new_fields as $field ) {
			if (!isset($settings[$field])) $settings[$field] = cerber_get_defaults($field);
        }
		update_site_option( CERBER_OPT_C, $settings );

		update_site_option( '_cerber_up', array( 'v' => CERBER_VER, 't' => time() ) );
	}
}

/**
 * Creates DB tables if they don't exist
 *
 * @return array Errors during the creating DB tables
 *
 */
function cerber_create_db() {
	global $wpdb;

	$wpdb->hide_errors();
	$db_errors = array();

	if (!cerber_is_table(CERBER_LOG_TABLE)){
		if ( ! $wpdb->query( "

	CREATE TABLE IF NOT EXISTS " . CERBER_LOG_TABLE . " (
    ip varchar(39) CHARACTER SET ascii NOT NULL COMMENT 'Remote IP',
    user_login varchar(60) NOT NULL COMMENT 'Username from HTTP request',
    user_id bigint(20) unsigned NOT NULL DEFAULT '0',
    stamp bigint(20) unsigned NOT NULL COMMENT 'Unix timestamp',
    activity int(10) unsigned NOT NULL DEFAULT '0',
    KEY ip (ip)
	) DEFAULT CHARSET=utf8 COMMENT='Cerber activity log';

				" )
		) {
			$db_errors[] = $wpdb->last_error;
		}
	}
	if (!cerber_is_table(CERBER_ACL_TABLE)){
		if ( ! $wpdb->query( "

	CREATE TABLE IF NOT EXISTS " . CERBER_ACL_TABLE . " (
    ip varchar(39) CHARACTER SET ascii NOT NULL COMMENT 'IP',
    tag char(1) NOT NULL COMMENT 'Type: B or W',
    comments varchar(250) NOT NULL,
    UNIQUE KEY ip (ip)
	) DEFAULT CHARSET=utf8 COMMENT='Cerber IP Access Lists';

				" )
		) {
			$db_errors[] = $wpdb->last_error;
		}
	}

	if (!cerber_is_table(CERBER_BLOCKS_TABLE)){
		if ( ! $wpdb->query( "
			CREATE TABLE IF NOT EXISTS " . CERBER_BLOCKS_TABLE . " (
		    ip varchar(39) CHARACTER SET ascii NOT NULL COMMENT 'Remote IP',
		    block_until bigint(20) unsigned NOT NULL COMMENT 'Unix timestamp',
		    reason varchar(250) NOT NULL COMMENT 'Why IP was blocked',
		    UNIQUE KEY ip (ip)
			) DEFAULT CHARSET=utf8 COMMENT='Cerber list of currently blocked IPs';			
				" )
		) {
			$db_errors[] = $wpdb->last_error;
		}
	}
	if (!cerber_is_table(CERBER_LAB_TABLE)){
		if ( ! $wpdb->query( "
			CREATE TABLE IF NOT EXISTS " . CERBER_LAB_TABLE . " (
			  ip varchar(39) CHARACTER SET ascii NOT NULL COMMENT 'Remote IP',
			  reason_id int(11) unsigned NOT NULL DEFAULT '0',
			  stamp bigint(20) unsigned NOT NULL COMMENT 'Unix timestamp',
			  details text NOT NULL
			) DEFAULT CHARSET=utf8 COMMENT='Cerber lab cache';
				" )
		) {
			$db_errors[] = $wpdb->last_error;
		}
	}

	return $db_errors;
}

/**
 * Upgrade structure of existing DB tables
 *
 * @return array Errors during upgrading
 * @since 3.0
 */
function cerber_upgrade_db( $force = false ) {
	global $wpdb;
	$wpdb->hide_errors();
	$db_errors = array();
	$sql       = array();
	// @since 3.0
	$sql[] = 'ALTER TABLE ' . CERBER_LOG_TABLE . ' CHANGE stamp stamp DECIMAL(14,4) NOT NULL';
	/*
	if ( $force || ! $wpdb->query( 'ALTER TABLE ' . CERBER_LOG_TABLE . ' CHANGE stamp stamp DECIMAL(14,4) NOT NULL' ) ) {
		if ( $wpdb->last_error ) {
			$db_errors[] = array( $wpdb->last_error, $wpdb->last_query );
		}
	}
	*/
	// @since 3.1
	if ( $force || ! cerber_check_table( CERBER_LOG_TABLE, 'ip_long' ) ) {
		$sql[] = 'ALTER TABLE ' . CERBER_LOG_TABLE . ' ADD ip_long BIGINT UNSIGNED NOT NULL DEFAULT "0" COMMENT "IPv4 long" AFTER ip, ADD INDEX (ip_long)';
	}
	if ( $force || ! cerber_check_table( CERBER_ACL_TABLE, 'ip_long_begin' ) ) {
		$sql[] = 'ALTER TABLE ' . CERBER_ACL_TABLE . " ADD ip_long_begin BIGINT UNSIGNED NOT NULL DEFAULT '0' COMMENT 'IPv4 range begin' AFTER ip, ADD ip_long_end BIGINT UNSIGNED NOT NULL DEFAULT '0' COMMENT 'IPv4 range end' AFTER ip_long_begin";
		$sql[] = 'ALTER TABLE ' . CERBER_ACL_TABLE . ' ADD UNIQUE ip_begin_end (ip, ip_long_begin, ip_long_end)';
		$sql[] = 'ALTER TABLE ' . CERBER_ACL_TABLE . ' DROP INDEX ip';
	}
	// @since 4.8.1
	$sql[] = 'ALTER TABLE ' . CERBER_ACL_TABLE . ' DROP INDEX begin_end';
	$sql[] = 'ALTER TABLE ' . CERBER_ACL_TABLE . ' ADD INDEX begin_end_tag (ip_long_begin, ip_long_end, tag)';

	if (!empty($sql)) {
		//$query = implode(";\n",$sql).";\n";
		foreach ( $sql as $query ) {
			if ( ! $wpdb->query( $query ) ) {
				if ( $wpdb->last_error ) {
					$db_errors[] = array( $wpdb->last_error, $wpdb->last_query );
				}
			}
		}
	}

	// Convert existing data to the new format
	$rows = $wpdb->get_results( 'SELECT * FROM ' . CERBER_ACL_TABLE );
	if ( $rows ) {
		foreach ( $rows as $row ) {
			$range = cerber_wildcard2range( $row->ip );
			if ( is_array( $range ) ) {
				$begin = $range['begin'];
				$end   = $range['end'];
			} elseif ( cerber_is_ipv4( $row->ip ) ) {
				$begin = ip2long( $row->ip );
				$end   = ip2long( $row->ip );
			} else {
				$begin = 0;
				$end   = 0;
			}
			$query = $wpdb->prepare( 'UPDATE ' . CERBER_ACL_TABLE . ' SET ip_long_begin = %d, ip_long_end = %d WHERE ip = %s', $begin, $end, $row->ip );
			if ( ! $wpdb->query( $query ) ) {
				if ( $wpdb->last_error ) {
					$db_errors[] = array( $wpdb->last_error, $wpdb->last_query );
				}
			}
		}
	}

	if ( $db_errors ) {
		update_site_option( '_cerber_db_errors', $db_errors );
	}
	else {
		update_site_option( '_cerber_db_errors', '' );
	}

	return $db_errors;
}

/**
 * Updating old activity log records to a new row format (has been introduced in v 3.1)
 *
 * @since 4.0
 *
 */
function cerber_up_data() {
	global $wpdb;
	$ips = $wpdb->get_col( 'SELECT DISTINCT ip FROM ' . CERBER_LOG_TABLE . ' WHERE ip_long = 0 LIMIT 50' );
	if ( ! $ips ) {
		return;
	}
	foreach ( $ips as $ip ) {
		if ( cerber_is_ipv4( $ip ) ) {
			$ip_long = ip2long( $ip );
		} else {
			$ip_long = 1;
		}
		$wpdb->query( 'UPDATE ' . CERBER_LOG_TABLE . ' SET ip_long = ' . $ip_long . ' WHERE ip = "' . $ip .'" AND ip_long = 0');
	}
}

/**
 * Just fix corrupted (have no long values) ACL entries
 *
 */
function cerber_acl_fixer(){
	global $wpdb;
	$rows = $wpdb->get_col( 'SELECT ip FROM ' . CERBER_ACL_TABLE . ' WHERE ip_long_begin = 0 OR ip_long_end = 0' );
	if ( ! $rows ) {
		return;
	}
	foreach ( $rows as $ip ) {
		if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) continue;
		$range = cerber_any2range( $ip );
		if ( is_array( $range ) ) {
			$begin = $range['begin'];
			$end   = $range['end'];
		} else {
			$begin = ip2long( $ip );
			$end   = ip2long( $ip );
		}

		$wpdb->query( 'UPDATE ' . CERBER_ACL_TABLE . ' SET ip_long_begin = ' . $begin . ', ip_long_end = ' . $end . ' WHERE ip = "' . $ip .'"');
	}
}

$file = plugin_basename( cerber_plugin_file() );
add_action( 'deac' . 'tivate_' . $file, 'cerber_clean' );
function cerber_clean( $ip ) {
	wp_clear_scheduled_hook( 'cerber' . '_hourly' );
	$pi       = get_file_data( cerber_plugin_file(), array( 'Version' => 'Version' ), 'plugin' );
	$pi ['v'] = time();
	$pi ['u'] = get_current_user_id();
	update_site_option( '_cerber_o' . 'ff', $pi );
	$f = 'cerb' . 'er_se' . 'nd_not' . 'ify';
	$f( 'sh' . 'utd' . 'own' );
}

/*
	Fix an issue with the empty user_id field in the comments table.
*/
add_filter( 'preprocess_comment', 'cerber_add_uid' );
function cerber_add_uid( $commentdata ) {
	$current_user           = wp_get_current_user();
	$commentdata['user_ID'] = $current_user->ID;

	return $commentdata;
}

/**
 * Load jQuery on the page
 *
 */
//add_action( 'login_enqueue_scripts', 'cerber_scripts' );
add_action( 'wp_enqueue_scripts', 'cerber_scripts' );
function cerber_scripts() {
	global $wp_cerber;
	if ($wp_cerber->getSettings('sitekey') && $wp_cerber->getSettings('secretkey')){
		wp_enqueue_script('jquery');
    }
}

/**
 * Footer stuff
 * Explicit rendering reCAPTCHA
 *
 */
add_action( 'login_footer', 'cerber_login_foo', 1000 );
function cerber_login_foo( $ip ) {
    global $wp_cerber;
    // Universal JS
	if (!$wp_cerber->recaptcha_here) return;
	$sitekey = $wp_cerber->getSettings('sitekey');
	$lang = get_bloginfo( 'language' );
	if ( $lang == 'en-US' ) {
		$lang = 'en';
	}

	if (!$wp_cerber->getSettings('invirecap')){
	    // Classic version (visible reCAPTCHA)
		echo '<script src = "https://www.google.com/recaptcha/api.js?hl=<?php echo $lang; ?>" async defer></script>';
    }
	else {
	    // Pure JS version with explicit rendering
		?>
        <script src="https://www.google.com/recaptcha/api.js?onload=init_recaptcha_widgets&render=explicit&hl=<?php echo $lang; ?>" async defer></script>
        <script type='text/javascript'>

            document.getElementById("cerber-recaptcha").remove();

            var init_recaptcha_widgets = function () {
                for (var i = 0; i < document.forms.length; ++i) {
                    var form = document.forms[i];
                    var place = form.querySelector('.cerber-form-marker');
                    if (null !== place) render_recaptcha_widget(form, place);
                }
            };

            function render_recaptcha_widget(form, place) {
                var place_id = grecaptcha.render(place, {
                    'callback': function (g_recaptcha_response) {
                        HTMLFormElement.prototype.submit.call(form);
                    },
                    'sitekey': '<?php echo $sitekey; ?>',
                    'size': 'invisible',
                    'badge': 'bottomright'
                });

                form.onsubmit = function (event) {
                    event.preventDefault();
                    grecaptcha.execute(place_id);
                };

            }
        </script>
		<?php
	}
}

/**
 * Inline reCAPTCHA widget
 *
 */
add_action( 'wp_footer', 'cerber_foo', 1000 );
function cerber_foo() {
    global $wp_cerber;
    if (!$wp_cerber->recaptcha_here) return;
	$lang = get_bloginfo( 'language' );
	if ( $lang == 'en-US' ) {
		$lang = 'en';
	}
	// jQuery version with support visible and invisible reCAPTCHA
	// TODO: convert it into pure JS
	?>
    <script type="text/javascript">

        jQuery(document).ready(function ($) {

            var recaptcha_ok = false;
            var the_recaptcha_widget = $("#cerber-recaptcha");
            var is_recaptcha_visible = ($(the_recaptcha_widget).data('size') !== 'invisible');

            var the_form = $(the_recaptcha_widget).closest("form");
            var the_button = $(the_form).find('input[type="submit"]');
            if (!the_button.length) {
                the_button = $(the_form).find(':button');
            }

            // visible
            if (the_button.length && is_recaptcha_visible) {
                the_button.prop("disabled", true);
                the_button.css("opacity", 0.5);
            }

            window.form_button_enabler = function () {
                if (!the_button.length) return;
                the_button.prop("disabled", false);
                the_button.css( "opacity", 1 );
            };

            // invisible
            if (!is_recaptcha_visible) {
                $(the_button).click(function (event) {
                    if (recaptcha_ok) return;
                    event.preventDefault();
                    grecaptcha.execute();
                });
            }

            window.now_submit_the_form = function () {
                recaptcha_ok = true;
                $(the_button).click(); // this is only way to submit a form that contains "submit" inputs
            };
        });
    </script>
    <script src = "https://www.google.com/recaptcha/api.js?hl=<?php echo $lang; ?>" async defer></script>
	<?php
}