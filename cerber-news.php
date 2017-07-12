<?php
/*
 	Copyright (C) 2015-16 Gregory Markov, http://wpcerber.com

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
if ( ! defined( 'WPINC' ) ) {
	exit;
}


function cerber_push_the_news( $version ) {

	$news['3.0'] =
		'<h3>Welcome a new version with reCAPTCHA and WordPress filters</h3>
<ul>
 	<li>Now you can use Google reCAPTCHA to protect WordPress registration form from spam registrations. Also reCAPTCHA available for lost password and login forms. <a href="http://wpcerber.com/how-to-setup-recaptcha/">How to setup reCAPTCHA</a>.</li>
 	<li>The registration process, WordPress registration form, XML-RPC, WP REST API are controlled by <a href="http://wpcerber.com/using-ip-access-lists-to-protect-wordpress/">IP Access Lists</a>.</li>
 	<li>Registration is impossible if a particular IP address is locked out.</li>
 	<li>Registration with a prohibited username is impossible.</li>
 	<li><a href="http://wpcerber.com/wp-cerber-hooks/">A set of filters and actions</a>. They are useful if you want to customize some aspects of the plugin as you want.</li>
 	<li>A new action <strong>Get WHOIS info</strong> that obtains detailed WHOIS information about given IP address. You can use it in vary <a href="http://jetflow.io">jetFlow.io automation scenarios</a>. For instance, you can monitor countries from what your users are logged in on the website or you <a href="http://wpcerber.com/notifications-on-wordpress-user-logs-in/">monitor user logins with notifications</a>.</li>
 	<li>A new trigger <strong>IP locked out</strong> that starts automation scenario after a suspicious IP address has been locked out by the WP Cerber plugin.</li>
</ul>

';

	$news['4.0'] =
		'<h3>Welcome a new version with extended Access Lists and reCAPTCHA for WooCommerce</h3>
<ul>
 	<li>reCAPTCHA for WooCommerce forms. <a href="http://wpcerber.com/how-to-setup-recaptcha/">How to set up reCAPTCHA</a>.</li>
 	<li>IP Access Lists has got support for IP networks in three forms: ability to restrict access with IPv4 ranges, IPv4 CIDR notation and IPv4 subnets: A,B,C has been added. Read more: <a href="http://wpcerber.com/using-ip-access-lists-to-protect-wordpress/">Access Lists for WordPress</a>.</li>
 	<li>Cerber can automatically detect an IP network of an intruder and suggest you to block the entire network right from the Activity screen.</li>
 	<!-- <li>reCAPTCHA will not be shown and processed for IP addresses from the White IP Access List.</li> -->
</ul>

 <p><a href="http://wpcerber.com/wp-cerber-security-4-0/" target="_blank">Read a full list of changes and improvements</a></p> 
';

	$news['4.3'] =
		'<h3>What\'s new in version 4.3</h3>
<ul>
 	<li>Do you want to keep eye on specific activity on your website? I have good news for you! Track them like a PRO. Use powerful subscriptions to get email notifications according to filters for events you have set. Filter out activities that you are interested to monitor and then click Subscribe. <a href="http://wpcerber.com/wordpress-notifications-made-easy/">Read more</a></li>
 	<li>Search and/or filter activity by IP address, username (login), specific event and a user. You can use any combination of them. </li>
 	<li>Now you can export activity from your WordPress website to a CSV file. You can export all activities or a set of filtered activities only as it described above. When you will import the CSV file in your spreadsheet editor, don\'t forget to select UTF-8 charset.</li>
 	<li>You can use multiple email addresses for notifications (Main Settings -> Notifications -> Email Address). Use a comma to specify several addresses.</li>
</ul>
';

	$news['4.5'][] = 'Instant mobile and browser notifications with Pushbullet. Get notified instantly via push notifications when an important event happens on your WordPress.';
	$news['4.5'][] = 'Ability to choose a 404 page template. The plugin will try to use the 404 template from the active theme, and this is a default behavior or a generate simple 404 page like Apache web server does.';
	$news['4.5'][] = 'Events on the Activity tab are displaying with user roles and avatars.';

	$news['4.7.7'][] = 'Welcome invisible reCAPTCHA. You can choose what type you want to use: classic visible or new invisible reCAPTCHA. <a target="_blank" href="http://wpcerber.com/how-to-setup-recaptcha/">How to setup</a>.';
	$news['4.7.7'][] = 'reCAPTCHA for comment forms is available now. Stop spam comments – use reCAPTCHA as an anti-spam tool for WordPress comment forms.';
	$news['4.7.7'][] = 'Dates on the plugin dashboard now are displayed according to the Site Language.';
	$news['4.7.7'][] = '<a target="_blank" href="https://www.facebook.com/pg/wpcerber/reviews/">You can leave a review on Facebook now.</a>';


	if ( ! empty( $news[ $version ] ) ) {
		$text = '<h3>What\'s new in WP Cerber '.$version.'</h3>';
		$text .= '<ul><li>'.implode('</li><li>', $news[ $version ]).'</li></ul>';

		$text .= '	<p style="margin-top: 18px;"><a href="http://wpcerber.com/security/releases/" target="_blank">Change log</a></p>';

		$text .= '	<p style="margin-top: 24px;"><span class="dashicons-before dashicons-email-alt"></span> &nbsp; <a href="http://wpcerber.com/subscribe-newsletter/">Subscribe to Cerber\'s newsletter</a></p>
					<p><span class="dashicons-before dashicons-twitter"></span> &nbsp; <a href="https://twitter.com/wpcerber">Follow Cerber on Twitter</a></p>
					<p><span class="dashicons-before dashicons-facebook"></span> &nbsp; <a href="https://www.facebook.com/wpcerber/">Follow Cerber on Facebook</a></p>
				';
		cerber_admin_info( $text );
	}
}

