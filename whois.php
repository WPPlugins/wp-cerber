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

define('WHOIS_ERR_EXPIRE',300);
define('WHOIS_OK_EXPIRE',24 * 3600);
define('WHOIS_IO_TIMEOUT', 3);

require_once(dirname(__FILE__).'/ripe.php');

/*
 * Get WHOIS about IP
 * @since 2.7
 *
 */
function cerber_ip_whois_info($ip) {
	$ret = array();

	$whois_server = cerber_get_whois_server($ip);
	if (is_array($whois_server)) return $whois_server;

	if ($whois_server == 'whois.ripe.net') {
		return ripe_readable_info($ip);
	}

	$whois_info = cerber_get_whois($ip);
	if (is_array($whois_info)) return $whois_info;
	$data = cerber_parse_whois_data($whois_info);

	// Special case - network was transfered to RIPE
	if (isset($data['ReferralServer']) && $data['ReferralServer'] == 'whois://whois.ripe.net') {
		return ripe_readable_info($ip);
	}

	$table1 = '';
	if (!empty($data)) {
		$table1 = '<table class="whois-object"><tr><td colspan="2"><b>FILTERED WHOIS INFO</b></td></tr>';
		foreach ( $data as $key => $value ) {
			if (is_email($value)) $value = '<a href="mailto:'.$value.'">'.$value.'</a>';
			elseif (strtolower($key) == 'country') {
				$value = '<b><span '.cerber_get_flag_css($value).'>'.cerber_country_name($value).'</span> ('.$value.')</b>';
				$ret['country'] = $value;
			}

			$table1.='<tr><td>'.$key.'</td><td>'.$value.'</td></tr>';
		}
		$table1.='</table>';
	}

	$table2 ='<table class="whois-object raw"><tr><td><b>RAW WHOIS INFO</b></td></tr>';
	$table2.='<tr><td><pre>'.$whois_info."\n WHOIS server: ".$whois_server.'</pre></td></tr>';
	$table2.='</table>';

	$info = $table1.$table2;

	// Other possible field with abuse email address
	if (empty($data['abuse-mailbox']) && !empty($data['OrgAbuseEmail'])){
		$data['abuse-mailbox'] = $data['OrgAbuseEmail'];
	}
	if (empty($data['abuse-mailbox'])){
		foreach ($data as $field){
			$maybe_email = trim($field);
			if (false !== strpos($maybe_email,'abuse') && is_email($maybe_email)){
				$data['abuse-mailbox'] = $maybe_email;
				break;
			}
		}
	}

	// Network
	if (!empty($data['inetnum'])){
		$data['network'] = $data['inetnum'];
	}
	elseif (!empty($data['NetRange'])){
		$data['network'] = $data['NetRange'];
	}

	$ret['data'] = $data;
	$ret['whois'] = $info;
	return $ret;
}
/*
 * Get WHOIS info fro given IP
 * @since 2.7
 *
 */
function cerber_get_whois($ip){
	$key = 'WHS-'.cerber_get_id_ip($ip);
	$info = get_transient($key);
	if (false === $info) {
		$whois_server = cerber_get_whois_server($ip);
		if (is_array($whois_server)) return $whois_server;
		$info = make_whois_request($whois_server, $ip);
		if (is_array($info)) return $info;
		set_transient( $key, $info , WHOIS_OK_EXPIRE );
	}
	return $info;
}
/*
 * Find out what is server storing WHOIS info for given IP
 * @since 2.7
 *
 */
function cerber_get_whois_server($ip){
	$key = 'SRV-'.cerber_get_id_ip($ip);
	$server = get_transient($key);
	if (false === $server) {
		$w = make_whois_request( 'whois.iana.org', $ip);
		if (is_array($w)) return $w;
		preg_match( '/^whois\:\s+([\w\.\-]{3,})/m', $w, $data );
		if ( ! isset( $data[1] ) ) return array('error'=>'No WHOIS server was found for IP '.$ip);
		$server = $data[1];
		set_transient( $key, $server , WHOIS_OK_EXPIRE );
	}
	return $server;
}
/*
 * Attempt to parse TXT WHOIS response to associative array
 * @since 2.7
 *
 */
function cerber_parse_whois_data($txt){
	$lines = explode("\n",$txt);
	$lines = array_filter($lines);
	$ret = array();
	foreach ( $lines as $line ) {
		if (preg_match( '/^([\w\-]+)\:\s+(.+)/', trim($line), $data )) $ret[$data[1]] = $data[2];
	}
	return $ret;
}
/*
 *
 * Retrieve RAW IP information by using WHOIS protocol
 * @since 2.7
 *
 */
function make_whois_request($server, $ip) {
	if (!$f = fsockopen( $server, 43, $errno, $errstr, WHOIS_IO_TIMEOUT )) return array('error'=>$errstr.' (WHOIS: '.$server.').');
	#Set the timeout for answering
	if (!stream_set_timeout($f,WHOIS_IO_TIMEOUT)) return array('error'=>'WHOIS: Unable to set IO timeout.');
	#Send the IP address to the whois server
	if (false === fwrite($f, "$ip\r\n" )) return array('error'=>'WHOIS: Unable to send request to remote WHOIS server ('.$server.').');
	//Set the timeout limit for reading again
	if (!stream_set_timeout($f,WHOIS_IO_TIMEOUT)) return array('error'=>'WHOIS: Unable to set IO timeout.');
	//Set socket in non-blocking mode
	if (!stream_set_blocking( $f, 0 )) return array('error'=>'WHOIS: Unable to set IO non-blocking mode.');
	//If connection still valid
	if ($f) {
		$data = '';
		while (!feof($f)) {
			$data .= fread($f,256);
		}
	}
	else return array('error'=>'Unable to get WHOIS response.');
	if (!$data) return array('error'=>'Remote WHOIS server return empty response ('.$server.').');
	return $data;
}
/*
 * Tiny national flag by country code
 * @since 2.7
 *
 */
function cerber_get_flag_css($code){
	$assets_url = plugin_dir_url(CERBER_FILE).'assets';
	return 'style="padding-left: 24px; background: url(\''.$assets_url.'/flags/'.strtolower($code).'.gif\') no-repeat left;"';
}
/*
 *
 * Country name from two letter code
 * ISO 3166-1 alpha-2
 * @since 2.7
 *
 */
function cerber_country_name($code) {
	global $cerber_country_names;
	$code = strtoupper($code);
	if (isset($cerber_country_names[$code])) return $cerber_country_names[$code];
	return __('Unknown','wp-cerber');
}

$cerber_country_names = array(
	'AF' => 'AFGHANISTAN',
	'AL' => 'ALBANIA',
	'AX' => 'Åland Islands',
	'DZ' => 'ALGERIA',
	'AS' => 'AMERICAN SAMOA',
	'AD' => 'ANDORRA',
	'AO' => 'ANGOLA',
	'AI' => 'ANGUILLA',
	'AQ' => 'ANTARCTICA',
	'AG' => 'ANTIGUA AND BARBUDA',
	'AR' => 'ARGENTINA',
	'AM' => 'ARMENIA',
	'AW' => 'ARUBA',
	'AU' => 'AUSTRALIA',
	'AT' => 'AUSTRIA',
	'AZ' => 'AZERBAIJAN',
	'BS' => 'BAHAMAS',
	'BH' => 'BAHRAIN',
	'BD' => 'BANGLADESH',
	'BB' => 'BARBADOS',
	'BY' => 'BELARUS',
	'BE' => 'BELGIUM',
	'BZ' => 'BELIZE',
	'BJ' => 'BENIN',
	'BM' => 'BERMUDA',
	'BT' => 'BHUTAN',
	'BO' => 'BOLIVIA, PLURINATIONAL STATE OF',
	'BQ' => 'BONAIRE, SINT EUSTATIUS AND SABA',
	'BA' => 'BOSNIA AND HERZEGOVINA',
	'BW' => 'BOTSWANA',
	'BV' => 'BOUVET ISLAND',
	'BR' => 'BRAZIL',
	'IO' => 'BRITISH INDIAN OCEAN TERRITORY',
	'BN' => 'BRUNEI DARUSSALAM',
	'BG' => 'BULGARIA',
	'BF' => 'BURKINA FASO',
	'BI' => 'BURUNDI',
	'KH' => 'CAMBODIA',
	'CM' => 'CAMEROON',
	'CA' => 'CANADA',
	'CV' => 'CAPE VERDE',
	'KY' => 'CAYMAN ISLANDS',
	'CF' => 'CENTRAL AFRICAN REPUBLIC',
	'TD' => 'CHAD',
	'CL' => 'CHILE',
	'CN' => 'CHINA',
	'CX' => 'CHRISTMAS ISLAND',
	'CC' => 'COCOS (KEELING) ISLANDS',
	'CO' => 'COLOMBIA',
	'KM' => 'COMOROS',
	'CG' => 'CONGO',
	'CD' => 'CONGO, THE DEMOCRATIC REPUBLIC OF THE',
	'CK' => 'COOK ISLANDS',
	'CR' => 'COSTA RICA',
	'CI' => 'COTE DIVOIRE',
	'HR' => 'CROATIA',
	'CU' => 'CUBA',
	'CW' => 'CURACAO',
	'CY' => 'CYPRUS',
	'CZ' => 'CZECH REPUBLIC',
	'DK' => 'DENMARK',
	'DJ' => 'DJIBOUTI',
	'DM' => 'DOMINICA',
	'DO' => 'DOMINICAN REPUBLIC',
	'EC' => 'ECUADOR',
	'EG' => 'EGYPT',
	'SV' => 'EL SALVADOR',
	'GQ' => 'EQUATORIAL GUINEA',
	'ER' => 'ERITREA',
	'EE' => 'ESTONIA',
	'ET' => 'ETHIOPIA',
	'EU' => 'European Union',
	'EZ' => 'Eurozone',
	'FK' => 'FALKLAND ISLANDS (MALVINAS)',
	'FO' => 'FAROE ISLANDS',
	'FJ' => 'FIJI',
	'FI' => 'FINLAND',
	'FR' => 'FRANCE',
	'GF' => 'FRENCH GUIANA',
	'PF' => 'FRENCH POLYNESIA',
	'TF' => 'FRENCH SOUTHERN TERRITORIES',
	'GA' => 'GABON',
	'GM' => 'GAMBIA',
	'GE' => 'GEORGIA',
	'DE' => 'GERMANY',
	'GH' => 'GHANA',
	'GI' => 'GIBRALTAR',
	'GR' => 'GREECE',
	'GL' => 'GREENLAND',
	'GD' => 'GRENADA',
	'GP' => 'GUADELOUPE',
	'GU' => 'GUAM',
	'GT' => 'GUATEMALA',
	'GG' => 'GUERNSEY',
	'GN' => 'GUINEA',
	'GW' => 'GUINEA-BISSAU',
	'GY' => 'GUYANA',
	'HT' => 'HAITI',
	'HM' => 'HEARD ISLAND AND MCDONALD ISLANDS',
	'VA' => 'HOLY SEE (VATICAN CITY STATE)',
	'HN' => 'HONDURAS',
	'HK' => 'HONG KONG',
	'HU' => 'HUNGARY',
	'IS' => 'ICELAND',
	'IN' => 'INDIA',
	'ID' => 'INDONESIA',
	'IR' => 'IRAN, ISLAMIC REPUBLIC OF',
	'IQ' => 'IRAQ',
	'IE' => 'IRELAND',
	'IM' => 'ISLE OF MAN',
	'IL' => 'ISRAEL',
	'IT' => 'ITALY',
	'JM' => 'JAMAICA',
	'JP' => 'JAPAN',
	'JE' => 'JERSEY',
	'JO' => 'JORDAN',
	'KZ' => 'KAZAKHSTAN',
	'KE' => 'KENYA',
	'KI' => 'KIRIBATI',
	'KP' => 'KOREA, DEMOCRATIC PEOPLES REPUBLIC OF',
	'KR' => 'KOREA, REPUBLIC OF',
	'KW' => 'KUWAIT',
	'KG' => 'KYRGYZSTAN',
	'LA' => 'LAO PEOPLES DEMOCRATIC REPUBLIC',
	'LV' => 'LATVIA',
	'LB' => 'LEBANON',
	'LS' => 'LESOTHO',
	'LR' => 'LIBERIA',
	'LY' => 'LIBYA',
	'LI' => 'LIECHTENSTEIN',
	'LT' => 'LITHUANIA',
	'LU' => 'LUXEMBOURG',
	'MO' => 'MACAO',
	'MK' => 'MACEDONIA, THE FORMER YUGOSLAV REPUBLIC OF',
	'MG' => 'MADAGASCAR',
	'MW' => 'MALAWI',
	'MY' => 'MALAYSIA',
	'MV' => 'MALDIVES',
	'ML' => 'MALI',
	'MT' => 'MALTA',
	'MH' => 'MARSHALL ISLANDS',
	'MQ' => 'MARTINIQUE',
	'MR' => 'MAURITANIA',
	'MU' => 'MAURITIUS',
	'YT' => 'MAYOTTE',
	'MX' => 'MEXICO',
	'FM' => 'MICRONESIA, FEDERATED STATES OF',
	'MD' => 'MOLDOVA, REPUBLIC OF',
	'MC' => 'MONACO',
	'MN' => 'MONGOLIA',
	'ME' => 'MONTENEGRO',
	'MS' => 'MONTSERRAT',
	'MA' => 'MOROCCO',
	'MZ' => 'MOZAMBIQUE',
	'MM' => 'MYANMAR',
	'NA' => 'NAMIBIA',
	'NR' => 'NAURU',
	'NP' => 'NEPAL',
	'NL' => 'NETHERLANDS',
	'NC' => 'NEW CALEDONIA',
	'NZ' => 'NEW ZEALAND',
	'NI' => 'NICARAGUA',
	'NE' => 'NIGER',
	'NG' => 'NIGERIA',
	'NU' => 'NIUE',
	'NF' => 'NORFOLK ISLAND',
	'MP' => 'NORTHERN MARIANA ISLANDS',
	'NO' => 'NORWAY',
	'OM' => 'OMAN',
	'PK' => 'PAKISTAN',
	'PW' => 'PALAU',
	'PS' => 'PALESTINE, STATE OF',
	'PA' => 'PANAMA',
	'PG' => 'PAPUA NEW GUINEA',
	'PY' => 'PARAGUAY',
	'PE' => 'PERU',
	'PH' => 'PHILIPPINES',
	'PN' => 'PITCAIRN',
	'PL' => 'POLAND',
	'PT' => 'PORTUGAL',
	'PR' => 'PUERTO RICO',
	'QA' => 'QATAR',
	'RE' => 'REUNION',
	'RO' => 'ROMANIA',
	'RU' => 'RUSSIAN FEDERATION',
	'RW' => 'RWANDA',
	'BL' => 'SAINT BARTH√âLEMY',
	'SH' => 'SAINT HELENA, ASCENSION AND TRISTAN DA CUNHA',
	'KN' => 'SAINT KITTS AND NEVIS',
	'LC' => 'SAINT LUCIA',
	'MF' => 'SAINT MARTIN (FRENCH PART)',
	'PM' => 'SAINT PIERRE AND MIQUELON',
	'VC' => 'SAINT VINCENT AND THE GRENADINES',
	'WS' => 'SAMOA',
	'SM' => 'SAN MARINO',
	'ST' => 'SAO TOME AND PRINCIPE',
	'SA' => 'SAUDI ARABIA',
	'SN' => 'SENEGAL',
	'RS' => 'SERBIA',
	'SC' => 'SEYCHELLES',
	'SL' => 'SIERRA LEONE',
	'SG' => 'SINGAPORE',
	'SX' => 'SINT MAARTEN (DUTCH PART)',
	'SK' => 'SLOVAKIA',
	'SI' => 'SLOVENIA',
	'SB' => 'SOLOMON ISLANDS',
	'SO' => 'SOMALIA',
	'ZA' => 'SOUTH AFRICA',
	'GS' => 'SOUTH GEORGIA AND THE SOUTH SANDWICH ISLANDS',
	'SS' => 'SOUTH SUDAN',
	'ES' => 'SPAIN',
	'LK' => 'SRI LANKA',
	'SD' => 'SUDAN',
	'SR' => 'SURINAME',
	'SJ' => 'SVALBARD AND JAN MAYEN',
	'SZ' => 'SWAZILAND',
	'SE' => 'SWEDEN',
	'CH' => 'SWITZERLAND',
	'SY' => 'SYRIAN ARAB REPUBLIC',
	'TW' => 'TAIWAN, PROVINCE OF CHINA',
	'TJ' => 'TAJIKISTAN',
	'TZ' => 'TANZANIA, UNITED REPUBLIC OF',
	'TH' => 'THAILAND',
	'TL' => 'TIMOR-LESTE',
	'TG' => 'TOGO',
	'TK' => 'TOKELAU',
	'TO' => 'TONGA',
	'TT' => 'TRINIDAD AND TOBAGO',
	'TN' => 'TUNISIA',
	'TR' => 'TURKEY',
	'TM' => 'TURKMENISTAN',
	'TC' => 'TURKS AND CAICOS ISLANDS',
	'TV' => 'TUVALU',
	'UG' => 'UGANDA',
	'UA' => 'UKRAINE',
	'AE' => 'UNITED ARAB EMIRATES',
	'GB' => 'UNITED KINGDOM',
	'US' => 'UNITED STATES',
	'UM' => 'UNITED STATES MINOR OUTLYING ISLANDS',
	'UY' => 'URUGUAY',
	'UZ' => 'UZBEKISTAN',
	'VU' => 'VANUATU',
	'VE' => 'VENEZUELA, BOLIVARIAN REPUBLIC OF',
	'VN' => 'VIET NAM',
	'VG' => 'VIRGIN ISLANDS, BRITISH',
	'VI' => 'VIRGIN ISLANDS, U.S.',
	'WF' => 'WALLIS AND FUTUNA',
	'EH' => 'WESTERN SAHARA',
	'YE' => 'YEMEN',
	'ZM' => 'ZAMBIA',
	'ZW' => 'ZIMBABWE'
);