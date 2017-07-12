=== Cerber Security & Limit Login Attempts ===
Contributors: gioni
Donate link: https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=SR8RJXFU35EW8
Tags: security, login, custom login, protect, woocommerce, antispam, recaptcha, captcha, activity, log, logging, block, fail2ban, monitoring, rename wp login, whitelist, blacklist, wordpress security, xmlrpc, user enumeration, hardening, authentication, notification, pushbullet, brute force, bruteforce, users
Requires at least: 4.4
Tested up to: 4.8
Stable tag: 4.8.2
License: GPLv2

Protection against brute force attacks and bots. Restrict login by IP access lists. Track user and bot activity. Limit login attempts. reCAPTCHA.

== Description ==

Defends WordPress against brute force attacks by limiting the number of login attempts through the login form, XML-RPC / REST API requests or using auth cookies.
Restricts access with a Black IP Access List and a White IP Access List.
Tracks user and intruder activity with powerful email, mobile and desktop notifications.
Stop spam: activates reCAPTCHA for protecting registration and comments forms.
Hardening WordPress.

**Features you will love**

* Limit login attempts when logging in by IP address or entire subnet.
* Monitors logins made by login forms, XML-RPC requests or auth cookies.
* Permit or restrict access by [White IP Access list and Black IP Access List](http://wpcerber.com/using-ip-access-lists-to-protect-wordpress/) with a single IP, IP range or subnet.
* Log all activities related to the logging in/out process.
* Cool notifications with powerful filters
* Hide wp-login.php, wp-signup.php and wp-register.php from possible attacks and return 404 HTTP Error.
* Hide wp-admin (dashboard) and return 404 HTTP Error when a user isn't logged in.
* Create **Custom login URL** ([rename wp-login.php](http://wpcerber.com/how-to-rename-wp-login-php/)).
* Immediately block IP or subnet when attempting to log in with non-existent or prohibited username.
* Disable WP REST API
* Disable XML-RPC (block access to the XML-RPC interface including Pingbacks and Trackbacks)
* Disable feeds (block access to the RSS, Atom and RDF feeds)
* Restrict access to XML-RPC, REST API and feeds by **White IP Access list** with IP or IP range.
* Disable automatic redirecting to login page.
* **Stop user enumeration** (block access to the pages like /?author=n)
* Proactively **block IP subnet class C** for intruder's IP.
* Antispam: **reCAPTCHA** to protect WordPress register and comment forms.
* [reCAPTCHA for WooCommerce & WordPress forms](http://wpcerber.com/how-to-setup-recaptcha/).
* Invisible reCAPTCHA for WordPress comments forms
* Citadel mode for **massive brute force attack**.
* [Play nice with **fail2ban**](http://wpcerber.com/how-to-protect-wordpress-with-fail2ban/): write failed attempts to the syslog or a custom log file.
* Filter out and inspect activities by IP address, user, username or a particular activity.
* Filter out activities and export them to a CSV file.
* Limit login attempts works on a site/server behind a reverse proxy.
* [Notifications by email or mobile push notifications](http://wpcerber.com/wordpress-notifications-made-easy/).
* Trigger and action for the [jetFlow.io automation plugin](http://jetflow.io).

= Limit login attempts done right =

By default, WordPress allows unlimited login attempts through the login form, XML-RPC or by sending special cookies. This allows passwords to be cracked with relative ease via brute force attack.

WP Cerber blocks intruders by IP or subnet from making further attempts after a specified limit on retries is reached, making brute force attacks or distributed brute force attacks from botnets impossible.

You will be able to create a **Black IP Access List** or **White IP Access List** to block or allow logins from a particular IP address, IP address range or a subnet any class (A,B,C).

Moreover, you can create your Custom login page and forget about automatic attacks to the default wp-login.php, which takes your attention and consumes a lot of server resources. If an attacker tries to access wp-login.php they will be blocked and get a 404 Error response.

= Log, filter out and export activities =

WP Cerber tracks time, IP addresses and usernames for successful and failed login attempts, logins, logouts, password changes, blocked IP and actions taken by itself. You can export them to a CSV file.

= Limit login attempts reinvented =

You can **hide WordPress dashboard** (/wp-admin/) when a user isn't logged in. If a user isn't logged in and they attempt to access the dashboard by requesting /wp-admin/, WP Cerber will return a 404 Error.

Massive botnet brute force attack? That's no longer a problem. **Citadel mode** will automatically be activated for awhile and prevent your site from making further attempts to log in with any username.

= Antispam protection: invisible reCAPTCHA for WooCommerce =

* WooCommerce login form
* WooCommerce register form
* WooCommerce lost password form

= Antispam protection: invisible reCAPTCHA for WordPress =

* WordPress login form
* WordPress register form
* WordPress lost password form
* WordPress comment form

**Documentation & Tutorials**

* [How to set up notifications](http://wpcerber.com/wordpress-notifications-made-easy/)
* [Push notifications with Pushbullet](http://wpcerber.com/wordpress-mobile-and-browser-notifications-pushbullet/)
* [How to set up invisible reCAPTCHA for WooCommerce](http://wpcerber.com/how-to-setup-recaptcha/)
* [Changing default plugin messages](http://wpcerber.com/wordpress-hooks/)
* [Best alternatives to the Clef plugin](http://wpcerber.com/two-factor-authentication-plugins-for-wordpress/)
* [Why reCAPTCHA does not protect WordPress from bots and brute-force attacks](http://wpcerber.com/why-recaptcha-does-not-protect-wordpress/)

**Translations**

* Czech, thanks to [Hrohh](https://profiles.wordpress.org/hrohh/)
* Deutsche, thanks to mario, Mike and [Daniel](http://detacu.de)
* Dutch, thanks to [Bernardo](https://twitter.com/bernardohulsman)
* Français, thanks to [hardesfred](https://profiles.wordpress.org/hardesfred/)
* Norwegian (Bokmål), thanks to [Eirik Vorland](https://www.facebook.com/KjellDaSensei)
* Portuguese, thanks to [Felipe Turcheti](http://felipeturcheti.com)
* Spanish, thanks to Ismael and [leemon](https://profiles.wordpress.org/leemon/)
* Український, thanks to [Nadia](https://profiles.wordpress.org/webbistro)
* Русский, thanks to [Yui](https://profiles.wordpress.org/fierevere/)

Thanks to [POEditor.com](https://poeditor.com) for helping to translate this project.

There are some semi-similar security plugins you can check out: Login LockDown, Login Security Solution,
BruteProtect, Ajax Login & Register, Lockdown WP Admin,
BulletProof Security, SiteGuard WP Plugin, All In One WP Security & Firewall, Brute Force Login Protection

**Another reliable plugins from the trusted author**

* [Plugin Inspector reveals issues with installed plugins](https://wordpress.org/plugins/plugin-inspector/)

Checks plugins for deprecated WordPress functions, known security vulnerabilities, and some unsafe PHP functions

* [Translate sites with Google Translate Widget](https://wordpress.org/plugins/goo-translate-widget/)

Make your website instantly available in 90+ languages with Google Translate Widget. Add the power of Google automatic translations with one click.

== Installation ==

Installing the WP Cerber security plugin is the same as other WordPress plugins.

1. Install the plugin through Plugins > Add New > Upload or unzip plugin package into wp-content/plugins/.
2. Activate the WP Cerber through the Plugins > Installed Plugins menu in the WordPress admin dashboard.
3. The plugin is now active and has started protecting your WordPress with default settings.
4. Make sure, that you received a notification letter with your site admin email.

**Important notes**

1. Before enabling invisible reCAPTCHA, you must get separate keys for invisible version. [How to enable reCAPTCHA](http://wpcerber.com/how-to-setup-recaptcha/).
2. If you want to test out plugin's features, do this from another computer and remove that computer's network from the White Access List. Cerber is smart enough to recognize "the boss".
3. If you've set up the Custom login URL and you use some caching plugin like **W3 Total Cache** or **WP Super Cache**, you have to add a new Custom login URL to the list of pages not to cache.
4. [Read this if your website is under CloudFlare](http://wpcerber.com/cloudflare-and-wordpress-cerber/)
5. If you use the Jetpack plugin or another plugin that needs to connect to wordpress.com, you need to unlock XML-RPC. To do that go to the Hardening tab, uncheck Disable XML-RPC, and click the Save changes button.

The following steps are optional but they allow you to reinforce the protection of your WordPress.

1. Fine tune **Limit login attempts** settings making them more restrictive according to your needs
2. Configure your **Custom login URL** and remember it (the plugin will send you an email with it).
3. Once you have configured Custom login URL, check 'Immediately block IP after any request to wp-login.php' and 'Block direct access to wp-login.php and return HTTP 404 Not Found Error'. Don't use wp-admin to log in to your WordPress dashboard anymore.
4. If your WordPress has a few experienced users, check 'Immediately block IP when attempting to log in with a non-existent username'.
5. Specify the list of prohibited usernames (logins) that legit users will never use. They will not be allowed to log in and register in any circumstances.
6. Configure mobile and browser notifications via Pushbullet.
7. Obtain keys and enable invisible reCAPTCHA for password reset and registration forms (WooCommerce supported too).


== Frequently Asked Questions ==

= Can I use the plugin with CloudFlare? =

Yes.  [WP Cerber settings for CloudFlare](http://wpcerber.com/cloudflare-and-wordpress-cerber/).

= Is this plugin compatible with WordPress multisite mode? =

Yes. All settings apply to all sites in the network simultaneously. You have to activate the plugin in the Network Admin area on the Plugins page. Just click on the Network Activate link.

= Is WP Cerber compatible with bbPress? =

Yes. [Compatibility notes](http://wpcerber.com/compatibility/).

= Is this plugin compatible with WooCommerce? =

Completely.

= Is reCAPTCHA for WooCommerce free feature? =

Yes. [How to set up reCAPTCHA for WooCommerce](http://wpcerber.com/how-to-setup-recaptcha/).

= Can I change login URL (rename wp-login.php)? =

Yes, easily. [How to rename wp-login.php](http://wpcerber.com/how-to-rename-wp-login-php/)

= Can I hide wp-admin? =

Yes, easily. [How to hide wp-admin and wp-login.php from possible attacks](http://wpcerber.com/how-to-hide-wp-admin-and-wp-login-php-from-possible-attacks/)

= Can I rename wp-admin folder? =

Nope. It's not possible and not recommended for compatibility reasons.

= Can WP Cerber work together with the Limit Login Attempts plugin? =

Nope. WP Cerber is a drop in replacement for that outdated plugin.

= Can WP Cerber protect my site from DDoS attacks? =

Nope. WP Cerber protects your site from Brute force attacks or distributed Brute force attacks. By default WordPress allows unlimited login attempts either through the login form or by sending special cookies. This allows passwords to be cracked with relative ease via a brute force attack. To prevent from such a bad situation use WP Cerber.

= Is there any WordPress plugin to protect my site from DDoS attacks? =

Nope. This hard task cannot be done by using a plugin. That may be done by using special hardware from your hosting provider.

= What is the goal of Citadel mode? =

Citadel mode is intended to block massive, distributed botnet attacks and also slow attacks. The last type of attack has a large range of intruder IPs with a small number of attempts to login per each.

= How to turn off Citadel mode completely? =

Set Threshold fields to 0 or leave them empty.

= What is the goal of using Fail2Ban? =

With Fail2Ban you can protect site on the OS level with iptables. See details here: [http://wpcerber.com/how-to-protect-wordpress-with-fail2ban/](http://wpcerber.com/how-to-protect-wordpress-with-fail2ban/)

= Do I need using Fail2Ban to get the plugin working? =

No, you don't. It is optional.

= Can I use this plugin on the WP Engine hosting? =

Yes! WP Cerber is not on the list of disallowed plugins. There are no limitation on the hosting providers. You can use it even on the shared hosting. Plugin consumes minimum resources and does not impact server performance or response time.

= It seems that old activity records are not removing from the activity log =

That means that scheduled tasks are not executed on your site. In other words, WordPress cron is not working the right way.
Try to add the following line to your wp-config.php file:

define( 'ALTERNATE_WP_CRON', true );

= I'm unable to log in / I'm locked out of my site / How to get access (log in) to the dashboard? =

There is a special version of the plugin called **WP Cerber Reset**. This version performs only one task. It will reset all WP Cerber settings to initial values (excluding Access Lists) and then will deactivate itself.

To get access to your dashboard you need to copy the WP Cerber Reset folder to the plugins folder. Follow these simple steps.

1. Download the wp-cerber-reset.zip archive to your computer using this link: [http://wpcerber.com/downloads/wp-cerber-reset.zip](http://wpcerber.com/downloads/wp-cerber-reset.zip)
2. Unpack wp-cerber folder from the archive.
3. Upload the wp-cerber folder to the **plugins** folder of your site using any FTP client or a file manager from your hosting control panel. If you see a question about overwriting files, click Yes.
4. Log in to your site as usually. Now WP Cerber is disabled completely.
5. Reinstall the WP Cerber plugin again. You need to do that, because **WP Cerber Reset** cannot work as a normal plugin.

== Screenshots ==

1. The Dashboard: Recently recorded important security events and recently locked out IP addresses.
2. WordPress activity log with filtering, export to CSV and powerful notifications. You can see what's going on right now, when an IP reaches the limit of login attempts and when it was blocked.
3. Activity log filtered by login and specific type of activity. Export it or click Subscribe to be notified with each event.
4. Detailed information about an IP address with WHOIS information.
5. These settings allows you to customize the plugin according to your needs.
6. White and Black IP access lists allow you to restrict access from a particular IP address, network or IP range.
7. Hardening WordPress: disable REST API, XML-RPC and stop user enumeration.
8. Powerful email, mobile and browser notifications for WordPress events.
9. Stop spammer: visible/invisible reCAPTCHA for WooCommerce and WordPress forms - no spam comments anymore.
10. You can export and import security settings and IP Access Lists on the Tools screen.
11. Beautiful widget for the WP dashboard to keep an eye on things. Get quick analytic with trends over last 24 hours.
12. WP Cerber adds four new columns on the WordPress Users screen: Date of registration, Date of last login, Number of failed login attempts and Number of comments. To get more information just click on the appropriate link.


== Changelog ==

= 4.8.1 =
* New: Starting with this version all database tables will be created with a default database engine. It should be InnoDB.
* New: To improve compatibility with some plugins the email notification function has been updated and now uses the comma-separated list of email addresses instead of an array.
* Bug fixed: An IP address from a range will not be allowed to log in if you have overlapping IP ranges in the both IP Access List.
* Bug fixed: A reason of blocking an IP address is not shown in notification emails if Always block entire subnet Class C of intruders IP is selected in the settings.

= 4.8 =
* New: You can enable/disable applying limit login rules to IP addresses in the White IP Access List.
* New: Block malicious IP addresses after a specified number of failed attempts to solve visible or invisible reCAPTCHA.
* New: Track password reset requests with username entered.

= 4.7.7 =
* New: invisible reCAPTCHA (classic, visible also available).
* New: reCAPTCHA for comment forms. Works well as anti-spam tool.
* Fixed bug: "Add network to the Black List" and "Add IP to the Black List" buttons on the Activity tab doesn't work in the Safari web browser.

= 4.5 =
* New: Instant mobile and browser notifications with Pushbullet.
* New: Ability to choose a 404 page template.
* New: Events on the Activity tab are displaying with user roles and avatars.
* Update: PHP function file_get_contents() has been replaced with cURL to improve compatibilty with restrictive hostings.
* Fixed bug: Password reset link that is generated by the WooCommerce reset password form can be corrupted if reCAPTCHA is enabled for the form.
* Fixed bug: The plugin doesn’t block IPv6 addresses from the Black IP Access List (versions affected: 4.0 – 4.3).

= 4.3 =
* New: Use powerful subscriptions to get email notifications according to filters for events you have set.
* New: Search and/or filter activity by IP address, username (login), specific event and a user. You may use any combination of them.
* New: Now you can export activity from your WordPress website to a CSV file. You may export all activities or just a set of filtered out activities.
* Update: Now you can specify multiple email boxes for notifications.
* Update: The Spanish translation has been updated, thanks to [leemon](https://profiles.wordpress.org/leemon/).

= 4.1 =
* New: Date format field allows you to specify a desirable format for displaying dates and time.
* Updated code for registration_errors filter to handle errors right way.
* The French translation has been updated.
* Fixed issue: Loading settings from a file with reCAPTCHA key and secret on a different website overwrite existing reCAPTCHA key and secret with values from the file.
* Fixed bug: The plugin tries to validate reCAPTCHA on WooCommerce login form if the validation enabled for the default WordPress login form only.

= 4.0 =
* New: reCAPTCHA for WooCommerce forms. [How to set up reCAPTCHA](http://wpcerber.com/how-to-setup-recaptcha/).
* New: IP Access Lists has got support for IP networks in three forms: ability to restrict access with IPv4 ranges, IPv4 CIDR notation and IPv4 subnets: A,B,C has been added. [Access Lists for WordPress](http://wpcerber.com/using-ip-access-lists-to-protect-wordpress/).
* New: Cerber can automatically detect an IP network of an intruder and suggest you to block entire network right from the Activity screen.
* New: Norwegian translation added, thanks to [Eirik Vorland](https://www.facebook.com/KjellDaSensei).
* Update: WP REST API is controlled by Access Lists. While REST API is blocked for the rest of the world, IP addresses from the White Access List can use WP REST API.
* Update: The WP Cerber admin menu is moved from Settings to the main admin menu.
* Update: To make Cerber more compatible with other plugins, the order of the init hook on the Custom login page (Custom login URL) has been changed.
* Update: Several languages and translations has been updated.
* Update: Large amount of code has been rewritten to improve performance and stability.
* Fixed bug: If a hacker or a bot uses login from the list of prohibited usernames or non-existent username, Citadel mode is unable to be automatically activated.
* Fixed bug: reCAPTCHA for an ordinary WordPress login form is incompatible with a WooCommerce login form.
* Fixed issue: In some cases the plugin log first digits of an IP address as an ID of existing user.

= 3.0 =
* New: [reCAPTCHA to protect WordPress forms spam registrations. Also available for lost password and login forms.](http://wpcerber.com/how-to-setup-recaptcha/)
* New: Registration, XML RCP, WP REST API are controlled by IP Access Lists now. If a particular IP address is locked out or blacklisted registration is impossible.
* New: Action Get WHOIS info and trigger IP locked out to create automation scenarios with the [jetFlow.io automation plugin](http://jetflow.io).
* New: Notification emails will contain Reason of a lockout.
* New: The activity DB table will be optimized after removing old records daily.
* Update: Column Username on the Activity tab now shows real value that submitted with WordPress login form.
* Update: Text domain is updated to 'wp-cerber'
* Fixed issue: If a user enter correct email address and wrong password to log in, IP address is locked immediately.

= 2.9 =
* New: Checking for a prohibited username (login). You can specify list of logins manually on the new settings page (Users).
* New: Rate limiting for notification letters. Set it on the main settings page.
* New: If new user registration disabled, automatic redirection from wp-register.php to the login page is blocked (404 error). Remote IP will be locked out.
* New: You can set user session expiration timeout.
* New: Define constant CERBER_IP_KEY if you want the plugin to use it as a key to get IP address from $_SERVER variable.
* Update: Improved WP-CLI compatibility.
* Update: All dates are displayed in a localized format with date_i18n function.
* Fixed bugs: incorrect admin URL in notification letters for multisite with multiple domains configuration, lack of error message on the login form if IP is blocked, CSRF vulnerability on the import settings page
* Removed calls of deprecated function get_currentuserinfo().

= 2.7.2 =
* Fixed bug for non-English WordPress configuration: the plugin is unable to block IP in some server environment. If you have configured language other than English you have to install this release.

= 2.7.1 =
* Fixed two small bugs related to 1) unable to remove IP subnet from the Access Lists and 2) getting IP address in case of reverse proxy doesn't work properly.

= 2.7 =

* New: Now you can view extra WHOIS information for IP addresses in the activity log including country, network info, abuse contact, etc.
* New: Added ability to disable WP REST API, see [Hardening WordPress](http://wpcerber.com/hardening-wordpress/)
* New: Added ability to add IP address to the Black List from the Activity tab. Nail it!
* New: Added Spanish translation, thanks to Ismael.
* New: Added ability to set numbers of displayed rows (lines) on the Activity and Lockout tabs. Click Screen Options on the top-right.
* Fixed minor security issue: Actions to remove IP on the Access Lists tab were not protected against CSRF attacks. Thanks to Gerard.
* Update: Small changes on the dashboard widget.
* Update: Action taken by the plugin (plugin makes a decision) now marked with dark vertical bar on the right side of the labels (Activity tab).

= 2.0.1.6 =
* New: Added Reason column on the Lockouts screen which will display cause of blocking particular IP.
* New: Added Hardening WP with options: disable XML-RPC completely, disable user enumeration, disable feeds (RSS, Atom, RSD).
* New: Added Custom email address for notifications.
* New: Added Dutch and Czech translations.
* New: Added Quick info about IP on Activity tab.
* Update: Removed option 'Allow whitelist in Citadel mode'. Now this whitelist is enabled by default all the time.
* Update: For notifications on the multisite installation the admin email address from the Network Settings will be used.
* Fixed Bug: Disable wp-login.php doesn't work for subfolder installation.
* Fixed Bug: Custom login URL doesn't work without trailing slash.
* Fixed Bug: Any request to wp-signup.php reveal hidden Custom login URL.

= 1.9 =
* Code refactoring and cleaning up.
* Unlocalized strings was localized.

= 1.8.1 =
* Fixed minor bug: no content (empty cells) in the custom colums added by other plugins on the Users screen in the Dashboard.

= 1.8 =
* New! added Hostname column for the Activity and Lockouts tabs.
* New! added ability to write failed login attempts to the specified file or to the syslog file. Use it to protect site with fail2ban.
* Added Ukrainian translation (Український переклад).

= 1.7 =
* Added ability to remove old records from the user activity log. Log will be cleaned up automatically. Check out new Keep records for field on the settings page.
* Added pagination for the Activity and Lockouts tabs.
* Added German (Deutsch) translation, thanks to mario.
* Added ability to reset settings to the recommended defaults at any time.

= 1.6 =
* New: beautiful widget for the dashboard to keep an eye on things. Get quick analytic with trends over 24 hours and ability to manually deactivate Citadel mode.
* French translation added, thanks to hardesfred.
* Hardening WordPress. Removed automatically redirection from /login/ to the login page, from /admin/ and /dashboard/ to the dashboard.
* Fixed issue with lost password link in the multisite mode.
* Now compatible with User Switching plugin.
* Added ability to manually deactivate Citadel mode, once it automatically switches on.

= 1.5 =
* New feature: importing and exporting settings and access lists from/to the file.
* Limited notifications in the dashboard.

= 1.4 =
* Added support Multisite mode for limit login attempts.
* Added Number of comments column on the Users screen in dashboard.
* Updated notification settings.
* Updated languages files.

= 1.3 =
* Fixed issue with hanging up during redirect to /wp-admin/ on some circumstance.
* Fixed minor issue with limit login attempts for non-admin users.
* Added Date of registration column on the Users screen in dashboard.
* Some UI improvements on access-list screen.
* Performance optimization & code refactoring.

= 1.2 =
* Added localization & internationalization files. You can use Loco Translate plugin to make your own translation.
* Added Russian translation.
* Added headers for failed attempts to use such headers with [fail2ban](http://www.fail2ban.org).

= 1.1 =
* Added ability to filter out Activity List by IP, username or particular event. You can see what happens and when it happened with particular IP or username. When IP reaches limit login attempts and when it was blocked.
* Added protection from adding to the Black IP Access List subnet belongs to current user's session IP.
* Added option to work with site/server behind reverse proxy.
* Update installation instruction.

= 1.0 =
* Initial version

== Other Notes ==

1. If you want to test out plugin's features, do this from another computer and remove that computer's network from the White Access List. Cerber is smart enough to recognize "the boss".
2. If you've set up the Custom login URL and you use some caching plugin like **W3 Total Cache** or **WP Super Cache**, you have to add a new Custom login URL to the list of pages not to cache.
3. [Read this if your website is under CloudFlare](http://wpcerber.com/cloudflare-and-wordpress-cerber/)

**Deutsche**
Schützt vor Ort gegen Brute-Force-Attacken. Umfassende Kontrolle der Benutzeraktivität. Beschränken Sie die Anzahl der Anmeldeversuche durch die Login-Formular, XML-RPC-Anfragen oder mit Auth-Cookies. Beschränken Sie den Zugriff mit Schwarz-Weiß-Zugriffsliste Zugriffsliste. Track Benutzer und Einbruch Aktivität.

**Français**
Protège site contre les attaques par force brute. Un contrôle complet de l'activité de l'utilisateur. Limiter le nombre de tentatives de connexion à travers les demandes formulaire de connexion, XML-RPC ou en utilisant auth cookies. Restreindre l'accès à la liste noire accès et blanc Liste d'accès. L'utilisateur de la piste et l'activité anti-intrusion.

**Український**
Захищає сайт від атак перебором. Обмежте кількість спроб входу через запити ввійти форми, XML-RPC або за допомогою авторизації в печиво. Обмежити доступ з чорний список доступу і список білий доступу. Користувач трек і охоронної діяльності.

**What does "Cerber" mean?**

Cerber is derived from the name Cerberus. In Greek and Roman mythology, Cerberus is a multi-headed dog with a serpent's tail, a mane of snakes, and a lion's claws. Nobody can bypass this angry dog. Now you can order WP Cerber to guard the entrance to your site too.


