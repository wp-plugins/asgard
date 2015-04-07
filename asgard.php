<?php
/*
Plugin Name: Asgard Security Scanner
Plugin URI: https://wordpress.org/plugins/asgard/
Description: One click enterprise security scan. Fast audit the files of your WordPress install for hidden backdoors, code-eval, encrypted iframes and links.
Author: Yuri Korzhenevsky
Author URI: https://github.com/outself
Version: 0.7
*/

/*
This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

// Make sure we don't expose any info if called directly
if ( !function_exists( 'add_action' ) ) {
	echo 'Hi there!  I\'m just a plugin, not much I can do when called directly.';
	exit;
}

require_once ABSPATH . 'wp-admin/includes/file.php';
require_once ABSPATH . 'wp-includes/class-http.php';

// TODO: while send wp-config, replace password to ****
define( 'ASGARD__PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'ASGARD_CHECKSUM', md5( file_get_contents( __FILE__ ) ) );
define( 'ASGARD_API', 'https://asgardapi.com/wordpress/v2beta' );
define( 'ASGARD_EXCLUDE_MASK', '/\/' . basename( WP_CONTENT_DIR ) . '\/(uploads|cache|backup|w3tc)/' );
define( 'ASGARD_PASSPORT', 'https://asgardapi.appspot.com/' );

add_action( 'wp_ajax_asgard_scan_files', 'asgard_scan_files_callback' );
add_action( 'wp_ajax_asgard_remove_malware', 'asgard_remove_malware_callback' );
add_action( 'admin_menu', 'asgard_admin_menu' );
add_action( 'admin_menu', 'asgard_admin_menu' );

function asgard_ext_scan() {
	if ( !asgard_authkey() ) return;
	if ( empty( $_GET['asgard_scan'] ) ) return;

	@ob_end_clean();
	if ( $_GET['asgard_scan'] !== asgard_authkey() ) {
		wp_send_json_error( array( 'error'=>'Invalid auth key' ) );
	}

	$scanner = new AsgardScanner();
	$scanner->scan( ABSPATH );

	$resp = array( 'unknown'=>$scanner->unknown, 'malware'=>$scanner->malware );
	if ( !empty( $scanner->scanres ) ) $resp['scan_result'] = $scanner->scanres;
	if ( !empty( $_GET['plugins_info'] ) ) {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$resp['plugins'] = get_plugins();
	}

	wp_send_json_success( $resp );
}

asgard_ext_scan();

function asgard_authkey( $authkey=null ) {
	if ( $authkey !== null ) {
		update_option( 'asgard_authkey', $authkey );
	}
	return get_option( 'asgard_authkey' );
}

function asgard_get_account( $refresh=false ) {
	if (  !( $account = get_transient( 'asgard_account' ) ) || $refresh ) {
		$plugin_info = is_admin() ? get_plugin_data( __FILE__ ) : array( 'Version'=>'-' );
		$params = array(
			'auth_key' => asgard_authkey(),
			'site_url' => site_url( '/' ) ,
			'admin_email' => get_option( 'admin_email' ) ,
			'client' => 'Wordpress ' . get_bloginfo( 'version' ) ,
			'asgard_checksum' => ASGARD_CHECKSUM,
			'asgard_version' => $plugin_info['Version'],
		);
		$resp = wp_remote_post( 'http://pro.asgardapi.appspot.com/get_account', array( 'body'=>$params, 'timeout'=>5 ) );
		$account_data = wp_remote_retrieve_body( $resp );
		$account = json_decode( $account_data, true );
		if ( !is_array( $account ) ) wp_die( 'unable to fetch asgard account.<br/><pre>'.print_r( $params, 1 ).'</pre>' );
		// 1 day cache
		set_transient( 'asgard_account', $account, DAY_IN_SECONDS );
		// upgrade auth_key
		if ( !empty( $account['auth_key'] ) && $account['auth_key'] !== asgard_authkey() ) {
			asgard_authkey( $account['auth_key'] );
		}
	}
	return $account;
}

function asgard_activate_url() {
	$q = build_query( array(
			'url' => urlencode( site_url( '/' ) ),
			'client' => urlencode( 'Wordpress ' . get_bloginfo( 'version' ) ),
			'return_uri' => urlencode( admin_url( 'admin.php?page=asgard&asgard_authkey={AuthKey}' ) ) )
	);
	return ASGARD_PASSPORT . 'activate?' . $q;
}

function asgard_unlock_status() {
	$till = get_option( 'asgard_unlock_till' );
	if ( !$till ) return false;
	if ( $till <= time() ) return 'renew';
	return true;
}

function asgard_unlock_notice() {
	if ( empty( $_GET['asgard_unlock_status'] ) ) {
		return;
	}

	$account = asgard_get_account( 'refresh' );
	if ( $_GET['asgard_unlock_status'] == 'success' ) {
?>
	<div class="updated">
    		<p>Success! Your full account active until <strong><?php echo date_i18n( get_option( 'date_format' ), $account['payment_until'] ); ?></strong>. </p>
	</div>
<?php } else { ?>
	<div class="error">
	<p>Brr! <?php echo esc_html( $_GET['asgard_unlock_status'] ); ?>. </p>
	</div>
<?php
	}
}

function asgard_activate_notice() {
	if ( !empty( $_GET['asgard_authkey'] ) && is_admin() ) {
		delete_transient( 'asgard_account' );
		asgard_authkey( $_GET['asgard_authkey'] );
	}

	if ( asgard_authkey() ) { return; }

?>
    <div class="updated">
    <p>Asgard Security. Almost done - <a href="<?php echo asgard_activate_url(); ?>">activate your account</a> and protect your blog from malware.</p>
    </div>
    <?php
}
add_action( 'admin_notices', 'asgard_activate_notice' );
add_action( 'admin_notices', 'asgard_unlock_notice' );

function asgard_assets() {
	/* Register our script. */
	wp_register_style( 'asgard', plugins_url( '/style.css', __FILE__ ) , array() , ASGARD_CHECKSUM );
	wp_register_style( 'bootstrap', plugins_url( '/bootstrap.min.css', __FILE__ ) , array() , ASGARD_CHECKSUM );
	wp_enqueue_style( 'asgard' );
	wp_enqueue_style( 'bootstrap' );
}

function asgard_remove_malware_callback() {
	check_ajax_referer( 'asgard-remove-malware', 'security' );
	foreach ( $_POST['files'] as $mw ) {
		$path = base64_decode( $mw );
		if ( !file_exists( $path ) ) {
			continue;
		}

		if ( @unlink( $path ) ) {
			echo '<p class="text-success">' . $path . ' removed</p>';
		}
		else {
			echo '<p class="text-danger">Unable to remove ' . $path . '</p>';
		}
	}
	die;
}

class AsgardTempFile {
	public $file;

	public function __construct( $prefix = '' ) {
		$this->file = tempnam( get_temp_dir() , $prefix );
		register_shutdown_function( array(
				$this,
				'__destruct'
			) );
	}
	public function __toString() {
		return $this->file;
	}
	public function __destruct() {
		@unlink( $this->file );
	}
}

function asgard_html_error( $err ) {
	die( '<p class="text-danger">' . esc_html( $err ) . '</p>' );
}

function asgard_zip_files( $files, $basepath ) {
	$tmpfile = new AsgardTempFile( 'asgard_zip' );

	if ( extension_loaded( 'zip' ) ) {
		$z = new ZipArchive();
		$z->open( $tmpfile, ZIPARCHIVE::CREATE );

		foreach ( $files as $file ) {
			$z->addFile( $file, str_replace( $basepath, '', $file ) );
		}
		$z->close();
	} else if ( file_exists( ABSPATH . 'wp-admin/includes/class-pclzip.php' ) ) {
			require_once ABSPATH . 'wp-admin/includes/class-pclzip.php';
			$archive = new PclZip( $tmpfile->file );
			$archive->add( $files, PCLZIP_OPT_REMOVE_PATH, $basepath );
		} else {
		asgard_html_error( 'Unable to compress files: enable PHP "zip" extension or upgrade Wordpress (with pclzip)' );
	}

	return $tmpfile->file;
}

class AsgardScanner {
	public $files = array();
	public $hashlist = array();
	public $result = array();
	public $scanres = array();

	public $malware = 0;
	public $unknown = 0;

	public function scan( $basepath ) {
		$this->files = array_values( array_filter( list_files( $basepath ), 'asgard_filter_target_file' ) );
		$this->hashlist = array_values( array_map( 'asgard_content_hash', $this->files ) );
		$res = asgard_send_hashes( $this->hashlist );

		$toscan = array();
		foreach ( $res as $index ) {
			$path = $this->files[abs( $index ) - 1];
			$verdict = false;
			if ( $index < 0 ) {
				$toscan[] = $path;
				++$this->unknown;
			}
			else {
				$this->result[$path] = 'Common Malware';
				++$this->malware;
			}
		}
		if ( count( $toscan ) > 0 ) {
			$zip = asgard_zip_files( $toscan, $basepath );
			$scanres = asgard_scan_zip( $zip );
			if ( $scanres && $scanres['match'] ) {
				foreach ( $scanres['verdict'] as $path => $verdict ) {
					$this->result[$basepath . $path] = $verdict;
					++$this->malware;
				}
			}
			$this->scanres = $scanres;
		}

	}
}

function asgard_scan_files_callback() {
	echo '<hr>';
	$t = microtime( true );
	$basepath = ABSPATH;

	$scanner = new AsgardScanner();
	$scanner->scan( $basepath );

	$scanned = count( $scanner->files );
	$url = site_url( '/' );
	$blacklist = asgard_blacklist_check( $url );

	if ( !empty( $blacklist ) ) {
?>
			<h3>Blacklist Check <?php echo $url; ?></h3>
<table class="table blacklist-table">
    <thead>
    <tr>
        <th>Provider</th>
        <th width="45%">Verdict</th>
    </tr>
    </thead>

    <tbody id="the-list">
    <?php
		foreach ( $blacklist as $bl ):
			$icon_url = plugins_url( '/icons/' . esc_attr( preg_replace( '/[^\w]/i', '_', strtolower( $bl['Source'] ) ) ) . '.ico', __FILE__ );
?>
		<tr id="akismet"<?php if ( $bl['Verdict'] && $bl['Verdict'] != 'NOT_FOUND' ) { echo ' class="danger"'; } ?>>
			<td>
				<img src="<?php echo $icon_url; ?>" width="16" height="16" alt=""/ class="asgard-blacklist-icon">
					<strong><?php echo esc_html( $bl['Source'] ); ?></strong>
			</td>
			<td class="success">
			<?php
		if ( is_array( $bl['Verdict'] ) ) { echo implode( '<br>', $bl['Verdict'] ); } else
			echo ( $bl['Verdict'] == 'NOT_FOUND' || !$bl['Verdict'] ) ? 'Clean' : esc_html( $bl['Verdict'] ); ?>
			</td>
    		</tr>
		<?php
		endforeach; ?>
    </tbody>
</table>

<p></p>
<h3>Malware Deep Scan</h3>
<?php
	}
	echo '<p>' . sprintf( _n( '%d file scanned', '%d files scanned', $scanned, 'asgard' ), $scanned ) . ' in ' . sprintf( '%.3f', microtime( true ) - $t ). ' sec.</p>';

	if ( !count( $scanner->result ) ) {
		echo '<p class="alert alert-success">No known malware in files found.</p>';
		die;
	}

?>

<table class="table table-hover">
    <thead>
    <tr>
        <th width="20%" scope="col" id="verdict" class="manage-column column-name">Verdict</th>
        <th scope="col" id="description" class="manage-column column-description">File</th>
    </tr>
    </thead>

    <tbody id="the-list">
    <?php
	foreach ( $scanner->result as $path => $verdict ): ?>
    <tr id="akismet" class="danger">
	<td><strong><?php echo $verdict; ?></strong></td>
        <td class="column-description desc mw-file" data-path="<?php echo base64_encode( $path ); ?>">
		<?php echo $path; ?>
        </td>
    </tr>
	<?php
	endforeach; ?>
    </tbody>
</table>

<button class="btn btn-danger remove-malware">Remove Files</button>

<p class="text-muted pull-right">Scan time: <?php
	echo round( microtime( true ) - $t, 3 ); ?> sec</p>
<?php
	die();
}


function asgard_admin_menu() {
	add_menu_page( 'Asgard Security', 'ASGARD', 'manage_options', 'asgard', 'asgard_ep', plugins_url( '/icon_small.png', __FILE__ ) );
}

function asgard_unlock_url( $action='new' ) {
	$siteurl = site_url( '/' );
	$q = build_query( array(
			'action' => $action,
			'site_url' => urlencode( $siteurl ),
			'client' => urlencode( 'Wordpress ' . get_bloginfo( 'version' ) ),
			'return_uri' => urlencode( admin_url( 'admin.php?page=asgard' ) ) )
	);
	return 'http://pro.asgardapi.appspot.com/unlock?' . $q;
}

function asgard_ep() {
	if ( !asgard_authkey() ) return;
	asgard_assets();
	$ajax_nonce = wp_create_nonce( 'asgard-remove-malware' );
?>
	<div class="wrap asgard">
	<h2>Asgard Security Scanner</h2>
	<button class="btn btn-large btn-primary scanit"><span>Scan for Malware</span></button>
	<?php $account = asgard_get_account(); ?>
	<img src="<?php echo plugins_url( '/loading.gif', __FILE__ ); ?>" width="16" height="16" class="asgard-scan-progress" />
	<br class="clear">
	<p class="text-muted">Please, give us your feedback to <a href="https://www.hipchat.com/g8VLm5ka8" target="_blank">team HipChat</a></p>
	<div class="scan-result"></div>
	</div>

<script type="text/javascript">
jQuery(document).ready(function($) {
        $('.scanit').click(function(){
                var $btn = $(this);
                $btn.prop('disabled', true);
                $btn.text('Scanning...');
		$('.asgard-scan-progress').show();
                $('.scan-result').html('').fadeOut();

                $.post(ajaxurl, {action: 'asgard_scan_files'}, function(response) {
                        $('.scan-result').html(response).fadeIn();
                }).always(function(){
                        $btn.text('Scan for Malware');
                        $btn.prop('disabled', false);
			$('.asgard-scan-progress').hide();
                });
        });

        $('.remove-malware').live('click', function(){
		if (!confirm('DANGER! This action completely remove files WITHOUT BACKUP. Use at own RISK.')) return;
                var files = $('.mw-file').map(function(){ return $(this).data('path'); }).get();
                $.post(ajaxurl, {action: 'asgard_remove_malware', files: files, security: '<?php
	echo $ajax_nonce; ?>'}, function(response) {
                        $('.scan-result').html(response);
                });
        });
});
</script>

<?php
}


function asgard_filter_target_file( $filepath ) {
	$extensions = array(
		'php',
		'php5',
		'php4',
		'phtml',
		'html',
		'htaccess',
		'tpl',
		'inc',
		'txt'
	);
	return !is_dir( $filepath ) && !preg_match( ASGARD_EXCLUDE_MASK, $filepath ) && in_array( pathinfo( $filepath, PATHINFO_EXTENSION ) , $extensions );
}


function asgard_content_hash( $filepath ) {
	$md5 = md5_file( $filepath );
	return implode( ' ', array(
			$md5,
			filesize( $filepath ) ,
			str_replace( ABSPATH . DIRECTORY_SEPARATOR, '', $filepath ) ,
		) );
}

function asgard_api_post( $url, $body, $json=false ) {
	$ch = curl_init();
	curl_setopt( $ch, CURLOPT_URL, $url );
	curl_setopt( $ch, CURLOPT_POST, 1 );
	curl_setopt( $ch, CURLOPT_POSTFIELDS, $body );
	curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
	curl_setopt( $ch, CURLOPT_CONNECTTIMEOUT, 2 );
	curl_setopt( $ch, CURLOPT_TIMEOUT, 60 );
	curl_setopt( $ch, CURLOPT_VERBOSE, true );
	$verbose = fopen( 'php://temp', 'rw+' );
	curl_setopt( $ch, CURLOPT_STDERR, $verbose );

	$authkey = asgard_authkey();
	if ( !$authkey ) {
		asgard_html_error( 'asgard_authkey option not found. Please, activate access.' );
	}
	$headers = array( 'X-AuthKey: ' . $authkey );

	if ( $json ) $headers[]='Content-Type: application/json; charset=utf-8' ;
	curl_setopt( $ch, CURLOPT_HTTPHEADER, $headers );

	$result = curl_exec( $ch );
	$errno = curl_errno( $ch );

	rewind( $verbose );
	if ( function_exists( 'stream_get_contents' ) ) { $verbose = stream_get_contents( $verbose ); } else { $verbose = '(no verbose info: stream_get_contents function not disables)'; }
	if ( $errno != 0 ) {
		echo '<p>'.nl2br( $verbose ).'</p>';
		asgard_html_error( sprintf( 'POST %s: error=%s code=%d', $url, $errno, curl_error( $ch ) ) );
	}

	$http_status = curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	if ( $http_status != 200 ) {
		echo '<p>'.nl2br( $verbose ).'</p>';
		asgard_html_error( sprintf( 'POST %s error: code=%d. Please, try again later.', $url, $http_status ) );
	}

	curl_close( $ch );
	return json_decode( $result, true );
}

function asgard_scan_zip( $path ) {
	return asgard_api_post( ASGARD_API . '/scan_zip', array( 'file' => '@' . $path ) );
}

function asgard_blacklist_check( $url ) {
	$resp = wp_remote_get( 'https://asgardapi.com/safeurl/v2beta/lookup?url=' . urlencode( $url ), array() );
	$result = json_decode( $resp['body'], true );
	return is_array( $result['results'] ) ? $result['results'] : array();
}

function asgard_send_hashes( $hashlist ) {
	$body = json_encode( array(
			'hash' => $hashlist
		) );
	// send blog url and email for auth
	// TODO: hack for ext scan
	$plugin_info = is_admin() ? get_plugin_data( __FILE__ ) : array( 'Version'=>'' );
	$q = build_query( array(
			'locale' => get_locale(),
			'checksum' => md5( $body ) ,
			'site_url' => site_url( '/' ) ,
			'admin_email' => get_option( 'admin_email' ) ,
			'wp_version' => get_bloginfo( 'version' ) ,
			'asgard_checksum' => ASGARD_CHECKSUM,
			'asgard_version' => $plugin_info['Version'],
		) );

	$result = asgard_api_post( ASGARD_API . '/check?' . $q, $body, 'json' );
	return is_array( $result['result'] ) ? $result['result'] : array();
}
