<?php
/*
Plugin Name: Asgard Security - One click security audit
Plugin URI: https://wordpress.org/plugins/asgard/
Description: One click enterprise security scan. Fast audit the files of your WordPress install for hidden backdoors, code-eval, encrypted iframes and links.
Author: Yuri Korzhenevsky
Author URI: https://github.com/outself
Version: 0.1
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
define( 'ASGARD_API', 'https://asgardapi.com/wordpress/v1beta' );
define( 'ASGARD_EXCLUDE_MASK', '/\/' . basename( WP_CONTENT_DIR ) . '\/(uploads|cache|backup|w3tc)/' );

add_action( 'wp_ajax_asgard_scan_files', 'asgard_scan_files_callback' );
add_action( 'wp_ajax_asgard_remove_malware', 'asgard_remove_malware_callback' );
add_action( 'admin_menu', 'asgard_admin_menu' );

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

function asgard_scan_files_callback() {
	echo '<hr>';
	$t = microtime( true );
	$basepath = ABSPATH;
	$files = list_files( $basepath );
	$files = array_filter( $files, 'asgard_filter_target_file' );
	$files = array_values( $files );
	$hashlist = array_map( 'asgard_content_hash', $files );
	$hashlist = array_values( $hashlist );
	$res = asgard_send_hashes( $hashlist );
	if ( is_wp_error( $res ) ) {
		die( '<div class="error"><p>' . $res->get_error_message() . '</p></div>' );
	}
	$result = array();
	$toscan = array();
	foreach ( $res as $index ) {
		$path = $files[abs( $index ) - 1];
		$verdict = false;
		if ( $index < 0 ) {
			$toscan[] = $path;
		}
		else {
			$result[$path] = 'Common Malware';
		}
	}
	if ( count( $toscan ) > 0 ) {
		$zip = asgard_zip_files( $toscan, $basepath );
		$scanres = asgard_scan_zip( $zip );
		if ( $scanres && $scanres['match'] ) {
			foreach ( $scanres['verdict'] as $path => $verdict ) {
				$result[$basepath . $path] = $verdict;
			}
		}
	}
	if ( !count( $result ) ) {
		echo '<p class="alert alert-success">Success! No known malware found.</p>';
		echo '<p class="text-muted pull-right">Scan time: ' . round( microtime( true ) - $t, 3 ) . ' sec</p>';
		die;
	}
?>
<h3>Dangerous Files</h3>

<table class="table table-hover">
    <thead>
    <tr>
        <th width="20%" scope="col" id="verdict" class="manage-column column-name">Verdict</th>
        <th scope="col" id="description" class="manage-column column-description">File</th>
    </tr>
    </thead>

    <tbody id="the-list">
    <?php
	foreach ( $result as $path => $verdict ): ?>
    <tr id="akismet" class="danger">
	<td><strong><?php
		echo $verdict; ?></strong></td>
        <td class="column-description desc mw-file" data-path="<?php
	echo base64_encode( $path ); ?>">
		<?php
	echo $path; ?>
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


function asgard_ep() {
	asgard_assets();
	$ajax_nonce = wp_create_nonce( 'asgard-remove-malware' );
?>
	<div class="wrap">
	<h2>Asgard Security Scanner</h2>
	<button class="btn btn-large btn-primary scanit">
		<span>Scan for Malware</span>
	</button>
	<img src="<?php echo plugins_url( '/loading.gif', __FILE__ ); ?>" width="16" height="16" class="asgard-scan-progress" />

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
		if (!confirm('DANGER! This action completely remove files and backup it with random prefix. Use at own RISK.')) return;
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
	if ( $json ) curl_setopt( $ch, CURLOPT_HTTPHEADER, array( 'Content-Type: application/json; charset=utf-8' ) );
	$result = curl_exec( $ch );
	$errno = curl_errno( $ch );
	if ( $errno != 0 ) {
		asgard_html_error( sprintf( 'POST %s: error=%s code=%d', $url, $errno, curl_error( $ch ) ) );
	}

	$http_status = curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	if ( $http_status != 200 ) {
		asgard_html_error( sprintf( 'POST %s error: code=%d. Please, try again later.', $url, $http_status ) );
	}

	curl_close( $ch );
	return json_decode( $result, true );
}

function asgard_scan_zip( $path ) {
	return asgard_api_post( ASGARD_API . '/scan_zip', array( 'file' => '@' . $path ) );
}


function asgard_send_hashes( $hashlist ) {
	$body = json_encode( array(
			'hash' => $hashlist
		) );
	// send blog url and email for auth
	$plugin_info = get_plugin_data( __FILE__ );
	$q = build_query( array(
			'checksum' => md5( $body ) ,
			'site_url' => get_site_url() ,
			'admin_email' => get_option( 'admin_email' ) ,
			'wp_version' => get_bloginfo( 'version' ) ,
			'asgard_checksum' => ASGARD_CHECKSUM,
			'asgard_version' => $plugin_info['Version'],
		) );

	$result = asgard_api_post( ASGARD_API . '/check?' . $q, $body, 'json' );
	return is_array( $result['result'] ) ? $result['result'] : array();
}
