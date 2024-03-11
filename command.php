<?php

if ( ! class_exists( 'WP_CLI' ) ) {
	return;
}

require_once 'src/Beacon_Api.php';
require_once 'src/Beacon_Command.php';
require_once 'src/Beacon_Plugin_Command.php';

WP_CLI::add_command( 'beacon', 'Beacon_Command' );
WP_CLI::add_command( 'beacon plugin', 'Beacon_Plugin_Command' );
