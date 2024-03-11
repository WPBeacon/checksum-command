<?php

use WP_CLI\Fetchers;
use WP_CLI\Formatter;
use WP_CLI\Utils;
use WP_CLI\WpOrgApi;

/**
 * Verifies plugin file integrity by comparing to published checksums.
 *
 * @package wp-cli
 */

class Beacon_Plugin_Command {

	/**
	 * URL template that points to the API endpoint to use.
	 *
	 * @var string
	 */
	private $url_template = 'https://downloads.wordpress.org/plugin-checksums/{slug}/{version}.json';

	/**
	 * Cached plugin data for all installed plugins.
	 *
	 * @var array|null
	 */
	private $plugins_data;

	/**
	 * Array of detected errors.
	 *
	 * @var array
	 */
	private $errors = array();

	/**
	 * Verifies plugin files against WordPress.org, alternative providers and localized checksums
	 *
	 * ## OPTIONS
	 *
	 * [<plugin>...]
	 * : One or more plugins to verify.
	 *
	 * [--all]
	 * : If set, all plugins will be verified.
	 *
	 * [--strict]
	 * : If set, even "soft changes" like readme.txt changes will trigger
	 * checksum errors.
	 *
	 * [--version=<version>]
	 * : Verify checksums against a specific plugin version.
	 * 
	 * [--provider=<url>]
	 * : Optional alternative provider to use. Example: https://wpbeacon.io/checksums/plugins/
	 *
	 * [--format=<format>]
	 * : Render output in a specific format.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 *   - yaml
	 *   - count
	 * ---
	 *
	 * [--insecure]
	 * : Retry downloads without certificate validation if TLS handshake fails. Note: This makes the request vulnerable to a MITM attack.
	 *
	 * [--exclude=<name>]
	 * : Comma separated list of plugin names that should be excluded from verifying.
	 *
	 * ## EXAMPLES
	 *
	 *     # Verify the checksums of all installed plugins
	 *     $ wp plugin verify-checksums --all
	 *     Success: Verified 8 of 8 plugins.
	 *
	 *     # Verify the checksums of a single plugin, Akismet in this case
	 *     $ wp plugin verify-checksums akismet
	 *     Success: Verified 1 of 1 plugins.
     * 
     * @subcommand verify-checksums
	 */
	public function verify_checksums( $args, $assoc_args ) {

		$fetcher     = new Fetchers\UnfilteredPlugin();
		$all         = (bool) Utils\get_flag_value( $assoc_args, 'all', false );
		$strict      = (bool) Utils\get_flag_value( $assoc_args, 'strict', false );
		$insecure    = (bool) Utils\get_flag_value( $assoc_args, 'insecure', false );
		$plugins     = $fetcher->get_many( $all ? $this->get_all_plugin_names() : $args );
		$provider    = Utils\get_flag_value( $assoc_args, 'provider', '' );
		$exclude     = Utils\get_flag_value( $assoc_args, 'exclude', '' );
		$version_arg = isset( $assoc_args['version'] ) ? $assoc_args['version'] : '';

		if ( empty( $plugins ) && ! $all ) {
			WP_CLI::error( 'You need to specify either one or more plugin slugs to check or use the --all flag to check all plugins.' );
		}

		$exclude_list = explode( ',', $exclude );

		$skips = 0;

		foreach ( $plugins as $plugin ) {
			$version       = empty( $version_arg ) ? $this->get_plugin_version( $plugin->file ) : $version_arg;
            $author        = empty( $this->get_plugin_author( $plugin->file ) ) ? "empty" : $this->get_plugin_author( $plugin->file );
			$checksum_file = "checksums/plugins/{$plugin->name}/{$author}_{$version}.json";

			if ( in_array( $plugin->name, $exclude_list, true ) ) {
				++$skips;
				continue;
			}

			if ( 'hello' === $plugin->name ) {
				$this->verify_hello_dolly_from_core( $assoc_args );
				continue;
			}

			if ( false === $version ) {
				WP_CLI::warning( "Could not retrieve the version for plugin {$plugin->name}, skipping." );
				++$skips;
				continue;
			}

			$wp_org_api = new WpOrgApi( [ 'insecure' => $insecure ] );
			$loaded     = false;

			// Attempt loading checksums from WordPress.org
			try {
				$checksums = $wp_org_api->get_plugin_checksums( $plugin->name, $version );
				$loaded    = true;
			} catch ( Exception $exception ) {
				unset($exception);
			}

			// Attempt loading checksums from alternative provider
			if ( ! $loaded && ! empty( $provider ) ) {
				$beacon_api = new BeaconApi( [ 'insecure' => $insecure ], $provider );
				try {
                    $checksums = $beacon_api->get_plugin_checksums( $plugin->name, $author, $version );
					$provider  = trim( $provider, "/" );
					WP_CLI::log( "Using checksum $provider/$checksum_file" );
					$loaded    = true;
                } catch ( Exception $exception ) {
					unset($exception);
				}

			} 

			// Generate and load local checksums
			if ( ! $loaded ) {
				if ( ! file_exists( $checksum_file ) ) {
					WP_CLI::runcommand( "beacon plugin generate-checksums $plugin->name --disable-remote-check" );

				}
				$checksums = json_decode( file_get_contents( $checksum_file ) );
				$checksums = (array) $checksums->files;
				WP_CLI::log( "Using checksum $checksum_file" );
			}

			//if ( false === $checksums ) {
			//	WP_CLI::warning( "Could not retrieve the checksums for version {$version} of plugin {$plugin->name}, skipping." );
			//	++$skips;
			//	continue;
			//}

			$files = $this->get_plugin_files( $plugin->file );

			foreach ( $checksums as $file => $checksum_array ) {
                $checksums[ $file ] = (array) $checksum_array;
				if ( ! in_array( $file, $files, true ) ) {
					$this->add_error( $plugin->name, $file, 'File is missing' );
				}
			}

			foreach ( $files as $file ) {
				if ( ! array_key_exists( $file, $checksums ) ) {
					$this->add_error( $plugin->name, $file, 'File was added' );
					continue;
				}

				if ( ! $strict && $this->is_soft_change_file( $file ) ) {
					continue;
				}
				$result = $this->check_file_checksum( dirname( $plugin->file ) . '/' . $file, $checksums[ $file ] );
				if ( true !== $result ) {
					$this->add_error( $plugin->name, $file, is_string( $result ) ? $result : 'Checksum does not match' );
				}
			}
		}

		if ( ! empty( $this->errors ) ) {
			$formatter = new Formatter(
				$assoc_args,
				array( 'plugin_name', 'file', 'message' )
			);
			$formatter->display_items( $this->errors );
		}

		$total     = count( $plugins );
		$failures  = count( array_unique( array_column( $this->errors, 'plugin_name' ) ) );
		$successes = $total - $failures - $skips;

		Utils\report_batch_operation_results(
			'plugin',
			'verify',
			$total,
			$successes,
			$failures,
			$skips
		);
	}

     /**
     * Generates a JSON file containing checksums of plugin files
	 *
	 * ## OPTIONS
	 *
	 * [<plugin>...]
	 * : One or more plugins to generate checksums.
	 *
	 * [--all]
	 * : If set, checksums for all local plugins will be generated.
     * 
     * [--disable-remote-check]
	 * : If set, will also generate checksums for plugins already 
     * on WordPress.org and WP Beacon.
     * 
     * [--source-dir]
	 * : If set, will generate checksums for plugins found is local
     * directory.
     * 
     * [--output-dir]
	 * : Defaults to /checksums/plugins/ found in the home directory.
	 *
	 * [--force]
	 * : If set, existing checksums will be overwritten.
	 *
	 * [--format=<format>]
	 * : Render output in a specific format.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 *   - yaml
	 *   - count
	 * ---
	 *
	 * [--exclude=<name>]
	 * : Comma separated list of plugin names that should be excluded from verifying.
	 *
	 * ## EXAMPLES
	 *
	 *     # Generates localized checksums for all plugins
	 *     $ wp beacon plugin generate-checksums --all
	 *     Success: Verified 8 of 8 plugins.
	 *
	 *     # Verify the checksums of a single plugin, Akismet in this case
	 *     $ wp beacon plugin generate-checksums akismet
	 *     Success: Verified 1 of 1 plugins.
	 *
	 * @subcommand generate-checksums
	 */
    public function generate_checksums( $args, $assoc_args ) {

        $plugins             = get_plugins();
        $plugins_to_generate = [];

        $all         = (bool) Utils\get_flag_value( $assoc_args, 'all', false );
		$strict      = (bool) Utils\get_flag_value( $assoc_args, 'strict', false );
        $force       = (bool) Utils\get_flag_value( $assoc_args, 'force', false );
		$insecure    = (bool) Utils\get_flag_value( $assoc_args, 'insecure', false );
        $disable_remote_check = (bool) Utils\get_flag_value( $assoc_args, 'disable-remote-check', false );
        $source_dir  = (string) Utils\get_flag_value( $assoc_args, 'source-dir', false );
        $output_dir  = (string) Utils\get_flag_value( $assoc_args, 'output-dir', false );
        $source_dir  = rtrim( $source_dir, "/" );
        $output_dir  = rtrim( $output_dir, "/" );

        if ( ! empty( $source_dir ) && ! is_dir( $source_dir ) ) {
            WP_CLI::error( "Source directory $source_dir not found." );
        }

        if ( ! empty( $output_dir ) && ! is_dir( $output_dir ) ) {
            WP_CLI::error( "Output directory $output_dir not found." );
        }
        
		if ( empty( $args ) && ! $all ) {
			WP_CLI::error( 'You need to specify either one or more plugin slugs to generate checksums or use the --all flag to generate all plugin checksums.' );
		}

        if ( ! empty( $source_dir ) ) {
            $plugins = $this->get_plugins_from_directory( $source_dir );
        }

        if ( ! empty( $args ) ) {
            foreach ( $plugins as $file => $details ) {
                if ( in_array( dirname( $file ), $args ) ) {
                    continue;
                }
                unset( $plugins[ $file ] );
            }
        }

        if ( ! $disable_remote_check ) {
            WP_CLI::log( "Checking WordPress.org for plugin checksums." );
        }

        foreach ( $plugins as $file => $details ) {

            if ( false === strpos( $file, '/' ) ) {
                $name = str_replace( '.php', '', basename( $file ) );
            } else {
                $name = dirname( $file );
            }

            $author  = sanitize_title( $details["Author"] );
            $version = $details["Version"];

            if ( ! $disable_remote_check ) {

                $arguments = [ 'headers' => [ 'Accept' => 'application/json' ] ];
                $response  = wp_remote_get( "https://downloads.wordpress.org/plugin-checksums/$name/$version.json", $arguments );
                if ( wp_remote_retrieve_response_code( $response ) === 200 ) {
                    continue;
                }
                if ( is_wp_error( $response ) ) {
                    continue;
                }

            }

            $plugins_to_generate[] = (object) [
                "name"    => $name,
                "author"  => empty( $author ) ? "empty" : $author,
                "version" => $version
            ];

        }

        foreach( $plugins_to_generate as $plugin ) {

            $json_file = get_home_path() . "checksums/plugins/{$plugin->name}/{$plugin->author}_{$plugin->version}.json";
            if ( ! empty( $output_dir ) ) {
                $json_file = "$output_dir/{$plugin->name}/{$plugin->author}_{$plugin->version}.json";
            }
            if ( ! $force and file_exists( $json_file ) ) {
                echo "Skipping $json_file already exists\n";
                continue;
            }
            WP_CLI::log( "Generating $json_file." );
            
            $skip_bad_files = [];
            $checksums      = [];
            $checksum_types = [
                'md5'    => 'md5sum',
                'sha256' => 'sha256sum'
            ];

            $path = WP_PLUGIN_DIR . "/$plugin->name";
            if ( ! empty( $source_dir ) ) {
                $path = "$source_dir/$plugin->name";
            }
            foreach( $checksum_types as $checksum_type => $checksum_command ) {
                $checksum_output = shell_exec( "cd $path && find . -type f -print0 | sort -z | xargs -0 $checksum_command 2>&1" );
                $checksum_output = explode( "\n", $checksum_output );
                foreach ( $checksum_output as $line ) {
                    if ( empty( $line ) ) {
                        continue;
                    }
                    list( $checksum, $filename ) = preg_split( '!\s+!', $line, 2 );
            
                    $filename = trim( preg_replace( '!^./!', '', $filename ) );
                    $checksum = trim( $checksum );
            
                    // See https://meta.trac.wordpress.org/ticket/3335 - Filenames like 'Testing Test' truncated to 'Testing'
                    if ( preg_match( '!^(\S+)\s+\S!', $filename, $m ) ) {
                            $skip_bad_files[ $m[1] ] = true;
                    }
            
                    if ( ! isset( $checksums[ $filename ] ) ) {
                        $checksums[ $filename ] = [
                            'md5'    => [],
                            'sha256' => [],
                        ];
                    }
                    $checksums[ $filename ][ $checksum_type ] = $checksum;
                }
            }

            $data = (object) [
                "plugin"  => $plugin->name,
                "version" => $plugin->version,
                "files"   => $checksums,
            ];
            if ( ! file_exists( dirname( $json_file ) ) ) {
                mkdir( dirname( $json_file ), 0777, true );
            }
            ksort( $data->files );
            if ( $force and file_exists( $json_file ) ) {
                unlink( $json_file );
            }
            file_put_contents( $json_file, json_encode( $data ) );

        }
    }

    private function get_plugins_from_directory( $plugin_root ) {
        // Files in wp-content/plugins directory.
        $plugins_dir  = @opendir( $plugin_root );
        $plugin_files = [];
        $wp_plugins   = [];

        if ( $plugins_dir ) {
            while ( ( $file = readdir( $plugins_dir ) ) !== false ) {
                if ( str_starts_with( $file, '.' ) ) {
                    continue;
                }

                if ( is_dir( $plugin_root . '/' . $file ) ) {
                    $plugins_subdir = @opendir( $plugin_root . '/' . $file );

                    if ( $plugins_subdir ) {
                        while ( ( $subfile = readdir( $plugins_subdir ) ) !== false ) {
                            if ( str_starts_with( $subfile, '.' ) ) {
                                continue;
                            }

                            if ( str_ends_with( $subfile, '.php' ) ) {
                                $plugin_files[] = "$file/$subfile";
                            }
                        }

                        closedir( $plugins_subdir );
                    }
                } else {
                    if ( str_ends_with( $file, '.php' ) ) {
                        $plugin_files[] = $file;
                    }
                }
            }

            closedir( $plugins_dir );
        }
        foreach ( $plugin_files as $plugin_file ) {
            if ( ! is_readable( "$plugin_root/$plugin_file" ) ) {
                continue;
            }
    
            // Do not apply markup/translate as it will be cached.
            $plugin_data = get_plugin_data( "$plugin_root/$plugin_file", false, false );
    
            if ( empty( $plugin_data['Name'] ) ) {
                continue;
            }
    
            $wp_plugins[ plugin_basename( $plugin_file ) ] = $plugin_data;
        }
    
        uasort( $wp_plugins, '_sort_uname_callback' );
        return $wp_plugins;
    }

	private function verify_hello_dolly_from_core( $assoc_args ) {
		$file       = 'hello.php';
		$wp_version = get_bloginfo( 'version', 'display' );
		$insecure   = (bool) Utils\get_flag_value( $assoc_args, 'insecure', false );
		$wp_org_api = new WpOrgApi( [ 'insecure' => $insecure ] );
		$locale     = '';

		try {
			$checksums = $wp_org_api->get_core_checksums( $wp_version, empty( $locale ) ? 'en_US' : $locale );
		} catch ( Exception $exception ) {
			WP_CLI::error( $exception );
		}

		if ( ! is_array( $checksums ) || ! isset( $checksums['wp-content/plugins/hello.php'] ) ) {
			WP_CLI::error( "Couldn't get hello.php checksum from WordPress.org." );
		}

		$md5_file = md5_file( $this->get_absolute_path( '/' ) . $file );
		if ( $md5_file !== $checksums['wp-content/plugins/hello.php'] ) {
			$this->add_error( 'hello', $file, 'Checksum does not match' );
		}
	}

	/**
	 * Adds a new error to the array of detected errors.
	 *
	 * @param string $plugin_name Name of the plugin that had the error.
	 * @param string $file Relative path to the file that had the error.
	 * @param string $message Message explaining the error.
	 */
	private function add_error( $plugin_name, $file, $message ) {
		$error['plugin_name'] = $plugin_name;
		$error['file']        = $file;
		$error['message']     = $message;
		$this->errors[]       = $error;
	}

	/**
	 * Gets the currently installed version for a given plugin.
	 *
	 * @param string $path Relative path to plugin file to get the version for.
	 *
	 * @return string|false Installed version of the plugin, or false if not
	 *                      found.
	 */
	private function get_plugin_author( $path ) {
		if ( ! isset( $this->plugins_data ) ) {
			$this->plugins_data = get_plugins();
		}

		if ( ! array_key_exists( $path, $this->plugins_data ) ) {
			return false;
		}
        
        $title = sanitize_title($this->plugins_data[ $path ]['Author']);
		return $title;
	}

	/**
	 * Gets the currently installed version for a given plugin.
	 *
	 * @param string $path Relative path to plugin file to get the version for.
	 *
	 * @return string|false Installed version of the plugin, or false if not
	 *                      found.
	 */
	private function get_plugin_version( $path ) {
		if ( ! isset( $this->plugins_data ) ) {
			$this->plugins_data = get_plugins();
		}

		if ( ! array_key_exists( $path, $this->plugins_data ) ) {
			return false;
		}

		return $this->plugins_data[ $path ]['Version'];
	}

	/**
	 * Gets the names of all installed plugins.
	 *
	 * @return array<string> Names of all installed plugins.
	 */
	private function get_all_plugin_names() {
		$names = array();
		foreach ( get_plugins() as $file => $details ) {
			$names[] = Utils\get_plugin_name( $file );
		}

		return $names;
	}

	/**
	 * Gets the list of files that are part of the given plugin.
	 *
	 * @param string $path Relative path to the main plugin file.
	 *
	 * @return array<string> Array of files with their relative paths.
	 */
	private function get_plugin_files( $path ) {
		$folder = dirname( $this->get_absolute_path( $path ) );

		// Return single file plugins immediately, to avoid iterating over the
		// entire plugins folder.
		if ( WP_PLUGIN_DIR === $folder ) {
			return (array) $path;
		}

		return $this->get_files( trailingslashit( $folder ) );
	}

	/**
	 * Checks the integrity of a single plugin file by comparing it to the
	 * officially provided checksum.
	 *
	 * @param string $path      Relative path to the plugin file to check the
	 *                          integrity of.
	 * @param array  $checksums Array of provided checksums to compare against.
	 *
	 * @return true|string
	 */
	private function check_file_checksum( $path, $checksums ) {
		if ( $this->supports_sha256()
			&& array_key_exists( 'sha256', $checksums )
		) {
			$sha256 = $this->get_sha256( $this->get_absolute_path( $path ) );
			return in_array( $sha256, (array) $checksums['sha256'], true );
		}
        

		if ( ! array_key_exists( 'md5', $checksums ) ) {
			return 'No matching checksum algorithm found';
		}

		$md5 = $this->get_md5( $this->get_absolute_path( $path ) );

		return in_array( $md5, (array) $checksums['md5'], true );
	}

	/**
	 * Checks whether the current environment supports 256-bit SHA-2.
	 *
	 * Should be supported for PHP 5+, but we might find edge cases depending on
	 * host.
	 *
	 * @return bool
	 */
	private function supports_sha256() {
		return true;
	}

	/**
	 * Gets the 256-bit SHA-2 of a given file.
	 *
	 * @param string $filepath Absolute path to the file to calculate the SHA-2
	 *                         for.
	 *
	 * @return string
	 */
	private function get_sha256( $filepath ) {
		return hash_file( 'sha256', $filepath );
	}

	/**
	 * Gets the MD5 of a given file.
	 *
	 * @param string $filepath Absolute path to the file to calculate the MD5
	 *                         for.
	 *
	 * @return string
	 */
	private function get_md5( $filepath ) {
		return hash_file( 'md5', $filepath );
	}

	/**
	 * Gets the absolute path to a relative plugin file.
	 *
	 * @param string $path Relative path to get the absolute path for.
	 *
	 * @return string
	 */
	private function get_absolute_path( $path ) {
		return WP_PLUGIN_DIR . '/' . $path;
	}

	/**
	 * Returns a list of files that only trigger checksum errors in strict mode.
	 *
	 * @return array<string> Array of file names.
	 */
	private function get_soft_change_files() {
		static $files = array(
			'readme.txt',
			'readme.md',
		);

		return $files;
	}

	/**
	 * Checks whether a given file will only trigger checksum errors in strict
	 * mode.
	 *
	 * @param string $file File to check.
	 *
	 * @return bool Whether the file only triggers checksum errors in strict
	 * mode.
	 */
	private function is_soft_change_file( $file ) {
		return in_array( strtolower( $file ), $this->get_soft_change_files(), true );
	}

    /**
	 * Normalizes directory separators to slashes.
	 *
	 * @param string $path Path to convert.
	 *
	 * @return string Path with all backslashes replaced by slashes.
	 */
	public static function normalize_directory_separators( $path ) {
		return str_replace( '\\', '/', $path );
	}

	/**
	 * Read a remote file and return its contents.
	 *
	 * @param string $url URL of the remote file to read.
	 *
	 * @return mixed
	 */
	protected static function _read( $url ) { // phpcs:ignore PSR2.Methods.MethodDeclaration.Underscore -- Could be used in classes extending this class.
		$headers  = array( 'Accept' => 'application/json' );
		$response = Utils\http_request(
			'GET',
			$url,
			null,
			$headers,
			array( 'timeout' => 30 )
		);
		if ( 200 === $response->status_code ) {
			return $response->body;
		}
		WP_CLI::error( "Couldn't fetch response from {$url} (HTTP code {$response->status_code})." );
	}

	/**
	 * Recursively get the list of files for a given path.
	 *
	 * @param string $path Root path to start the recursive traversal in.
	 *
	 * @return array<string>
	 */
	protected function get_files( $path ) {
		$filtered_files = array();
		try {
			$files = new RecursiveIteratorIterator(
				new RecursiveCallbackFilterIterator(
					new RecursiveDirectoryIterator(
						$path,
						RecursiveDirectoryIterator::SKIP_DOTS
					),
					function ( $current, $key, $iterator ) use ( $path ) {
						return $this->filter_file( self::normalize_directory_separators( substr( $current->getPathname(), strlen( $path ) ) ) );
					}
				),
				RecursiveIteratorIterator::CHILD_FIRST
			);
			foreach ( $files as $file_info ) {
				if ( $file_info->isFile() ) {
					$filtered_files[] = self::normalize_directory_separators( substr( $file_info->getPathname(), strlen( $path ) ) );
				}
			}
		} catch ( Exception $e ) {
			WP_CLI::error( $e->getMessage() );
		}

		return $filtered_files;
	}

	/**
	 * Whether to include the file in the verification or not.
	 *
	 * Can be overridden in subclasses.
	 *
	 * @param string $filepath Path to a file.
	 *
	 * @return bool
	 */
	protected function filter_file( $filepath ) {
		return true;
	}

}

class BeaconApi {

    /**
	 * Plugin checksums endpoint.
	 *
	 * @var string
	 */
	private $options = [];
	private $endpoint = "";

    /**
	 * WpOrgApi constructor.
	 *
	 * @param array $options Associative array of options to pass to the API abstraction.
	 */
	public function __construct( $options = [], $endpoint = "" ) {
		$this->options = $options;
		$this->endpoint = $endpoint;
	}

    /**
	 * Gets the checksums for the given version of plugin.
	 *
	 * @param string $plugin  Plugin slug to query.
	 * @param string $version Version string to query.
	 * @return bool|array False on failure. An array of checksums on success.
	 * @throws RuntimeException If the remote request fails.
	 */
	public function get_plugin_checksums( $plugin, $author, $version ) {
		$url = sprintf(
			'%s%s/%s_%s.json',
			$this->endpoint,
			$plugin,
            $author,
			$version
		);

		$response = $this->json_get_request( $url );

		if (
			! is_array( $response )
			|| ! isset( $response['files'] )
			|| ! is_array( $response['files'] )
		) {
			return false;
		}

		return $response['files'];
	}

    /**
	 * Execute a remote GET request.
	 *
	 * @param string $url     URL to execute the GET request on.
	 * @param array  $headers Optional. Associative array of headers.
	 * @param array  $options Optional. Associative array of options.
	 * @return mixed|false False on failure. Decoded JSON on success.
	 * @throws RuntimeException If the JSON could not be decoded.
	 */
	private function json_get_request( $url, $headers = [], $options = [] ) {
		$headers = array_merge(
			[
				'Accept' => 'application/json',
			],
			$headers
		);

		$response = $this->get_request( $url, $headers, $options );

		if ( false === $response ) {
			return $response;
		}

		$data = json_decode( $response, true );

		if ( JSON_ERROR_NONE !== json_last_error() ) {
			throw new RuntimeException( 'Failed to decode JSON: ' . json_last_error_msg() );
		}

		return $data;
	}

    /**
	 * Execute a remote GET request.
	 *
	 * @param string $url     URL to execute the GET request on.
	 * @param array  $headers Optional. Associative array of headers.
	 * @param array  $options Optional. Associative array of options.
	 * @return string|false False on failure. Response body string on success.
	 * @throws RuntimeException If the remote request fails.
	 */
	private function get_request( $url, $headers = [], $options = [] ) {
		$options = array_merge(
			$this->options,
			[
				'halt_on_error' => false,
			],
			$options
		);

		$response = Utils\http_request( 'GET', $url, null, $headers, $options );

		if (
			! $response->success
			|| 200 > (int) $response->status_code
			|| 300 <= $response->status_code
		) {
			throw new RuntimeException(
				"Couldn't fetch response from {$url} (HTTP code {$response->status_code})."
			);
		}

		return trim( $response->body );
	}

}