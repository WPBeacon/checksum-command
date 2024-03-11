<?php

use WP_CLI\Utils;

class Beacon_Api {

	/**
	 * Plugin checksums endpoint.
	 *
	 * @var string
	 */
	private $options  = [];
	private $endpoint = '';

	/**
	 * WpOrgApi constructor.
	 *
	 * @param array $options Associative array of options to pass to the API abstraction.
	 */
	public function __construct( $options = [], $endpoint = '' ) {
		$this->options  = $options;
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
