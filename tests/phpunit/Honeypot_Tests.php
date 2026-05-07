<?php
namespace MagicLogin;

use MagicLogin\Constants;
use ReflectionClass;

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', '/' );
}

if ( ! defined( 'HOUR_IN_SECONDS' ) ) {
	define( 'HOUR_IN_SECONDS', 3600 );
}

class Honeypot_Tests extends TestCase {

	protected $testFiles = [
		'constants.php',
		'classes/Honeypot.php',
	];

	private const SALT = 'magic-login-test-salt';

	public function setUp(): void {
		parent::setUp();

		$_POST = [];

		\WP_Mock::userFunction(
			'wp_salt',
			[
				'times'  => '0+',
				'return' => self::SALT,
			]
		);

		\WP_Mock::userFunction(
			'wp_unslash',
			[
				'times'      => '0+',
				'return_arg' => 0,
			]
		);

		\WP_Mock::userFunction(
			'sanitize_text_field',
			[
				'times'      => '0+',
				'return_arg' => 0,
			]
		);

		\WP_Mock::userFunction(
			'sanitize_key',
			[
				'times'  => '0+',
				'return' => static function ( $key ) {
					return strtolower( preg_replace( '/[^a-zA-Z0-9_\-]/', '', (string) $key ) );
				},
			]
		);

		\WP_Mock::userFunction(
			'absint',
			[
				'times'  => '0+',
				'return' => static function ( $value ) {
					return abs( (int) $value );
				},
			]
		);

		\WP_Mock::userFunction(
			'apply_filters',
			[
				'times'      => '0+',
				'return_arg' => 1,
			]
		);

		\WP_Mock::userFunction(
			'__',
			[
				'times'      => '0+',
				'return_arg' => 0,
			]
		);

		\WP_Mock::userFunction(
			'esc_html__',
			[
				'times'      => '0+',
				'return_arg' => 0,
			]
		);
	}

	public function tearDown(): void {
		$_POST = [];

		parent::tearDown();
	}

	public function test_allows_valid_login_request_honeypot_payload(): void {
		$this->seedPayload( 'login_request', time() - 10 );

		$decision = $this->validateContext( 'login_request' );

		$this->assertSame( 'allow', $decision['type'] );
	}

	public function test_rejects_filled_bait_field_as_silent_success(): void {
		$this->seedPayload( 'login_request', time() - 10, 'bot-value' );

		$decision = $this->validateContext( 'login_request' );

		$this->assertSame( 'silent_success', $decision['type'] );
	}

	public function test_rejects_too_fast_login_request_as_silent_success(): void {
		$this->seedPayload( 'login_request', time() );

		$decision = $this->validateContext( 'login_request' );

		$this->assertSame( 'silent_success', $decision['type'] );
	}

	public function test_rejects_expired_login_request_as_silent_success(): void {
		$this->seedPayload( 'login_request', time() - HOUR_IN_SECONDS - 1 );

		$decision = $this->validateContext( 'login_request' );

		$this->assertSame( 'silent_success', $decision['type'] );
	}

	public function test_rejects_invalid_code_login_request_with_error(): void {
		$decision = $this->validateContext( 'code_login' );

		$this->assertSame( 'error', $decision['type'] );
		$this->assertSame( 'Invalid login code.', $decision['message'] );
	}

	private function validateContext( string $context ): array {
		$method = $this->getHoneypotReflection()->getMethod( 'validate_context' );
		$method->setAccessible( true );

		return $method->invoke( $this->getHoneypotInstance(), $context );
	}

	private function getHoneypotReflection(): ReflectionClass {
		return new ReflectionClass( Honeypot::class );
	}

	private function getHoneypotInstance(): Honeypot {
		return $this->getHoneypotReflection()->newInstanceWithoutConstructor();
	}

	private function seedPayload( string $context, int $renderedAt, string $baitValue = '' ): void {
		$signature  = hash_hmac( 'sha256', $context . '|' . abs( $renderedAt ), self::SALT );
		$field_name = Constants\HONEYPOT_BAIT_FIELD_PREFIX . substr( $signature, 0, 12 );

		$_POST[ Constants\HONEYPOT_PAYLOAD_FIELD ] = $renderedAt . '.' . $signature;
		$_POST[ $field_name ]                      = $baitValue;
	}
}
