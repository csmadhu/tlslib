package tlslib

import "errors"

var (
	ErrInvalidTLSMsgType            = errors.New("invalid_tls_msg_type")
	ErrVersionReadFailed            = errors.New("version_read_failed")
	ErrRandomReadFailed             = errors.New("random_read_failed")
	ErrSessionIDReadFailed          = errors.New("session_id_read_failed")
	ErrCipherSuitesReadFailed       = errors.New("cipher_suites_read_failed")
	ErrCipherSuiteParseFailed       = errors.New("cipher_suite_parse_failed")
	ErrCompressionMethodsReadFailed = errors.New("compression_methods_read_failed")
	ErrCompressionMethodParseFailed = errors.New("compression_method_parse_failed")
	ErrExtensionsReadFailed         = errors.New("extensions_read_failed")
	ErrExtensionParseFailed         = errors.New("extension_parse_failed")

	ErrServerHelloReadFailed = errors.New("server_hello_read_failed")
	ErrInvalidServerHello    = errors.New("invalid_server_hello")
	ErrIncompleteServerHello = errors.New("incomplete_server_hello")

	ErrClientHelloReadFailed = errors.New("client_hello_read_failed")
	ErrInvalidClientHello    = errors.New("invalid_client_hello")
	ErrIncompleteClientHello = errors.New("incomplete_client_hello")
)
