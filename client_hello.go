package tlslib

import (
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

const typeClientHello uint8 = 1

type ProtocolVersion uint16

func (v ProtocolVersion) Hi() uint8 {
	return uint8(v >> 8)
}

func (v ProtocolVersion) Lo() uint8 {
	return uint8(v)
}

func (v ProtocolVersion) MarshalJSON() ([]byte, error) {
	return json.Marshal([2]uint8{v.Hi(), v.Lo()})
}

type CompressionMethod uint8

func (m CompressionMethod) MarshalJSON() ([]byte, error) {
	return json.Marshal(uint16(m))
}

type ClientHelloInfo struct {
	Raw []byte `json:"raw"`

	Version            ProtocolVersion     `json:"version"`
	Random             []byte              `json:"random"`
	SessionID          []byte              `json:"session_id"`
	CipherSuites       []CipherSuite       `json:"cipher_suites"`
	CompressionMethods []CompressionMethod `json:"compression_methods"`
}

func UnmarshalClientHello(handshakeBytes []byte) (*ClientHelloInfo, error) {
	info := &ClientHelloInfo{Raw: handshakeBytes}
	handshakeMessage := cryptobyte.String(handshakeBytes)

	var messageType uint8
	if !handshakeMessage.ReadUint8(&messageType) || messageType != typeClientHello {
		return nil, fmt.Errorf(
			"%w: want msgType(%d) got msgType(%d)",
			ErrInvalidTLSMsgType, typeClientHello, messageType)
	}

	var clientHello cryptobyte.String
	if !handshakeMessage.ReadUint24LengthPrefixed(&clientHello) || !handshakeMessage.Empty() {
		return nil, ErrClientHelloReadFailed
	}

	if !clientHello.ReadUint16((*uint16)(&info.Version)) {
		return nil, ErrVersionReadFailed
	}

	if !clientHello.ReadBytes(&info.Random, 32) {
		return nil, ErrRandomReadFailed
	}

	if !clientHello.ReadUint8LengthPrefixed((*cryptobyte.String)(&info.SessionID)) {
		return nil, ErrSessionIDReadFailed
	}

	var cipherSuites cryptobyte.String
	if !clientHello.ReadUint16LengthPrefixed(&cipherSuites) {
		return nil, ErrCipherSuitesReadFailed
	}
	info.CipherSuites = []CipherSuite{}
	for !cipherSuites.Empty() {
		var suite uint16
		if !cipherSuites.ReadUint16(&suite) {
			return nil, ErrCipherSuiteParseFailed
		}
		info.CipherSuites = append(info.CipherSuites, MakeCipherSuite(suite))
	}

	var compressionMethods cryptobyte.String
	if !clientHello.ReadUint8LengthPrefixed(&compressionMethods) {
		return nil, ErrCompressionMethodsReadFailed
	}
	info.CompressionMethods = []CompressionMethod{}
	for !compressionMethods.Empty() {
		var method uint8
		if !compressionMethods.ReadUint8(&method) {
			return nil, ErrCompressionMethodParseFailed
		}
		info.CompressionMethods = append(info.CompressionMethods, CompressionMethod(method))
	}

	return info, nil
}
