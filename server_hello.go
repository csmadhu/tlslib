package tlslib

import (
	"golang.org/x/crypto/cryptobyte"
)

const typeServerHello uint8 = 2

type ServerHelloInfo struct {
	Raw []byte `json:"raw"`

	Version            ProtocolVersion     `json:"version"`
	Random             []byte              `json:"random"`
	SessionID          []byte              `json:"session_id"`
	CipherSuites       []CipherSuite       `json:"cipher_suites"`
	CompressionMethods []CompressionMethod `json:"compression_methods"`
	Extensions         []Extension         `json:"extensions"`

	Info struct {
		SCTs           bool     `json:"scts"`
		Protocols      []string `json:"protocols"`
		JA3String      string   `json:"ja3_string"`
		JA3Fingerprint string   `json:"ja3_fingerprint"`
	} `json:"info"`
}

func UnmarshalServerHello(handshakeBytes []byte) *ServerHelloInfo {
	info := &ServerHelloInfo{Raw: handshakeBytes}
	handshakeMessage := cryptobyte.String(handshakeBytes)

	var messageType uint8
	if !handshakeMessage.ReadUint8(&messageType) || messageType != typeServerHello {
		return nil
	}

	var serverHello cryptobyte.String
	if !handshakeMessage.ReadUint24LengthPrefixed(&serverHello) || !handshakeMessage.Empty() {
		return nil
	}

	if !serverHello.ReadUint16((*uint16)(&info.Version)) {
		return nil
	}

	if !serverHello.ReadBytes(&info.Random, 32) {
		return nil
	}

	if !serverHello.ReadUint8LengthPrefixed((*cryptobyte.String)(&info.SessionID)) {
		return nil
	}

	var cipherSuites cryptobyte.String
	if !serverHello.ReadUint16LengthPrefixed(&cipherSuites) {
		return nil
	}
	info.CipherSuites = []CipherSuite{}
	for !cipherSuites.Empty() {
		var suite uint16
		if !cipherSuites.ReadUint16(&suite) {
			return nil
		}
		info.CipherSuites = append(info.CipherSuites, MakeCipherSuite(suite))
	}

	var compressionMethods cryptobyte.String
	if !serverHello.ReadUint8LengthPrefixed(&compressionMethods) {
		return nil
	}
	info.CompressionMethods = []CompressionMethod{}
	for !compressionMethods.Empty() {
		var method uint8
		if !compressionMethods.ReadUint8(&method) {
			return nil
		}
		info.CompressionMethods = append(info.CompressionMethods, CompressionMethod(method))
	}

	info.Extensions = []Extension{}

	if serverHello.Empty() {
		return info
	}
	var extensions cryptobyte.String
	if !serverHello.ReadUint16LengthPrefixed(&extensions) {
		return nil
	}
	for !extensions.Empty() {
		var extType uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extType) || !extensions.ReadUint16LengthPrefixed(&extData) {
			return nil
		}

		parseData := extensionParsers[extType]
		if parseData == nil {
			parseData = ParseUnknownExtensionData
		}
		data := parseData(extData)

		info.Extensions = append(info.Extensions, Extension{
			Type:    extType,
			Name:    Extensions[extType].Name,
			Grease:  Extensions[extType].Grease,
			Private: Extensions[extType].Private,
			Data:    data,
		})

		switch extType {
		case 16:
			info.Info.Protocols = data.(*ALPNData).Protocols
		case 18:
			info.Info.SCTs = true
		}

	}

	if !serverHello.Empty() {
		return nil
	}

	info.Info.JA3String = JA3String(info.Version, info.CipherSuites, info.Extensions)
	info.Info.JA3Fingerprint = JA3Fingerprint(info.Info.JA3String)

	return info
}
