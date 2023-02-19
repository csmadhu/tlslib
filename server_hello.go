package tlslib

import (
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

const typeServerHello uint8 = 2

type ServerHelloInfo struct {
	Raw []byte `json:"raw"`

	Version   ProtocolVersion `json:"version"`
	Random    []byte          `json:"random"`
	SessionID []byte          `json:"session_id"`
}

func UnmarshalServerHello(handshakeBytes []byte) (*ServerHelloInfo, error) {
	info := &ServerHelloInfo{Raw: handshakeBytes}
	handshakeMessage := cryptobyte.String(handshakeBytes)

	var messageType uint8
	if !handshakeMessage.ReadUint8(&messageType) || messageType != typeServerHello {
		return nil, fmt.Errorf(
			"%w: want msgType(%d) got msgType(%d)",
			ErrInvalidTLSMsgType, typeServerHello, messageType)
	}

	var serverHello cryptobyte.String
	if !handshakeMessage.ReadUint24LengthPrefixed(&serverHello) {
		return nil, ErrServerHelloReadFailed
	}

	if !serverHello.ReadUint16((*uint16)(&info.Version)) {
		return nil, ErrVersionReadFailed
	}

	if !serverHello.ReadBytes(&info.Random, 32) {
		return nil, ErrRandomReadFailed
	}

	if !serverHello.ReadUint8LengthPrefixed((*cryptobyte.String)(&info.SessionID)) {
		return nil, ErrSessionIDReadFailed
	}

	return info, nil
}
