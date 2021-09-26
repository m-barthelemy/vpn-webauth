// From https://github.com/keysonZZZ/kmg/blob/master/third/kmgRadius/MSCHAPV2/packet.go
package MSCHAPV2

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
)

type Packet interface {
	String() string
	OpCode() OpCode
	Encode() (data []byte)
}

func Decode(data []byte) (p Packet, err error) {
	if len(data) == 1 {
		return &SimplePacket{
			Code: OpCode(data[0]),
		}, nil
	}
	if len(data) < 4 {
		return nil, fmt.Errorf("data bytes length is %d, must be at least 4", len(data))
	}
	code := OpCode(data[0])
	Identifier := uint8(data[1])
	switch code {
	case OpCodeChallenge:
		if len(data) < 21 {
			return nil, fmt.Errorf("challenge packet length is less than 21")
		}
		resp := &ChallengePacket{}
		copy(resp.Challenge[:], data[5:21])
		resp.Name = string(data[21:])
		resp.Identifier = Identifier
		return resp, nil
	case OpCodeResponse:
		if len(data) < 53 {
			return nil, fmt.Errorf("response packet length is less than 53 ")
		}
		resp := &ResponsePacket{}
		copy(resp.PeerChallenge[:], data[5:21])
		copy(resp.NTResponse[:], data[29:53])
		resp.Name = string(data[54:])
		resp.Identifier = Identifier
		return resp, nil
	case OpCodeSuccess:
		resp := &SuccessPacket{}
		hex.Decode(resp.Auth[:], data[6:46])
		resp.Message = string(data[49:])
		resp.Identifier = Identifier
		return resp, nil
	default:
		return nil, fmt.Errorf("unknown opcode '%s'", code)
	}
}

type OpCode uint8

const (
	OpCodeChallenge      OpCode = 1
	OpCodeResponse       OpCode = 2
	OpCodeSuccess        OpCode = 3
	OpCodeFailure        OpCode = 4
	OpCodeChangePassword OpCode = 7
)

func (c OpCode) String() string {
	switch c {
	case OpCodeChallenge:
		return "Challenge"
	case OpCodeResponse:
		return "Response"
	case OpCodeSuccess:
		return "Success"
	case OpCodeFailure:
		return "Failure"
	case OpCodeChangePassword:
		return "ChangePassword"
	default:
		return "unknow OpCode " + strconv.Itoa(int(c))
	}
}

type ChallengePacket struct {
	Identifier uint8
	Challenge  [16]byte
	Name       string
}

func (p *ChallengePacket) String() string {
	return fmt.Sprintf("Code: Challenge Challenge: %#v Name: %s", p.Challenge, p.Name)
}
func (p *ChallengePacket) OpCode() OpCode {
	return OpCodeChallenge
}
func (p *ChallengePacket) Encode() (data []byte) {
	len := 4 + 1 + 16 + len(p.Name)
	data = make([]byte, len)
	data[0] = byte(p.OpCode())
	data[1] = byte(p.Identifier)
	binary.BigEndian.PutUint16(data[2:4], uint16(len))
	data[4] = 16
	copy(data[5:21], p.Challenge[:])
	copy(data[21:], p.Name)
	return data
}

type ResponsePacket struct {
	Identifier    uint8
	PeerChallenge [16]byte //16byte
	NTResponse    [24]byte //24byte
	Name          string
}

func (p *ResponsePacket) String() string {
	return fmt.Sprintf("Code: Response PeerChallenge: %#v NTResponse:%#v Name:%#v", p.PeerChallenge, p.NTResponse, p.Name)
}
func (p *ResponsePacket) OpCode() OpCode {
	return OpCodeResponse
}
func (p *ResponsePacket) Encode() (data []byte) {
	len := 4 + 1 + 49 + len(p.Name)
	data = make([]byte, len)
	data[0] = byte(p.OpCode())
	data[1] = byte(p.Identifier)
	binary.BigEndian.PutUint16(data[2:4], uint16(len))
	data[4] = 49
	copy(data[5:21], p.PeerChallenge[:])
	copy(data[29:53], p.NTResponse[:])
	copy(data[54:], p.Name)
	return data
}

// Looks like "S=<auth_string> M=<message>" once encoded
type SuccessPacket struct {
	Identifier uint8
	Auth       [20]byte // the binary format of auth_string
	Message    string
}

func (p *SuccessPacket) String() string {
	return fmt.Sprintf("Code: Success AuthString: %#v Message: %s", p.Auth, p.Message)
}

func (p *SuccessPacket) OpCode() OpCode {
	return OpCodeSuccess
}
func (p *SuccessPacket) Encode() (data []byte) {
	len := 4 + 2 + 40 + 3 + len(p.Message)
	data = make([]byte, len)
	data[0] = byte(p.OpCode())
	data[1] = byte(p.Identifier)
	binary.BigEndian.PutUint16(data[2:4], uint16(len))
	copy(data[4:6], "S=")
	hex.Encode(data[6:46], p.Auth[:])
	out := bytes.ToUpper(data[6:46])
	copy(data[6:46], out)
	copy(data[46:49], " M=")
	copy(data[49:], p.Message)
	return data
}

type SimplePacket struct {
	Code OpCode
}

func (p *SimplePacket) OpCode() OpCode {
	return p.Code
}

func (p *SimplePacket) String() string {
	return fmt.Sprintf("Code: %s", p.OpCode())
}

func (p *SimplePacket) Encode() (data []byte) {
	data = make([]byte, 1)
	data[0] = byte(p.OpCode())
	return data
}

type ReplySuccessPacketRequest struct {
	AuthenticatorChallenge [16]byte
	Response               *ResponsePacket
	Username               []byte
	Password               []byte
	Message                string
}

func ReplySuccessPacket(req *ReplySuccessPacketRequest) (p *SuccessPacket) {
	Auth := GenerateAuthenticatorResponse(req.Password, req.Response.NTResponse, req.Response.PeerChallenge, req.AuthenticatorChallenge, req.Username)
	return &SuccessPacket{
		Identifier: req.Response.Identifier,
		Auth:       Auth,
		Message:    req.Message,
	}
}
