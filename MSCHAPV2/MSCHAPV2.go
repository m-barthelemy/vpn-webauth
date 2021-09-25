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
	Encode() (b []byte)
}

func Decode(b []byte) (p Packet, err error) {
	if len(b) == 1 {
		//eap - mschapv2 的一种特殊情况,只有opcode,其他啥也没有
		return &SimplePacket{
			Code: OpCode(b[0]),
		}, nil
	}
	if len(b) < 4 {
		return nil, fmt.Errorf("[MSCHAPV2.Decode] protocol error 1, len(b)[%d] < 2", len(b))
	}
	code := OpCode(b[0])
	Identifier := uint8(b[1])
	switch code {
	case OpCodeChallenge:
		if len(b) < 21 {
			return nil, fmt.Errorf("[MsChapV2PacketFromEap] protocol error 2 Challenge packet len is less than 21 ")
		}
		resp := &ChallengePacket{}
		copy(resp.Challenge[:], b[5:21])
		resp.Name = string(b[21:])
		resp.Identifier = Identifier
		return resp, nil
	case OpCodeResponse:
		if len(b) < 53 {
			return nil, fmt.Errorf("[MsChapV2PacketFromEap] protocol error 3 Response packet len is less than 53 ")
		}
		resp := &ResponsePacket{}
		copy(resp.PeerChallenge[:], b[5:21])
		copy(resp.NTResponse[:], b[29:53])
		resp.Name = string(b[54:])
		resp.Identifier = Identifier
		return resp, nil
	case OpCodeSuccess:
		resp := &SuccessPacket{}
		hex.Decode(resp.Auth[:], b[6:46])
		resp.Message = string(b[49:])
		resp.Identifier = Identifier
		return resp, nil
	default:
		return nil, fmt.Errorf("[MsChapV2PacketFromEap] can not parse opcode:%s", p.OpCode)
	}
	return p, nil
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
func (p *ChallengePacket) Encode() (b []byte) {
	len := 4 + 1 + 16 + len(p.Name)
	b = make([]byte, len)
	b[0] = byte(p.OpCode())
	b[1] = byte(p.Identifier)
	binary.BigEndian.PutUint16(b[2:4], uint16(len))
	b[4] = 16
	copy(b[5:21], p.Challenge[:])
	copy(b[21:], p.Name)
	return b
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
func (p *ResponsePacket) Encode() (b []byte) {
	len := 4 + 1 + 49 + len(p.Name)
	b = make([]byte, len)
	b[0] = byte(p.OpCode())
	b[1] = byte(p.Identifier)
	binary.BigEndian.PutUint16(b[2:4], uint16(len))
	b[4] = 49
	copy(b[5:21], p.PeerChallenge[:])
	copy(b[29:53], p.NTResponse[:])
	copy(b[54:], p.Name)
	return b
}

// look like "S=<auth_string> M=<message>"
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
func (p *SuccessPacket) Encode() (b []byte) {
	len := 4 + 2 + 40 + 3 + len(p.Message)
	b = make([]byte, len)
	b[0] = byte(p.OpCode())
	b[1] = byte(p.Identifier)
	binary.BigEndian.PutUint16(b[2:4], uint16(len))
	copy(b[4:6], "S=")
	hex.Encode(b[6:46], p.Auth[:])
	out := bytes.ToUpper(b[6:46])
	copy(b[6:46], out)
	copy(b[46:49], " M=")
	copy(b[49:], p.Message)
	return b
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

func (p *SimplePacket) Encode() (b []byte) {
	b = make([]byte, 1)
	b[0] = byte(p.OpCode())
	return b
}

type ReplySuccessPacketRequest struct {
	AuthenticatorChallenge [16]byte
	Response               *ResponsePacket
	Username               []byte
	Password               []byte
	Message                string
}

/*func ReplySuccessPacket(req *ReplySuccessPacketRequest) (p *SuccessPacket) {
	Auth := GenerateAuthenticatorResponse(req.Password, req.Response.NTResponse, req.Response.PeerChallenge, req.AuthenticatorChallenge, req.Username)
	return &SuccessPacket{
		Identifier: req.Response.Identifier,
		Auth:       Auth,
		Message:    req.Message,
	}
}*/
