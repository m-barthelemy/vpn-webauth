// From https://github.com/keysonZZZ/kmg/blob/master/third/kmgRadius/vsa.go
package MSCHAPV2

import (
	"crypto"
	// #nosec
	_ "crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"reflect"

	"github.com/bronze1man/radius"
)

type Stringer interface {
	String() string
}

//Vendor Specific Attributes
type VSA interface {
	GetType() VendorType
	String() string
	Encode() (b []byte, err error)
}

// the data is the data from avp
func vsaDecode(p *radius.Packet, data []byte) (vsa VSA, err error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("[vsaDecode] len(data)[%d]<4", len(data))
	}
	vendorId := VendorId(binary.BigEndian.Uint32(data[:4]))
	switch vendorId {
	case VendorIdMicrosoft:
		if len(data) < 5 {
			return nil, fmt.Errorf("[vsaDecode] len(data)[%d]<5", len(data))
		}
		vendorType := VendorType(data[4])
		decoder := vendorType.decoder()
		return decoder(p, vendorType, data[6:])
	default:
		return nil, fmt.Errorf("[vsaDecode] not implement vendorid:%d", vendorId)
	}
}

type VendorId uint32

const (
	VendorIdMicrosoft = 311
)

func (a VendorId) String() string {
	switch a {
	case VendorIdMicrosoft:
		return "Microsoft"
	default:
		return fmt.Sprintf("unknow VendorId:%d", a)
	}
}

type VendorType uint8 //微软的?

const (
	VendorTypeMSMPPEEncryptionPolicy VendorType = 7
	VendorTypeMSMPPEEncryptionTypes  VendorType = 8
	VendorTypeMSMPPESendKey          VendorType = 16
	VendorTypeMSMPPERecvKey          VendorType = 17
)

func (a VendorType) String() string {
	switch a {
	case VendorTypeMSMPPEEncryptionPolicy:
		return "MSMPPEEncryptionPolicy"
	case VendorTypeMSMPPEEncryptionTypes:
		return "MSMPPEEncryptionTypes"
	case VendorTypeMSMPPESendKey:
		return "MSMPPESendKey"
	case VendorTypeMSMPPERecvKey:
		return "MSMPPERecvKey"
	default:
		return fmt.Sprintf("unknow VendorType:%d", a)
	}
}

func (a VendorType) decoder() func(p *radius.Packet, typ VendorType, data []byte) (avp VSA, err error) {
	switch a {
	case VendorTypeMSMPPEEncryptionPolicy:
		return vsaUint32Enum(MSMPPEEncryptionPolicy(0))
	case VendorTypeMSMPPEEncryptionTypes:
		return vsaUint32Enum(MSMPPEEncryptionTypes(0))
	case VendorTypeMSMPPESendKey, VendorTypeMSMPPERecvKey:
		return vsaSendOrRecvKey
	default:
		return vsaBinary
	}
}

func (a VendorType) VendorId() VendorId {
	return VendorIdMicrosoft
}

func vsaEncodeWithByteSlice(typ VendorType, data []byte) (b []byte, err error) {
	if len(data) > 255-2 {
		return nil, fmt.Errorf("[encodeWithByteSlice] data length %d overflow(should less than 253)", len(data))
	}
	length := len(data) + 6
	b = make([]byte, length)
	binary.BigEndian.PutUint32(b[:4], uint32(typ.VendorId()))
	b[4] = byte(typ)
	b[5] = byte(len(data) + 2)
	copy(b[6:], data)
	return b, nil
}
func vsaBinary(p *radius.Packet, typ VendorType, data []byte) (avp VSA, err error) {
	return &BinaryVSA{
		Type:  typ,
		Value: data,
	}, nil
}

type BinaryVSA struct {
	Type  VendorType
	Value []byte
}

func (a *BinaryVSA) GetType() VendorType {
	return a.Type
}
func (a *BinaryVSA) String() string {
	return fmt.Sprintf("Type: %s Value: %#v", a.Type, a.Value)
}
func (a *BinaryVSA) Encode() (b []byte, err error) {
	if len(a.Value) > 253 {
		return nil, fmt.Errorf("[BinaryAVP.Encode] len(a.Value)[%d]>253", len(a.Value))
	}
	return vsaEncodeWithByteSlice(a.Type, a.Value)
}
func (a *BinaryVSA) GetValue() interface{} {
	return a.Value
}

// t should from a uint32 type like AcctStatusTypeEnum
func vsaUint32Enum(t Stringer) func(p *radius.Packet, typ VendorType, data []byte) (avp VSA, err error) {
	return func(p *radius.Packet, typ VendorType, data []byte) (avp VSA, err error) {
		if len(data) != 4 {
			return nil, fmt.Errorf("[vsaUint32Enum] len(data)[%d]!=4", len(data))
		}
		value := reflect.New(reflect.TypeOf(t)).Elem()
		value.SetUint(uint64(binary.BigEndian.Uint32(data)))
		valueI := value.Interface().(Stringer)
		return &Uint32EnumVSA{
			Type:  typ,
			Value: valueI,
		}, nil
	}
}

type Uint32EnumVSA struct {
	Type  VendorType
	Value Stringer // value should derive from a uint32 type like AcctStatusTypeEnum
}

func (a *Uint32EnumVSA) GetType() VendorType {
	return a.Type
}
func (a *Uint32EnumVSA) String() string {
	return fmt.Sprintf("Type: %s Value: %s", a.GetType(), a.Value)
}
func (a *Uint32EnumVSA) Encode() (b []byte, err error) {
	b = make([]byte, 4)
	value := reflect.ValueOf(a.Value)
	out := value.Uint()
	if out >= (1 << 32) {
		panic("[Uint32EnumAVP.Encode] enum number overflow")
	}
	binary.BigEndian.PutUint32(b, uint32(out))
	return vsaEncodeWithByteSlice(a.Type, b)
}
func (a *Uint32EnumVSA) Copy() VSA {
	return &Uint32EnumVSA{
		Type:  a.Type,
		Value: a.Value,
	}
}
func (a *Uint32EnumVSA) GetValue() interface{} {
	return a.Value
}

func vsaSendOrRecvKey(p *radius.Packet, typ VendorType, data []byte) (avp VSA, err error) {
	key, salt, err := msMPPEKeyDecode(p, data)
	if err != nil {
		return nil, err
	}
	return &MSMPPESendOrRecvKeyVSA{
		packet: p,
		Type:   typ,
		Salt:   salt,
		Key:    key,
	}, nil
}

//send or recv key
type MSMPPESendOrRecvKeyVSA struct {
	packet *radius.Packet
	Type   VendorType
	Salt   [2]byte //最高位要是1
	Key    []byte
}

func (a *MSMPPESendOrRecvKeyVSA) SetPacket(p *radius.Packet) {
	a.packet = p
}
func (a *MSMPPESendOrRecvKeyVSA) GetType() VendorType {
	return a.Type
}
func (a *MSMPPESendOrRecvKeyVSA) String() string {
	return fmt.Sprintf("Type: %s Salt: %#v Key: %#v", a.GetType(), a.Salt, a.Key)
}
func (a *MSMPPESendOrRecvKeyVSA) Encode() (b []byte, err error) {
	b, err = msMPPEKeyEncode(a.packet, a.Salt, a.Key)
	if err != nil {
		return nil, err
	}
	return vsaEncodeWithByteSlice(a.Type, b)
}
func (a *MSMPPESendOrRecvKeyVSA) GetValue() interface{} {
	return a.Key
}

//随机一个新的 MSMPPESendOrRecvKeyVSA 的对象
func NewMSMPPESendOrRecvKeyVSA(p *radius.Packet, typ VendorType, key []byte) *MSMPPESendOrRecvKeyVSA {
	salt := [2]byte{}
	_, err := rand.Read(salt[:])
	if err != nil {
		panic(err)
	}
	salt[0] = salt[0] | 0x80 //最高位要是1
	vsa := &MSMPPESendOrRecvKeyVSA{
		packet: p,
		Type:   typ,
		Salt:   salt,
		Key:    key,
	}
	return vsa
}

type MSMPPEEncryptionPolicy uint32

const (
	MSMPPEEncryptionPolicyEncryptionAllowed  MSMPPEEncryptionPolicy = 1
	MSMPPEEncryptionPolicyEncryptionRequired MSMPPEEncryptionPolicy = 2
)

func (a MSMPPEEncryptionPolicy) String() string {
	switch a {
	case MSMPPEEncryptionPolicyEncryptionAllowed:
		return "Allowed"
	case MSMPPEEncryptionPolicyEncryptionRequired:
		return "Required"
	default:
		return fmt.Sprintf("unknow MSMPPEEncryptionPolicy:%d", a)
	}
}

type MSMPPEEncryptionTypes uint32

const (
	MSMPPEEncryptionTypesRC4Bit40      MSMPPEEncryptionTypes = 2
	MSMPPEEncryptionTypesRC4Bit128     MSMPPEEncryptionTypes = 4
	MSMPPEEncryptionTypesRC4Bit40Or128 MSMPPEEncryptionTypes = 6
)

func (a MSMPPEEncryptionTypes) String() string {
	switch a {
	case MSMPPEEncryptionTypesRC4Bit40:
		return "RC4Bit40"
	case MSMPPEEncryptionTypesRC4Bit128:
		return "RC4Bit128"
	case MSMPPEEncryptionTypesRC4Bit40Or128:
		return "RC4Bit40Or128"
	default:
		return fmt.Sprintf("unknow MSMPPEEncryptionTypes:%d", a)
	}
}

func msMPPEKeyEncode(p *radius.Packet, salt [2]byte, inData []byte) (out []byte, err error) {
	paddingSize := 16 - (len(inData)+1)%16
	if paddingSize == 16 {
		paddingSize = 0
	}
	paddingedData := make([]byte, len(inData)+1+paddingSize)
	if len(inData) > 255 {
		return nil, fmt.Errorf("[msMPPEKeyEncode] length overflow len(inData)[%d]>255", len(inData))
	}
	paddingedData[0] = byte(len(inData))
	copy(paddingedData[1:], inData)
	out = make([]byte, len(paddingedData)+2)
	copy(out[:2], salt[:])
	h := crypto.MD5.New()
	h.Write([]byte(p.Secret))
	h.Write(p.Authenticator[:])
	h.Write(out[:2])
	b := h.Sum(nil)
	blockSize := len(paddingedData) / 16
	for i := 0; i < blockSize; i++ {
		thisC := out[2+i*16 : 2+i*16+16]
		thisP := paddingedData[i*16 : i*16+16]
		xor(b, thisP, thisC)
		h := crypto.MD5.New()
		h.Write([]byte(p.Secret))
		h.Write(thisC)
		b = h.Sum(nil)
	}
	return out, nil
}

func msMPPEKeyDecode(p *radius.Packet, inData []byte) (out []byte, salt [2]byte, err error) {
	if len(inData) < 18 {
		return nil, salt, fmt.Errorf("[msMPPEKeyDecode] len(inData)[%d]<18", len(inData))
	}
	if (len(inData)-2)%16 != 0 {
		return nil, salt, fmt.Errorf("[msMPPEKeyDecode] (len(inData)[%d]-2)%%16!=0", len(inData))
	}
	salt = [2]byte{}
	copy(salt[:], inData[:2])
	h := crypto.MD5.New()
	h.Write([]byte(p.Secret))
	h.Write(p.Authenticator[:])
	h.Write(salt[:])
	b := h.Sum(nil)
	blockSize := (len(inData) - 2) / 16
	out = make([]byte, len(inData)-2)
	for i := 0; i < blockSize; i++ {
		thisC := inData[2+i*16 : 2+i*16+16]
		thisP := out[i*16 : i*16+16]
		xor(b, thisC, thisP)
		h := crypto.MD5.New()
		h.Write([]byte(p.Secret))
		h.Write(thisC)
		b = h.Sum(nil)
	}
	if int(out[0]) > len(inData)-3 {
		return nil, salt, fmt.Errorf("[msMPPEKeyDecode] out[0][%d]>len(inData)[%d]-3", out[0], len(inData))
	}
	return out[1 : out[0]+1], salt, nil
}

func xor(inA []byte, inB []byte, out []byte) {
	for i := 0; i < len(inA); i++ {
		out[i] = inA[i] ^ inB[i]
	}
}
