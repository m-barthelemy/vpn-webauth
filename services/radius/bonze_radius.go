package radius

import (
	"fmt"

	"github.com/bronze1man/radius"
)

/*type RadiusResponder2 struct {
	Port   int
	Secret string
}

func New2(port int, secret string) *RadiusResponder2 {
	return &RadiusResponder2{
		Port:   port,
		Secret: secret,
	}
}*/

type RadiusService struct{}

func (p RadiusService) RadiusHandle(request *radius.Packet) *radius.Packet {
	// a pretty print of the request.
	fmt.Printf("[Authenticate] %s\n", request.String())
	npac := request.Reply()
	switch request.Code {
	case radius.AccessRequest:
		// check username and password
		if request.GetUsername() == "a" && request.GetPassword() == "a" {
			npac.Code = radius.AccessAccept
			// add Vendor-specific attribute - Vendor Cisco (code 9) Attribute h323-remote-address (code 23)
			npac.AddVSA(radius.VSA{Vendor: 9, Type: 23, Value: []byte("10.20.30.40")})
		} else {
			npac.Code = radius.AccessReject
			npac.AddAVP(radius.AVP{Type: radius.ReplyMessage, Value: []byte("you dick!")})
		}
	case radius.AccountingRequest:
		// accounting start or end
		npac.Code = radius.AccountingResponse
	default:
		npac.Code = radius.AccessAccept
	}
	return npac
}
