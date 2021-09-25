package radius

import (
	"bytes"
	"fmt"
	"log"

	"layeh.com/radius"
	"layeh.com/radius/rfc2759"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2868"
	"layeh.com/radius/rfc2869"
	"layeh.com/radius/rfc3079"
	"layeh.com/radius/vendors/microsoft"
)

type RadiusResponder struct {
	Port   int
	Secret string
}

func New(port int, secret string) *RadiusResponder {
	return &RadiusResponder{
		Port:   port,
		Secret: secret,
	}
}

func (r *RadiusResponder) Start() {
	/*handler := func(w radius.ResponseWriter, r *radius.Request) {
		username := rfc2865.UserName_GetString(r.Packet)
		password := rfc2865.UserPassword_GetString(r.Packet)
		//challenge := microsoft.MSCHAPChallenge_Get(r.Packet)
		//response := microsoft.MSCHAP2Response_Get(r.Packet)
		//responsePacket := r.Response(radius.CodeAccessAccept)
		log.Printf("#RARARARARARARARADIUS username=%s, password=%s", username, password)
		var code radius.Code
		if username == "matthieu.barthelemy" { //&& password == "totototo" {
			code = radius.CodeAccessAccept
		} else {
			code = radius.CodeAccessReject
			//packet := r.Packet
			//packet.MarshalBinary()
		}
		log.Printf("Writing %v to %v", code, r.RemoteAddr)
		w.Write(r.Response(code))
	}*/
	handler := func(w radius.ResponseWriter, r *radius.Request) {
		username := rfc2865.UserName_Get(r.Packet)
		value, err := microsoft.MSCHAPChallenge_Lookup(r.Packet)
		if err != nil {
			log.Printf("Error looking for Microsoft vendor: %+v", err)
		} else {
			log.Printf("Got MS vendor attribute: %s", value)
		}
		challenge := microsoft.MSCHAPChallenge_Get(r.Packet)
		response := microsoft.MSCHAP2Response_Get(r.Packet)

		test := rfc2865.CHAPPassword_Get(r.Packet)
		log.Printf("Got CHAP password attribute: %s", test)

		// TODO: look up user in local database.
		// The password must be stored in the clear for CHAP mechanisms to work.
		// In theory, it would be possible to use a password hashed with MD4 as
		// all the functions in MSCHAPv2 use the MD4 hash of the password anyway,
		// but given that MD4 is so vulnerable that breaking a hash is almost as
		// fast as computing it, it's just not worth it.
		password := []byte("mamie")

		log.Printf("MSCHAP challenge length=%d, response len=%d", len(challenge), len(response))
		if len(challenge) == 16 && len(response) == 50 {
			// See rfc2548 - 2.3.2. MS-CHAP2-Response
			ident := response[0]
			peerChallenge := response[2:18]
			peerResponse := response[26:50]
			ntResponse, err := rfc2759.GenerateNTResponse(challenge, peerChallenge, username, password)
			if err != nil {
				log.Printf("Cannot generate ntResponse for %s: %v", username, err)
				w.Write(r.Response(radius.CodeAccessReject))
				return
			}

			if bytes.Equal(ntResponse, peerResponse) {
				responsePacket := r.Response(radius.CodeAccessAccept)

				recvKey, err := rfc3079.MakeKey(ntResponse, password, false)
				if err != nil {
					log.Printf("Cannot make recvKey for %s: %v", username, err)
					w.Write(r.Response(radius.CodeAccessReject))
					return
				}

				sendKey, err := rfc3079.MakeKey(ntResponse, password, true)
				if err != nil {
					log.Printf("Cannot make sendKey for %s: %v", username, err)
					w.Write(r.Response(radius.CodeAccessReject))
					return
				}

				authenticatorResponse, err := rfc2759.GenerateAuthenticatorResponse(challenge, peerChallenge, ntResponse, username, password)
				if err != nil {
					log.Printf("Cannot generate authenticator response for %s: %v", username, err)
					w.Write(r.Response(radius.CodeAccessReject))
					return
				}

				success := make([]byte, 43)
				success[0] = ident
				copy(success[1:], authenticatorResponse)

				rfc2869.AcctInterimInterval_Add(responsePacket, rfc2869.AcctInterimInterval(3600))
				rfc2868.TunnelType_Add(responsePacket, 0, rfc2868.TunnelType_Value_L2TP)
				rfc2868.TunnelMediumType_Add(responsePacket, 0, rfc2868.TunnelMediumType_Value_IPv4)
				microsoft.MSCHAP2Success_Add(responsePacket, []byte(success))
				microsoft.MSMPPERecvKey_Add(responsePacket, recvKey)
				microsoft.MSMPPESendKey_Add(responsePacket, sendKey)
				microsoft.MSMPPEEncryptionPolicy_Add(responsePacket, microsoft.MSMPPEEncryptionPolicy_Value_EncryptionAllowed)
				microsoft.MSMPPEEncryptionTypes_Add(responsePacket, microsoft.MSMPPEEncryptionTypes_Value_RC440or128BitAllowed)

				log.Printf("Access granted to %s", username)
				w.Write(responsePacket)
				return
			}
		}

		log.Printf("Access denied for %s", username)
		w.Write(r.Response(radius.CodeAccessReject))
	}

	server := radius.PacketServer{
		Handler:      radius.HandlerFunc(handler),
		SecretSource: radius.StaticSecretSource([]byte(r.Secret)),
	}
	server.Addr = fmt.Sprintf(":%d", r.Port)
	log.Printf("Starting Radius responder on port %d", r.Port)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
