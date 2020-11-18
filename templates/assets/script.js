'use strict';

async function webAuthNRegisterStart(allowCrossPlatformDevice = false) {
    $("#touchid-icon").addClass("fadein-animated");
    const response = await fetch("/auth/webauthn/beginregister?type=touchid", {method: 'POST'});
    if (response.status !== 200) {
        console.error(response);
        $("#error").show();
        return;
    }
    let optionsData = await response.json();
    
    optionsData.publicKey.user.id = Uint8Array.from(base64.decode(optionsData.publicKey.user.id), c => c.charCodeAt(0));
    optionsData.publicKey.challenge = Uint8Array.from(base64.decode(optionsData.publicKey.challenge), c => c.charCodeAt(0));

    // Not sure how to set that using the server webauthn library so overriding here...
    if(allowCrossPlatformDevice == false) {
        optionsData.publicKey.allowCredentials = [
            { 
                type: "public-key", 
                id: optionsData.publicKey.user.id, 
                transports: ["internal"]
            },
        ];
    }
    
    let newCredentialInfo = await navigator.credentials.create(optionsData);
    /*console.log(newCredentialInfo);
    const regoResponse = {
        PublicKeyCredential : {
            ID: newCredentialInfo.id,
            RawID: btoa(String.fromCharCode(...new Uint8Array(newCredentialInfo.rawId))),
            Type: newCredentialInfo.type
        },
        AttestationResponse: {
            ClientDataJSON: bufferEncode(newCredentialInfo.response.clientDataJSON),
            AttestationObject: bufferEncode(newCredentialInfo.response.attestationObject),
        }
    };
    console.log(JSON.stringify(regoResponse));
    const registerResponse = await fetch("/auth/webauthn/finishregister?type=touchid", {
        method: "POST",
        body: JSON.stringify(regoResponse),
        headers: { "Content-Type": "application/json" },
    });
    if (registerResponse.status !== 200) {
        console.error(registerResponse);
        $("#error").show();
        return;
    }*/

    let attestationObject = newCredentialInfo.response.attestationObject;
    let clientDataJSON = newCredentialInfo.response.clientDataJSON;
    let rawId = newCredentialInfo.rawId;
    const regoResponse = {
        id: newCredentialInfo.id,
        rawId: bufferEncode(rawId),
        type: newCredentialInfo.type,
        response: {
            attestationObject: bufferEncode(attestationObject),
            clientDataJSON: bufferEncode(clientDataJSON),
        },
    };
    const registerResponse = await fetch("/auth/webauthn/finishregister?type=touchid", {
        method: "POST",
        body: JSON.stringify(regoResponse),
        headers: { "Content-Type": "application/json" },
    });
    if (registerResponse.status !== 200) {
        console.error(registerResponse);
        $("#error").show();
        return;
    }
    
    /* expected by the go library:
    CredentialCreationResponse {
        PublicKeyCredential {
            ID string
            Type string
            RawID URLEncodedBase64
            Extensions {}

        }
        AttestationResponse {
            ClientDataJSON  URLEncodedBase64
            AttestationObject URLEncodedBase64
        }
    }*/
     
}

$(document).ready(async function(){
    const searchParams = new URLSearchParams(window.location.search);

    if (searchParams.has('error')) {
        $("#error").show();
    }

    if (searchParams.has('options')) {
        const allOptions = searchParams.get('options').split(",");
        if(!allOptions.includes("webauthn")) {
            console.log("Webauthn is not allowed");
            $("#webauthn-section").hide();
        }
        if(!allOptions.includes("otp")) {
            console.log("OTP is not allowed");
            $("#otp-section").hide();
        }
        if (!window.PublicKeyCredential) { // Browser without any Webauthn support
            $("#touchid-section").hide();
        }
        else { 
            const tpmAuthAvailable = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
            const touchIdAllowed = allOptions.includes("touchid");
            if(tpmAuthAvailable && touchIdAllowed){
                console.log("TouchID/FaceID/Windows Hello is allowed and available.");
            } else {
                console.log(`TouchID/FaceID/Windows Hello allowed: ${touchIdAllowed}, available: ${available}`);
                $("#touchid-section").hide();
            }
        }
    }
});

$("input[type='number']").keyup( function() {
    const dataLength = $(this).val().length;
    
    if(dataLength > 0) {
        $("#error").hide();
    }
    if (dataLength == 6) {
        $("form").submit();
    }
}).change();


function bufferEncode(value) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(value)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");;
  }

// From https://github.com/client9/stringencoders/blob/master/javascript/base64.js
var base64 = {};
base64.PADCHAR = '=';
base64.ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

base64.makeDOMException = function() {
    // sadly in FF,Safari,Chrome you can't make a DOMException
    var e, tmp;

    try {
        return new DOMException(DOMException.INVALID_CHARACTER_ERR);
    } catch (tmp) {
        // not available, just passback a duck-typed equiv
        // https://developer.mozilla.org/en/Core_JavaScript_1.5_Reference/Global_Objects/Error
        // https://developer.mozilla.org/en/Core_JavaScript_1.5_Reference/Global_Objects/Error/prototype
        var ex = new Error("DOM Exception 5");

        // ex.number and ex.description is IE-specific.
        ex.code = ex.number = 5;
        ex.name = ex.description = "INVALID_CHARACTER_ERR";

        // Safari/Chrome output format
        ex.toString = function() { return 'Error: ' + ex.name + ': ' + ex.message; };
        return ex;
    }
}

base64.getbyte64 = function(s,i) {
    // This is oddly fast, except on Chrome/V8.
    //  Minimal or no improvement in performance by using a
    //   object with properties mapping chars to value (eg. 'A': 0)
    var idx = base64.ALPHA.indexOf(s.charAt(i));
    if (idx === -1) {
        throw base64.makeDOMException();
    }
    return idx;
}

base64.decode = function(s) {
    // convert to string
    s = '' + s;
    var getbyte64 = base64.getbyte64;
    var pads, i, b10;
    var imax = s.length
    if (imax === 0) {
        return s;
    }

    if (imax % 4 !== 0) {
        throw base64.makeDOMException();
    }

    pads = 0
    if (s.charAt(imax - 1) === base64.PADCHAR) {
        pads = 1;
        if (s.charAt(imax - 2) === base64.PADCHAR) {
            pads = 2;
        }
        // either way, we want to ignore this last block
        imax -= 4;
    }

    var x = [];
    for (i = 0; i < imax; i += 4) {
        b10 = (getbyte64(s,i) << 18) | (getbyte64(s,i+1) << 12) |
            (getbyte64(s,i+2) << 6) | getbyte64(s,i+3);
        x.push(String.fromCharCode(b10 >> 16, (b10 >> 8) & 0xff, b10 & 0xff));
    }

    switch (pads) {
    case 1:
        b10 = (getbyte64(s,i) << 18) | (getbyte64(s,i+1) << 12) | (getbyte64(s,i+2) << 6);
        x.push(String.fromCharCode(b10 >> 16, (b10 >> 8) & 0xff));
        break;
    case 2:
        b10 = (getbyte64(s,i) << 18) | (getbyte64(s,i+1) << 12);
        x.push(String.fromCharCode(b10 >> 16));
        break;
    }
    return x.join('');
}

base64.encode = function(s) {
    if (arguments.length !== 1) {
        throw new SyntaxError("Not enough arguments");
    }
    var padchar = base64.PADCHAR;
    var alpha   = base64.ALPHA;
    var getbyte = base64.getbyte;

    var i, b10;
    var x = [];

    // convert to string
    s = '' + s;

    var imax = s.length - s.length % 3;

    if (s.length === 0) {
        return s;
    }
    for (i = 0; i < imax; i += 3) {
        b10 = (getbyte(s,i) << 16) | (getbyte(s,i+1) << 8) | getbyte(s,i+2);
        x.push(alpha.charAt(b10 >> 18));
        x.push(alpha.charAt((b10 >> 12) & 0x3F));
        x.push(alpha.charAt((b10 >> 6) & 0x3f));
        x.push(alpha.charAt(b10 & 0x3f));
    }
    switch (s.length - imax) {
    case 1:
        b10 = getbyte(s,i) << 16;
        x.push(alpha.charAt(b10 >> 18) + alpha.charAt((b10 >> 12) & 0x3F) +
               padchar + padchar);
        break;
    case 2:
        b10 = (getbyte(s,i) << 16) | (getbyte(s,i+1) << 8);
        x.push(alpha.charAt(b10 >> 18) + alpha.charAt((b10 >> 12) & 0x3F) +
               alpha.charAt((b10 >> 6) & 0x3f) + padchar);
        break;
    }
    return x.join('');
}

base64.getbyte = function(s,i) {
    var x = s.charCodeAt(i);
    if (x > 255) {
        throw base64.makeDOMException();
    }
    return x;
}
