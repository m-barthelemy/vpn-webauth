'use strict';

// Inspired by https://github.com/hbolimovsky/webauthn-example/blob/master/index.html
async function webAuthNRegisterStart(allowCrossPlatformDevice = false) {
    $("#touchid-icon").addClass("fadein-animated");
    const response = await fetch("/auth/webauthn/beginregister?type=touchid", {method: 'POST'});
    if (response.status !== 200) {
        console.error(response);
        $("#error").show();
        return;
    }
    let optionsData = await response.json();
    
    optionsData.publicKey.user.id = bufferDecode(optionsData.publicKey.user.id);
    optionsData.publicKey.challenge = bufferDecode(optionsData.publicKey.challenge);

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
    else {
        window.location.href = "/success";
    }
}

async function webAuthNLogin(allowCrossPlatformDevice = false) {
    $("#touchid-icon").addClass("fadein-animated");
    const response = await fetch("/auth/webauthn/beginlogin?type=touchid", {method: 'POST'});
    if (response.status !== 200) {
        console.error(response);
        $("#error").show();
        return;
    }
    let credentialRequestOptions = await response.json();
    console.log(credentialRequestOptions)
    credentialRequestOptions.publicKey.challenge = bufferDecode(credentialRequestOptions.publicKey.challenge);
    credentialRequestOptions.publicKey.allowCredentials.forEach(function (listItem) {
        listItem.id = bufferDecode(listItem.id)
    });
    
    const assertion = await navigator.credentials.get(credentialRequestOptions);
    console.log(assertion)
    let authData = assertion.response.authenticatorData;
    let clientDataJSON = assertion.response.clientDataJSON;
    let rawId = assertion.rawId;
    let sig = assertion.response.signature;
    let userHandle = assertion.response.userHandle;

    const loginResponseData = {
        id: assertion.id,
        rawId: bufferEncode(rawId),
        type: assertion.type,
        response: {
            authenticatorData: bufferEncode(authData),
            clientDataJSON: bufferEncode(clientDataJSON),
            signature: bufferEncode(sig),
            userHandle: bufferEncode(userHandle),
        },
    };
    const loginResponse = await fetch("/auth/webauthn/finishlogin?type=touchid", {
        method: "POST",
        body: JSON.stringify(loginResponseData),
        headers: { "Content-Type": "application/json" },
    });
    if (!loginResponse.ok) {
        console.error(loginResponse);
        $("#error").show();
        return;
    }
    else {
        window.location.href = "/success";
    }
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
                console.log(`TouchID/FaceID/Windows Hello allowed: ${touchIdAllowed}, available: ${tpmAuthAvailable}`);
                $("#touchid-section").hide();
            }
        }
    }
    let sessionValidity = $("#session-validity").text();
    console.log(`Session valid until ${sessionValidity}`);
    if (sessionValidity != "") {
        let expiry = new Date();
        expiry.setSeconds(expiry.getSeconds() + parseInt($("#session-validity").text()));
        $("#session-validity").text(expiry);
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

// ArrayBuffer to URLBase64
function bufferEncode(value) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(value)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");;
}

// Base64 to ArrayBuffer
function bufferDecode(value) {
    return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}

