'use strict';

// Inspired by https://github.com/hbolimovsky/webauthn-example/blob/master/index.html
async function webAuthNRegisterStart(allowCrossPlatformDevice = false) {
    $("#touchid-icon").addClass("fadein-animated");
    const response = await fetch("/auth/webauthn/beginregister?type=touchid", {
        method: 'POST',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
    });
    if (response.status == 401) {
        window.location.href = "/";
    }
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
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
    });
    if (registerResponse.status !== 200) {
        console.error(registerResponse);
        $("#error").show();
        return;
    }
    else {
        window.location.href = "/success?source=register&provider=webauthn";
    }
}

async function webAuthNLogin(allowCrossPlatformDevice = false) {
    $("#touchid-icon").addClass("fadein-animated");
    const response = await fetch("/auth/webauthn/beginlogin?type=touchid", {
        method: 'POST',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
    });
    if (response.status == 401) {
        window.location.href = "/";
    }
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
    credentialRequestOptions.mediation = "silent";

    let assertion;
    try{
        assertion = await navigator.credentials.get(credentialRequestOptions);
    }
    catch (e) {
        $("#touchid-icon").removeClass("fadein-animated");
        $("#error").html(`<b>You may be trying to authenticate from a new device or browser. <br/>
            Sign in using your allowed device or browser, and click 'Add new browser or device'.<br/>
            Then follow the instructions.<br/>
            <a href="/enter2fa?options=code">I got a temporary code</a>
            </b>`);
        $("#error").show();
        return;
    }
    
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
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
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

async function getSingleUseCode() {
    const codeResponse = await fetch("/auth/code/generate", {
        method: "POST",
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
    });
    if (!codeResponse.ok) {
        console.error(codeResponse);
        $("#error").text(codeResponse.statusText);
        $("#error").show();
        return;
    }
    else {
        const code = await codeResponse.json();
        $("#temp-code-value").text(code.code);

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
        // This one is very specific, so hidden by default
        if(allOptions.includes("code")) {
            console.log("Single usage code is allowed");
            $("#code-section").show();
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
        $("#session-validity").text(expiry.toLocaleString());
    }

    // Success page: check if it was a registration or a login
    if (searchParams.has('source')) {
        const source = searchParams.get('source');
        const provider = searchParams.get('provider');
        if (source == "register" && provider == "webauthn") {
            $("#success-info-message").text("The next times you sign in, you will need to use the same browser.");
            $("#success-info").show();
        }

    }

    //$("input[type='number']").keyup( function() {
    $("#otp").keyup( function() {
        const dataLength = $(this).val().length;
        
        if(dataLength > 0) {
            $("#error").hide();
        }
        if (dataLength == 6) {
            $("#otp-form").submit();
        }
    }).change();

    $("#code").keyup( async function() {
        const dataLength = $(this).val().length;
        
        if(dataLength > 0) {
            $("#error").hide();
        }
        if (dataLength == 6) {
            const codeResponse = await fetch("/auth/code/validate", {
                method: "POST",
                body: JSON.stringify(
                    { code: $(this).val() }
                ),
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                },
            });
            if (!codeResponse.ok) {
                console.error(codeResponse);
                $("#error").text(codeResponse.statusText);
                $("#error").show();
                return;
            }
            else {
                window.location.href = "/choose2fa";
            }
        }
    }).change();
});


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

