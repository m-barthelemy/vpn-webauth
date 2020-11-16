'use strict';

async function webAuthNRegisterStart(allowCrossPlatformDevice = false) {
    $("#touchid-icon").addClass("fadein-animated");
    const response = await fetch("/auth/webauthn/register", {method: 'POST'});
    if (response.status !== 200) {
        console.error(response);
        $("#error").show();
        return;
    }
    let optionsData = await response.json();
    let devicetype = "platform";
    if (allowCrossPlatformDevice) {
        devicetype = "cross-platform";
    }
    const options = {
        publicKey: {
            rp: { 
                name: optionsData.RpName, 
                id: optionsData.RpDomain,
            },
            user: {
                name: optionsData.Identity,
                id: Uint8Array.from(optionsData.Id, c => c.charCodeAt(0)),
                displayName: optionsData.Identity,
            },
            pubKeyCredParams: [ { type: "public-key", alg: -7 } ],
            allowCredentials: [
                { 
                    type: "public-key", 
                    id: Uint8Array.from(optionsData.Id, c => c.charCodeAt(0)), 
                    transports: ["internal"]
                },
            ],
            challenge: Uint8Array.from(optionsData.Secret, c => c.charCodeAt(0)),
            authenticatorSelection: { 
                authenticatorAttachment: devicetype,
                userVerification: "preferred"

            },
            timeout: 30000,
        }
    };
    
    let newCredentialInfo = await navigator.credentials.create(options);
        
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