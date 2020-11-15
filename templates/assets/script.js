'use strict';

function webAuthNRegisterStart(allowCrossPlatformDevice = false) {
    $("#touchid-icon").addClass("fadein-animated");
    fetch("/auth/webauthn/register", {method: 'POST'})
        .then(function(response) {
            if (response.status !== 200) {
                console.error(response);
                $("#error").show();
                return;

            }
            response.json().then(function(optionsData) {
                var devicetype = "platform";
                if (allowCrossPlatformDevice) {
                    devicetype = "cross-platform";
                }
                let options = {
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
                
                navigator.credentials.create(options)
                    .then(function (newCredentialInfo) {
                        // send attestation response and client extensions
                        // to the server to proceed with the registration
                        // of the credential
                        console.log("inside then");
                    }).catch((err) => {
                            console.error(err);
                    });
            }); 
        });
}

let searchParams = new URLSearchParams(window.location.search);

if (searchParams.has('error')) {
    $("#error").show();
}

if (searchParams.has('options')) {
    var allOptions = searchParams.get('options').split(",");
    if (!window.PublicKeyCredential) { // Browser without any Webauthn support
        $("#touchid").hide();
    }
    else { 
        PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
            .then(function(available){ 
                let touchIdAllowed = allOptions.includes("touchid");
                if(available && touchIdAllowed){
                    console.log("TouchID/FaceID/Windows Hello is allowed and available.");
                } else {
                    console.log(`TouchID/FaceID/Windows Hello allowed: ${touchIdAllowed}, available: ${available}`);
                    $("#touchid").hide();
                }
            }).catch(function(err){
                // Something went wrong
                console.error(err);
            });
    }
    if(!allOptions.includes("webauthn")) {
        $("#webauthn").hide();
    }
    if(!allOptions.includes("otp")) {
        $("#otp").hide();
    }
}
$("input[type='number']").keyup( function() {
    console.warn("change! " + $("input[type='number']").val());
    var dataLength = $(this).val().length;
    
    if(dataLength > 0) {
        $("#error").hide();
    }
    if (dataLength == 6) {
        $("form").submit();
    }
}).change();