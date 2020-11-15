'use strict';

function webAuthNRegisterStart(rpName, userEmail, displayName, randomStringFromServer) {
    let options = {
        publicKey: {
            rp: { 
                name: rpName, 
                id: "massdm.cloud",
            },
            user: {
                name: userEmail,
                id: Uint8Array.from("UZSL85T9AFC", c => c.charCodeAt(0)),
                displayName: displayName,
            },
            pubKeyCredParams: [ { type: "public-key", alg: -7 } ],
            allowCredentials: [
                { 
                    type: "public-key", 
                    id: Uint8Array.from(randomStringFromServer, c => c.charCodeAt(0)), 
                    transports: ["internal"]
                },
            ],
            challenge: Uint8Array.from(randomStringFromServer, c => c.charCodeAt(0)),
            authenticatorSelection: { authenticatorAttachment: "platform" },
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

}

let searchParams = new URLSearchParams(window.location.search);
if (searchParams.has('error')) {
    $("#error").show();
}
if (searchParams.has('options')) {
    var allOptions = searchParams.get('options').split(",");
    if (!allOptions.includes("touchid")) {
        $("#touchid").hide();
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