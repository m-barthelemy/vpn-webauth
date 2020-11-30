'use strict';

async function tryGetNotificationsApproval() {
    if(Notification.permission === "granted") {
        return true;
    }
    else {
        const permission = await Notification.requestPermission();
        if(permission === 'granted') {
            return true;
        }
    }
    return false;
}

/*function createNotification(title, text, icon) {
    const notif = new Notification(title, {
        body: text,
        ison: icon
    });
    notif.onclick = function(event) {
        event.preventDefault(); // prevent the browser from focusing the Notification's tab
        window.open('https://vpn.massdm.cloud');
    }
}*/

const checkWorkerPush = () => {
    if (!('serviceWorker' in navigator)) {
        console.warn('No Service Worker support!');
        return false;
    }
    if (!('PushManager' in window)) {
      console.warn('No Push API Support!');
      return false;
    }
    return true;
}

const getSubscriptionKey = async subscription => {
    const response = await fetch("/user/push_subscriptions/begin", {
      method: 'post',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(subscription),
    });
    return response.json();
  }

function urlBase64ToUint8Array(base64String) {
    var padding = '='.repeat((4 - base64String.length % 4) % 4);
    var base64 = (base64String + padding)
        .replace(/\-/g, '+')
        .replace(/_/g, '/');

    var rawData = atob(base64);
    var outputArray = new Uint8Array(rawData.length);

    for (var i = 0; i < rawData.length; ++i) {
        outputArray[i] = rawData.charCodeAt(i);
    }
    return outputArray;
}

const saveSubscription = async subscription => {
    const response = await fetch("/user/push_subscriptions/finish", {
      method: 'post',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(subscription),
    });
    return response;
  }

const registerServiceWorker = async () => {
    if (!('PushManager' in window)) {
        console.warn("pushManager not available");
        return;
    }
    if (!('serviceWorker' in navigator)) {
        console.warn("Service Worker not available");
        return;
    }
    let swRegistration = await navigator.serviceWorker.register('/service.js');
    swRegistration = await navigator.serviceWorker.ready;
    console.log("Registered service worker");
    const existingSubscription = await swRegistration.pushManager.getSubscription();
    if (existingSubscription){
        console.log("Already subscribed to push notifications");
        return swRegistration;
    }

    try {
        var vapid = await getSubscriptionKey();
        const applicationServerKey = urlBase64ToUint8Array(vapid.PublicKey);
        const options = { applicationServerKey: applicationServerKey, userVisibleOnly: true};
        const subscription = await swRegistration.pushManager.subscribe(options);
        const response = await saveSubscription(subscription);
    } catch (err) {
        console.log('Error', err);
    }
}

// Force service worker reload during dev
if (new URLSearchParams(window.location.search).has('sw')) {
    console.log("Going to reload SW");
    navigator.serviceWorker.getRegistration("/assets/service.js").then(function(reg) {
        if (reg) {
            console.log("Reloading Service Worker");
            reg.unregister().then(function() {
                window.location.href = "/";
            });
        } 
    });
}


// Inspired by https://github.com/hbolimovsky/webauthn-example/blob/master/index.html

async function webAuthNRegisterStart(allowCrossPlatformDevice = false) {
    let provider = "webauthn";
    if (!allowCrossPlatformDevice) {
        provider = "touchid";
    }
    $(`#${provider}-icon`).addClass("fadein-animated");

    const response = await fetch(`/auth/webauthn/beginregister?type=${provider}`, {
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
    
    let newCredentialInfo;
    try{
        newCredentialInfo = await navigator.credentials.create(optionsData);
    }
    catch (e) {
        $(`#${provider}-icon`).removeClass("fadein-animated");
        $("#error").html(`<b>Unable to register your security device. </b>`);
        $("#error").show();
        return;
    }

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
    const registerResponse = await fetch(`/auth/webauthn/finishregister?type=${provider}`, {
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
        window.location.href = `/success?source=register&provider=${provider}`;
    }
}

async function webAuthNLogin(allowCrossPlatformDevice = false) {
    $("#touchid-icon").addClass("fadein-animated");
    let provider = "webauthn";
    if (!allowCrossPlatformDevice) {
        provider = "touchid";
    }
    const response = await fetch(`/auth/webauthn/beginlogin?type=${provider}`, {
        method: 'POST',
        headers: {
            'Accept': 'application/json'
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
            This will allow you to generate a one time code.<br/>
            Click <a href="/enter2fa?options=code">here</a> to enter a one time code.
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
    const loginResponse = await fetch(`/auth/webauthn/finishlogin?type=${provider}`, {
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
            'Accept': 'application/json'
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
        $("#temp-code-value").show();
        $("#temp-code-expiry").text(`This code is valid until ${new Date(code.ExpiresAt).toLocaleString()}`);
    }
}

// ArrayBuffer to URLBase64
function bufferEncode(value) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(value)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
}

// Base64 to ArrayBuffer
function bufferDecode(value) {
    return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}



// main
$(document).ready(async function(){
    if ('permissions' in navigator) {
        const notificationPerm = await navigator.permissions.query({name:'notifications'});
        console.log(`Notifications are ${notificationPerm.state}`);
        if (notificationPerm.state === "granted") {
            registerServiceWorker();
        }
        // Watch for permissions change if user denies notifications but later enables them
        notificationPerm.onchange = function() {
            if (notificationPerm.state !== "denied") {
                tryGetNotificationsApproval() && registerServiceWorker();
            }
        };
    }

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
        if(!allOptions.includes("touchid")) {
            console.log("TouchID is not allowed");
            $("#touchid-section").hide();
        }
        // This one is very specific, so hidden by default
        if(allOptions.includes("code")) {
            console.log("Single usage code is allowed");
            $("#code-section").show();
        }
    }

    if (!window.PublicKeyCredential) { // Browser without any Webauthn support
        $("#touchid-section").hide();
        $("#webauthn-section").hide();
    }
    else {
        const tpmAuthAvailable = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
        if(tpmAuthAvailable){
            console.log("TouchID/FaceID/Windows Hello is available.");
        } else {
            console.log(`TouchID/FaceID/Windows Hello available: ${tpmAuthAvailable}`);
            $("#touchid-section").hide();
        }
    }

    // Fetch and display user and session info.
    var userInfo = {};
    const userResponse = await fetch("/user/info", {
        method: "GET",
        headers: {
            'Accept': 'application/json',
        },
    });
    if (!userResponse.ok) {
        if(userResponse.statusText != "") {
            $("#error").text(userResponse.statusText);
        }
        $("#error").show();
        return;
    }
    else {
        userInfo = await userResponse.json();
        console.log(`userInfo: ${JSON.stringify(userInfo)}`);
    }
    $("#data-issuer").text(userInfo.Issuer);
    $("#data-session-validity").text(new Date(userInfo.SessionExpiry * 1000).toLocaleString());

    if (userInfo.EnableNotifications) {
        if (checkWorkerPush() && Notification.permission === "default") {
            $("#notification-info").show();
        }
        else if (Notification.permission === "denied") {
            $("#notification-warning").show();
        }
    }

    $("#login-touchid").click(function() {
        webAuthNLogin(false);
    });
    $("#login-webauthn").click(function() {
        webAuthNLogin(true);
    });
    $("#register-touchid").click(function() {
        webAuthNRegisterStart(false);
    });
    $("#register-webauthn").click(function() {
        webAuthNRegisterStart(true);
    });
    $("#register-otc").click(function() {
        getSingleUseCode();
    });
    $("#allow-notifications").click(function() {
        if (tryGetNotificationsApproval()) {
            registerServiceWorker();
            $("#allow-notifications").addClass("disabled");
            $("#allow-notifications-icon").text("check_circle");
            // Reload is apparently needed to ensure the Service Worker is linked to the page, despite calling claim()
            // TODO: FIXME.
            setTimeout(location.reload.bind(location), 3000);
        }
    });

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
            // TODO: Move to function
            const codeResponse = await fetch("/auth/code/validate", {
                method: "POST",
                body: JSON.stringify(
                    { Code: $(this).val() }
                ),
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                },
            });
            if (!codeResponse.ok) {
                console.error(codeResponse);
                if(codeResponse.statusText != "") {
                    $("#error").text(codeResponse.statusText);
                }
                $("#error").show();
                return;
            }
            else {
                window.location.href = "/auth/getmfachoice";
            }
        }
    }).change();
});
