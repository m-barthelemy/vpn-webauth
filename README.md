## What is it?

This is quick (and dirty) web application allowing to add a second round of authentication to a Strongswan VPN.
It doesn't replace, and in fact requires, a normal authentication process using passwords or certificates.

Traditionally, simple IPSec VPN authentication methods involve deploying certificates to the client, or using a login + password.

While IKEv2 permits, in theory, the use of a second round of authentication, default VPN clients installed on OS such as MacOs and Windows have very little compatibility with it.

This project uses the `ext-auth` Strongswan plugin to provide an additional layer of authentication via a user web login and optional 2FA.
This can help to protect your organization aganist VPN credentials or certificates being leaked or stolen.

It can also help achieve compliance with some security standards requiring MFA to be implemented for VPNs giving access to sensitive environments.

This tool compatible with all VPN clients and operating systems.


## How does it work?

 - The user registers to the webapp (_before_ connecting to the VPN)
 - They authenticate using OAuth2 (for now, Google and Azure Directory are supported)
 - Optionally, they are required to complete additional authentication, using an OTP token (independent from the OAuth2 provider 2FA), TouchID/FaceID or a physical security key.
 - A "session" is created with the user email, their source IP address and the time when they completed the web authentication
 - They now connect to the VPN. Strongswan's `ext-auth` plugin calls this webapp to check if the user has successfully completed a web authentication recently and from the same source IP address. If not, the connection is rejected.

 If a user enables this app to send them notifications, they will generally be transparently allowed automatically to connect to the VPN once their VPN session expires, or if they connect from a different location/source IP, as long as their web authentication through this app is valid.

 If they need to sign in again, they will receive a clickable notification taking them to the app, as long as their browser is running. Without a running browser or if they refused to allow notifications from the app, they can still sign in _before_ connecting to the VPN.

## What does it look like?
Home/welcome screen:

<img width="742" alt="Screen Shot 2020-11-24 at 8 37 32 AM" src="https://user-images.githubusercontent.com/2519084/100031318-4d974800-2e30-11eb-95f9-73a143b05b09.png">


Signing in for the first time? 

<img width="749" alt="Screen Shot 2020-11-24 at 8 38 25 AM" src="https://user-images.githubusercontent.com/2519084/100031359-6d2e7080-2e30-11eb-94c4-3fa2f3ef1792.png">


OTP registration screen:

<img width="623" alt="Screen Shot 2020-11-24 at 8 40 48 AM" src="https://user-images.githubusercontent.com/2519084/100031508-c4344580-2e30-11eb-9c38-1979c9957505.png">


Normal user sign-in once they have setup their additional authentication step; in this example the user configured TouchID and a physical security key:

<img width="609" alt="Screen Shot 2020-11-24 at 8 44 00 AM" src="https://user-images.githubusercontent.com/2519084/100031692-37d65280-2e31-11eb-81f8-2a1c01758ff7.png">


Successful sign-in:

<img width="615" alt="Screen Shot 2020-12-04 at 9 04 54 AM" src="https://user-images.githubusercontent.com/2519084/101108589-d328ae00-360f-11eb-8367-812057910879.png">



## Limitations
- The user identity reported by Strongswan **must** match the email reported by the web authentication. However, if the Strongswan identity is the first part of the email address (without @domain.tld), you can modify the `webauth-check.sh` script to add the domain.
- If a user successfully authenticates using this app, someone else on the same local network would be able to reuse the web session, provided they have the user's Strongswan credentials. This by design, since the app matches a web auth with a Strongswan connection only using the Strongswan identity and the source IP address.
- Since the web authentication has to happen before connecting to the VPN, is probably needs to be hosted in a less protected part of your environment.
- There is currently no way to reset a user account if they have lost or changed their 2FA device. However, all you need to do is manually delete the User record in the database (`DELETE FROM users WHERE email='user@domain.tld'`).
- Strongswan blocks during the call to the `ext-auth` plugin. Since checking the user web authentication against this app is fast, this shouldn't be an issue, unless you have a high number of users connecting almost simultaneously.
- There is currently no limit on how many attempts a user can make at entering a 2FA OTP code or using a Webauthn device.

 ## Setup
 ### Build
 You'll need to build the project:
```
go get github.com/m-barthelemy/vpn-webauth
```
Alternatively, you can use the provided Dockerfile.

 ### Deploy
 You probably want to ensure this web app is served over HTTPS: while the OAuth2 flow will be protected by the provider, this app will receive information back from it, and if additional 2FA is required, the code has to be sent to the server.

 ### Run
 If you run the application behind a proxy such as Nginx, you need to make sure that the app receives the **real** user source IP address.
 With Nginx, you can for example add the following directive to your configuration:
 ```
 proxy_set_header X-Forwarded-For $remote_addr;
 ```
 and then set `ORIGINALIPHEADER` to `X-Forwarded-For`.
 
 You should also set a proper database configuration to store your sessions. By default, the app will store them into a Sqlite database in the `/tmp` directory. For a real setup, you can use Mysql or Postgres.

 ### Strongswan
 Make sure that Strongswan was build with the `ext-auth` module. While this is an [official module](https://wiki.strongswan.org/projects/strongswan/wiki/Ext-auth), it is not enabled in all Linux distributions (Ubuntu and Debian don't ship it for example):
 ```
 ipsec listplugins | grep ext-auth
 ```
 If it's not in the list, you'll have to compile Strongswan with the `--enable-extauth` option. 

 Then, configure the plugin. It can run any command; for verifying the webapp authentications, you can use the `webauth-check.sh` script in this repo.
 The script requires `curl` to be installed. 
 When deploying it to your Strongswan server, make sure it is executable: `chmod 755 /path/to/webauth-check.sh`.
 The `ext-auth` module configuration can then be added to `/etc/strongswan.conf` or equivalent file on your distribution:

```
plugins {
	...
	ext-auth {
		load = yes
		script = /path/to/webauth-check.sh https://this_webapp_host/vpn/check VPNCHECKPASSWORD
	}
	...
}
```

The application endpoint verifying if a user will be allowed to connect is `/vpn/check`.
It expects the following JSON encoded body data:
```json
{
	"Identity": "string",  // the VPN connection identity/login, matching the OAuth2 identity (email)
	"SourceIP": "string"
}
```

 ## Configuration options
All the configuration parameters have to passed as environment variables.
### Application
- `CONNECTIONSRETENTION`: how long to keep VPN connections audit logs, in days. Default: `90`.
  > NOTE: The connections audit log cleanup task is only run during the application startup. Also, there is currently no way to view this audit log from the app.
- `DBTYPE`: the database engine where the sessions will be stored. Default: `sqlite`. Can be `sqlite`, `postgres`, `mysql`.
- `DBDSN`: the database connection string. Default: `tmp/vpnwa.db`. Check https://gorm.io/docs/connecting_to_the_database.html for examples.
  > By default a Sqlite database is created. You probably want to at least change its path. Sqlite is only suitable for testing purposes or for a small number of concurrent users, and will only work with with a single instance of the app. It is recommended to use MySQL or Postgres instead.

  > NOTE: the app will automatically create the tables and thus needs to have the privileges to do so.
- `ENCRYPTIONKEY`: Key used to encrypt sensitive information in the database. Must be 32 characters. **Mandatory** if `ENFORCEMFA` is set to `true`.
- `EXCLUDEDIDENTITIES`: list of VPN accounts (identities) that do not require any additional authentication by this app, separated by comma. Optional.
  > The VPN server will still query the application when these accounts try to connect, but will always get a positive response.
  > NOTE: Your VPN's own authentication process still fully applies.
- `HOST`: the IP address to listen on. Default: `127.0.0.1`
- `ISSUER`: Name that appears on the users OTP authenticator app and browser notifications title. Default: `VPN`.
  > It is recommended that you set it to the name of your VPN connection as it appears on your users devices.
- `LOGOURL`: Add your organization logo on top of the webapp pages. Optional. If the app is served over HTTPS (and it should), `LOGOURL` must also be a HTTPS URL.
- `ORIGINALIPHEADER`: the header to use to fetch the real user/client source IP. Optional. If running this app behind Nginx for example, you will need to configure Nginx to pass the real client IP to the app using a specific header, and set its name here. Traditionally, `X-Forwarded-For` is used for this purpose. Default: empty.
- `ORIGINALPROTOHEADER`: the header to use to fetch the real protocol (http, https) used between the clients and the proxy. Default: `X-Forwarded-Proto`.
- `PORT`: the port to listen to. Default: `8080`
- `SIGNINGKEY`: Key used to sign the user session tokens during the web authentication. By default, a new signing key will be generated each time this application starts.
  > Regenerating a new key every time the application starts means that all your users web sessions will be invalid and they will have to sign in again if they need a new VPN "session".
  > It is recommended that you create and pass your own key.
- `WEBSESSIONVALIDITY`: How long a web authentication is valid. During this time, users don't need to go through the full OAuth2 + MFA process to get a new VPN session since the browser and existing session are considered as trusted. Default: `12h`. Specify custom value as a number and a time unit, for example `48h30m`. 

### OAuth2
- `OAUTH2PROVIDER`: The Oauth2 provider. Can be `google` or `azure`. **Mandatory**.
- `OAUTH2CLIENTID`: Google or Microsoft Client ID. **Mandatory**.
- `OAUTH2CLIENTSECRET`: Google or Microsoft Client Secret. **Mandatory**.
- `OAUTH2TENANT`: Azure Directory tenant ID. Mandatory if `OAUTH2PROVIDER` is set to `azure`.
- `REDIRECTDOMAIN`: the base URL that OAuth2 will redirect to after signing in. Default: http://`HOST`:`PORT`
  > You need to set it to the user-facing endpoint for this application, for example https://vpn.myconpany.com.

  > NOTE: You need to add this app redirect/callback endpoint (`REDIRECTDOMAIN/auth/google/callback` or `REDIRECTDOMAIN/auth/azure/callback`) to the list of allowed callbacks in your Google or Azure credentials configuration console.

### Multi-Factor Authentication
  - `ENFORCEMFA`: Whether to enforce additional 2FA after OAuth2 login. Default: `true`. If enabled, users will have to choose one of the available MFA options (see below).
  - `MFAOTP`: Whether to enable OTP token authentication after OAuth2 login. Default: `true`. 
  - `MFATOUCHID`: Whether to enable Apple TouchID/FaceID and Windows Hello biometrics authentication after OAuth2 login, if a compatible device is detected. Default: `true`.
    > With compatible devices and operating systems, this is certainly the fastest, most convenient and most secure additional authentication. 
    > This feature complies with the definiton of "Something you are" of the common three authentication factors.
    > NOTE: TouchID/FaceID feature is available in MacOS >= 11.x and iOS >= 14.x. The option will only be shown to the user if a compatible OS is detected.
  - `MFAWEBAUTHN`: Whether to enable strong authentication using security devices such as Fido keys after OAuth2 login. Default: `true`.

Webauthn additional authentications, including TouchID, are tied to a specific device and browser.
In case a user wants to be able to sign in from multiple browsers or devices, they have the option of generating a one-time 6 digits code to register a new device. This code is valid for 5 minutes and will be disabled after 3 failed attempts. 

It is also possible to sign in from different browsers and devices by using the OTP (authenticator app) feature.

### VPN
  - `VPNCHECKPASSWORD`: Shared password between the app and the Strongswan `ext-auth` script to protect the endpoint checking for valid user "sessions". Optional.
    > If the `/vpn/check` endpoint is publicly available, it is a good idea to set a password to ensure that only your VPN server is allowed to query the app for user sessions. Make sure you also set it in your `ext-auth` configuration.
  - `VPNSESSIONVALIDITY`: How long to allow (re)connections to the VPN after completing the web authentication. During this interval the web authentication status is not reverified. Default: `30m`. Specify custom value as a number and a time unit, for example `1h30m`.
    > This option aims at reducing the burden put on the users and avoids them having to go through the web auth again if they get disconnected within the configured delay, due for example to poor network connectivity or inactivity. 
    > NOTE: subsequent VPN connections must come from the same IP address used during the web authentication.

### SSL
  - `SSLMODE`: whether and how SSL is enabled. Default: `off`. Can be `auto`, `custom`, `proxy`, `off`.
    > `off` doesn't enforce SSL at all at the application level. It is only recommended for local testing.

    > `auto` automatically generates a private key and a Let'sEncrypt SSL certificate for the domain specified in `REDIRECTDOMAIN`. The generated key and certificates are stored into `SSLAUTOCERTSDIR` and reused during future application restarts.
    > NOTE: `auto` will force the application to also listen on port 80 in order to generate the LetsEncrypt certificate. This port is privileged, meaning that you will need to start the application as root using `sudo`, or executing `chmod u+s vpn-webauth` to grant the binary admin permissions. Any user request to port 80 will redirect to the `PORT` HTTPS port.

    > `custom` will let you specify a custom certificate and key using `SSLCUSTOMCERTPATH` and `SSLCUSTOMKEYPATH`.

    > `proxy` delegates the responsibility of providing SSL termination to an external component or proxy. However, unlike `off`, it sets the `Secure` flag for the cookies generated by the application and adds an HSTS HTTP header.
  - `SSLCUSTOMCERTPATH`: path to the SSL certificate. Optional. Default: `/ssl/key.pem`. If needed, this file can contain any additional certificate required to build the full chain, _after_ the leaf certificate.
  - `SSLCUSTOMKEYPATH`: path to the SSL certificate private key. Optional. Default: `/ssl/cert.pem`.
  - `SSLAUTOCERTSDIR`: used to store automatically manage certificates when `SSLMODE` is set to `auto`. Default: `/tmp`. Should be changed to a more persistent path. The directory must be writeable.


### Notifications & Session continuity
These 2 features can improve the user experience. After registering or signing in, users will be shown a message inviting them to enable notifications for the app. 

If they accept, when they attempt to connect to the VPN without a valid web session, they will receive a notification letting them know that they need to sign in for the VPN connection to be authorized.

 Additionally, if their VPN session is expired (`VPNSESSIONVALIDITY`) but they still have a valid web session (`WEBSESSIONVALIDITY`), their next attempt to connect to the VPN will try to transparently ask the browser used to sign in to prove that it still holds a valid session and has the same source IP as the VPN connection attempt. If so, the VPN connection will be automatically allowed and a new VPN "session" created without any intervention.

> NOTE: automatic VPN sessions renewal is a best effort feature; the browser must be running, even without this app opened, and must reply with a "proof of session and IP" quickly enough. This is because Strongswan will be waiting in blocking mode for the app to reply whether the user is allowed. 
Network latency and distance between end users and the app could negatively impact their ability to use the feature.
By default, the app stops waiting for a browser "proof of session" after 600ms.


- `ENABLENOTIFICATIONS`: whether to enable desktop notifications and session continuity. Default: `true`.
- `VAPIDPUBLICKEY` and `VAPIDPRIVATEKEY`: a key pair to authenticate and authorize browser desktop notifications. Mandatory if `ENABLENOTIFICATIONS` is set to `true`. 

If they are not set, a new key pair will be dynamically generated and suggested before the app startup fails. If you use the suggested key pair, ensure the suggested `VAPIDPRIVATEKEY` is kept secret and has not been shared or logged. Once set, the keys must not change otherwise all existing users subscriptions to notifications will be invalid.

   > NOTE: you can also generate your own set of keys using the following commands:
   ```
   # Generate private key
   openssl ecparam -name prime256v1 -genkey -noout -out vapid_private.pem
   # Output private key in a format suitable for VAPIDPRIVATEKEY:
   openssl ec -in vapid_private.pem -outform DER|tail -c +8|head -c 32|base64|tr -d '=' |tr '/+' '_-'
   # Output public key in a format suitable for VAPIDPUBLICKEY:
   openssl ec -in vapid_private.pem -pubout -outform DER|tail -c 65|base64|tr -d '=' |tr '/+' '_-' 

   ```
Currently Google Chrome, Firefox and Edge support notifications and automated VPN session renewal without meeding to keep this app opened.
Safari requires the user to keep a tab open.
