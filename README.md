## What is it?

This is quick (and dirty) web application allowing to add a second round of authentication to a Strongswan VPN and/or to SSH connections.
It doesn't replace, and in fact requires, a normal VPN or SSH authentication process.
It provides an additional layer of authentication via a user web login and optional 2FA : any VPN or SSH connection is tied to an existing user web session.


It can help achieve compliance with some security standards requiring MFA to be implemented to your authentication workflows.

### For Strongswan VPNs
This project uses the `ext-auth` Strongswan plugin.
This can help to protect your organization aganist VPN credentials or certificates being leaked or stolen.
This tool compatible with all VPN clients and operating systems.

### For SSH
This project used the `pam_exec` PAM module shipped with the majority of the Linux distributions.


## How does it work?

 - The user registers to the webapp
 - They authenticate using OAuth2 (for now, Google and Azure Directory are supported)
 - Optionally, they are required to complete additional authentication, using an OTP token (independent from the OAuth2 provider 2FA), TouchID/FaceID or a physical security key.
 - A "session" is created with the user email, their source IP address and the time when they completed the web authentication
 - If the VPN webauth feature is configured: when a user connects to your VPN, Strongswan's `ext-auth` plugin calls this webapp to check if the user has successfully completed a web authentication recently, from the same source IP address and user name (the web session email must match the VPN connection identity). If not, the connection is rejected.
- If the SSH webauth feature is enabled and configured: when a user connected to a remote system via SSH, the PAM `pam_exec` module calls this webapp to check if the user has successfully completed a web authentication recently and has registered their SSH key in this app. If not, the connection is rejected with a message inviting the user to sign in. 
  Unlike the VPN feature, the app does not enforce that the SSH connection come from the same source IP as the web session, since in many organizations a VPN connection or a jump host are used for accessing remote systems through SSH. The link between a user web session and SSH connections is made using the user SSH keys by default or, alternatively, by matching a web session identity (email) with the SSH username (like the VPN web auth feature previously described).


 If a user enables this app to send them notifications, they will generally be transparently allowed automatically to connect to the remote VPN or SSH system once their VPN session expires, or if they connect from a different location/source IP, as long as their web authentication through this app is valid.

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
The easiest way to use this project is to download the precompiled binaries generated with each release at https://github.com/m-barthelemy/vpn-webauth/releases for your system.

Alternatively, you can build the project yourself:
```
go get github.com/m-barthelemy/vpn-webauth
```

You can also build the provided Dockerfile.

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

 ### Configure the VPN server (Strongswan)
 Make sure that Strongswan was build with the `ext-auth` module. While this is an [official module](https://wiki.strongswan.org/projects/strongswan/wiki/Ext-auth), it is not enabled in all Linux distributions (Ubuntu and Debian don't ship it for example):
 ```
 ipsec listplugins | grep ext-auth
 ```
 If it's not in the list, you'll have to compile Strongswan with the `--enable-extauth` option. 

 Then, configure the plugin. It can run any command; for verifying the webapp authentications, you can use the `scripts/vpn-webauth.sh` script in this repo.
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
  "SourceIP": "string",
  "CallerName": "string", // optional. Name of the VPN connection to display in browser desktop notifications.
}
```

### Configure PAM for SSH

XXXXXXXXXXXXXXXxxxxxx
XXXXXXXXXXXXXXXxxxxxx

Deploy the provided `scripts/ssh-webauth.sh` `pem_exec` script. Make sure it has restricted permissions (`chmod 500` for example). 
The script requires `curl` to be installed.

Configure the PAM session module to require and use `ssh-webauth.sh`:

First, we'll configure PAM to use this app in non enforcing mode, in order not to break all your accesses to your remote system in case this app is not properly configured.
```
xxxxxxx  stdout quiet /path/to/ssh-webauth.sh https://thisappdomain.tld/check/ssh REMOTEAUTHCHECKPASSWORD
```

Ensure that `sshd` uses the PAM authentication subsystem: you must have `UsePAM yes` present in your sshd config file.

Try connecting to your remote system through SSH. Once you have a fully working setup, you can enforce the custom PAM authentication:
```
xxxxxxxxxxxxXXXXXXXXXXXX
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
- `EXCLUDEDIDENTITIES`: list of VPN or SSH user accounts (identities) that do not require any additional authentication by this app, separated by comma. Optional.
  > The VPN or SSH server will still query the application when these accounts try to connect, but will always get a positive response.
- `HOST`: the IP address to listen on. Default: `127.0.0.1`
- `ORGNAME`: Name that appears on the users OTP authenticator app. Default: `VPN`.
  > It is recommended that you set it to the name of your organization.

  > Browser notifications related to VPN connections will use `ORGNAME` in their title by default, unless the call from the VPN server sets a custom `CallerName` field (check `scripts/vpn-webauth.sh`).

  > Browser notifications related to SSH connections will contain the hostname and IP address of the remote system the user tries to connect to.

- `LOGOURL`: Add your organization logo on top of the webapp pages. Optional. If the app is served over HTTPS (and it should), `LOGOURL` must also be a HTTPS URL.
- `ORIGINALIPHEADER`: the header to use to fetch the real user/client source IP. Optional. 
  > If running this app behind Nginx for example, or using a corporate proxy, you will need to configure them to pass the real client IP to the app using a specific header, and set its name here. Traditionally, `X-Forwarded-For` is used for this purpose. Default: empty.
  > The source IP address seen by Strongswan must match the source IP address used for the web authentication. If you have both a corporate HTTP proxy for users and a reverse-proxy such as Nginx in front of this app, you will need to configure the corporate proxy to set a header containing the original client IP, and ensure that Nginx passes it to the app. Do not configure both the corporate and the reverse proxies to append to the same header, as the app will only read the its value.
- `ORIGINALPROTOHEADER`: the header to use to fetch the real protocol (http, https) used between the clients and the proxy. Default: `X-Forwarded-Proto`.
- `PORT`: the port to listen to. Default: `8080`
- `REMOTEAUTHCHECKPASSWORD`: Shared password between the app and the Strongswan/SSH scripts to protect the endpoint checking for valid user web sessions. Optional.
    > If the `/check/...` endpoints or this app are publicly available, it is a good idea to set a password to ensure that only your VPN or SSH servers are allowed to query the app for user sessions.
- `REMOTESESSIONVALIDITY`: How long to allow VPN/SSH (re)connections after completing the web authentication. During this interval the web authentication status is not reverified. Default: `30m`. Specify custom value as a number and a time unit, for example `1h30m`.
  > If you enable the web notifications feature, you can set this to a short duration. Doing so can help increase security since new connections will be verified against a valid web session on an online browser more often. However, if you have reports from users complaining that they have frequent VPN connection failures, you may want to increase this value, as some users on slow network connections may have more trouble replying in a timely fashion that their browser is online and holds a valid session.
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

### SSH
 - `ENABLESSH`: whether to enable additional web authentication through this app for SSH connections. Default: `false`.
 - `SSHREQUIREKEY`: whether to use the users SSH key to tie them to a valid web session. Default: `true`. If enabled, users have to register their public key in the app. 
   > When they SSH into a remote system configured to use this app, if their SSH key is not recognized, they will receive a one-time code and will be instructed to enter it into this app in order to automatically register their SSH public key.

   > NOTE: If this option is disabled, SSH keys will be ignored by the app. In that case, the only way to link a user web session to an SSH connection is that the SSH username matches the web identity (email address).

   > It is highly recommended that you use SSH keys authentication for your users and that you enable this option in the app. 
   
  This app is compatible with multiple SSH authentications (for example, when SSHD is configured with `AuthenticationMethods "publickey,keyboard-interactive"`).

### VPN
  - `ENABLEVPN`: whether to enable additional web authentication through this app for VPN connections. Default: `false`.
  - `VPNCHECKALLOWEDIPS`: Comma-separated list of IPs allowed to query the check endpoint. Optional. Default: empty, anyone can use the endpoint.
    > NOTE: For this to work as expected, the VPN server needs to connect **directly** to the check endpoint, without any corporate or forward proxy. `ORIGINALIPHEADER` is ignored for requests coming from your VPN server.
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

If they accept, when they attempt a remote connection without a valid web session, they will receive a notification letting them know that they need to sign in for the remote VPN or SSH connection to be authorized.

 Additionally, if their remote (VPN or SSH) session is expired (`REMOTESESSIONVALIDITY`) but they still have a valid web session (`WEBSESSIONVALIDITY`), their next attempt to connect to the VPN will try to transparently ask the browser used to sign in to prove that it still holds a valid session. If so, the VPN or SSH connection will be automatically allowed, without any user intervention or visible notification.

> NOTE: automatic remote sessions renewal is a best effort feature; the browser must be running, even without this app opened, and must reply with a "proof of session and IP" quickly enough. This is because Strongswan will be waiting in blocking mode for the app to reply whether the user is allowed. 
Network latency and distance between end users and the app could negatively impact their ability to use the feature.
By default, the app stops waiting for a browser "proof of session" after 600ms.

&nbsp;


- `ENABLENOTIFICATIONS`: whether to enable desktop notifications and session continuity. Default: `true`.
- `VAPIDPUBLICKEY` and `VAPIDPRIVATEKEY`: a key pair to authenticate and authorize browser desktop notifications. Mandatory if `ENABLENOTIFICATIONS` is set to `true`. 

   > If they are not set, a new key pair will be dynamically generated and suggested before the app startup fails. If you use the suggested key pair, ensure the suggested `VAPIDPRIVATEKEY` is kept secret and has not been shared or logged. Once set, the keys must not change otherwise all existing users subscriptions to notifications will be invalid.

   > NOTE: you can also generate your own set of keys using the following commands:
   ```
   # Generate private key
   openssl ecparam -name prime256v1 -genkey -noout -out vapid_private.pem
   # Output private key in a format suitable for VAPIDPRIVATEKEY:
   openssl ec -in vapid_private.pem -outform DER|tail -c +8|head -c 32|base64|tr -d '=' |tr '/+' '_-'
   # Output public key in a format suitable for VAPIDPUBLICKEY:
   openssl ec -in vapid_private.pem -pubout -outform DER|tail -c 65|base64|tr -d '=' |tr '/+' '_-' 

   ```
Currently Google Chrome, Firefox and Edge support notifications and automated remote session renewal without meeding to keep this app opened.
Safari requires the user to keep a tab open.
