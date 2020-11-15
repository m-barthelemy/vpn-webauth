## What is it?

This is quick (and dirty) web application allowing to add a second round of authentication to a Strongswan VPN.
It doesn't replace, and in fact requires, a normal authentication process using passwords or certificates.

Traditionally, simple IPSec VPN authentication methods involve deploying certificates to the client, or using a login + password.

While IKEv2 permits, in theory, the use of a second round of authentication, default VPN clients installed on OS such as MacOs and Windows have very little compatibility with it.

This project uses the `ext-auth` Strongswan plugin to provide an additional layer of authentication via a user web login and optional 2FA token.
This can help to protect your organization aganist VPN credentials or certificates being leaked or stolen.
This tool compatible with all VPN clients and operating systems.

It can also help achieve compliance with some security standards requiring MFA to be implemented for VPNs giving access to sensitive environments.


## How does it work?

 - The user goes to the webapp _before_ connecting to the VPN
 - They authenticate using OAuth2 (for now, only Google is supported)
 - Optionally, they are required to complete additional authentication, using an OTP token (independent from any Google/OAuth2 2FA), TouchID/FaceID or a physical security key.
 - A "session" is created with the user email, their source IP address and the time when they completed the web authentication
 - They now connect to the VPN
 - After the normal VPN authentication, the `ext-auth` plugin calls this webapp to check if the user has successfully completed a web authentication recently and from the same source IP address. If not, the connection is rejected.

## What does it look like?
<img width="537" alt="Screen Shot 2020-11-11 at 9 02 27 AM" src="https://user-images.githubusercontent.com/2519084/98752335-f7241580-23fc-11eb-985e-91c26c7249aa.png">

First web auth: 2FA registration

<img width="622" alt="Screen Shot 2020-11-12 at 6 54 06 AM" src="https://user-images.githubusercontent.com/2519084/98873794-f1d5d200-24b3-11eb-9916-370f8caf4472.png">

Subsequent web auths:

<img width="648" alt="Screen Shot 2020-11-11 at 9 05 09 AM" src="https://user-images.githubusercontent.com/2519084/98752367-030fd780-23fd-11eb-8d69-1725d7d5b1d8.png">

<img width="571" alt="Screen Shot 2020-11-11 at 9 06 06 AM" src="https://user-images.githubusercontent.com/2519084/98752428-2470c380-23fd-11eb-97cc-f9a06a5a5f15.png">



## Limitations
- The web auth has to happen **before** connecting to the VPN, since the VPN will verify the existence of a web "session" when the user connects.
- The user identity reported by Strongswan **must** match the email reported by the web authentication. However, if the Strongswan identity is the first part of the email address (without @domain.tld), you can modify the `webauth-check.sh` script to add the domain.
- If a user successfully authenticates using this app, someone else on the same local network would be able to reuse the web session, provided they have the user's Strongswan credentials. This by design, since the app matches a web auth with a Strongswan connection only using the Strongswan identity and the source IP address.
- Only Google is currently supported for the web authentication.
- Since the web authentication has to happen before connecting to the VPN, is probably needs to be hosted in a less protected part of your environment.
- There is currently no way to reset a user account if they have lost their 2FA device. You need to manually delete the User record in the database.
- Strongswan blocks during the call to the `ext-auth` plugin. Since checking the user web authentication against this app is fast, this shouldn't be an issue, unless you have a high number of users connecting almost simultaneously.
- There is currently no limit on how many attempts a user can make at entering a 2FA code.

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
 and then set `VPNWA_ORIGINALIPHEADER` to `X-Forwarded-For`.
 
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
		script = /path/to/webauth-check.sh https://this_webapp_host/vpn/check
	}
	...
}
```


 ## Configuration options
All the configuration parameters have to passed as environment variables.
  - `VPNWA_HOST`: the IP address to listen on. Default: `127.0.0.1`
  - `VPNWA_PORT`: the port to listen to. Default: `8080`
  - `VPNWA_DBTYPE`: the database engine where the sessions will be stored. Default: `sqlite`. Can be `sqlite`, `postgres`, `mysql`.
  - `VPNWA_DBDSN`: the database connection string. Default: `tmp/vpnwa.db`. Check https://gorm.io/docs/connecting_to_the_database.html for examples.
    > By default a Sqlite database is created. You probably want to at least change its path. Sqlite is only suitable for testing purposes or for a small number of concurrent users, and will only work with with a single instance of the app. It is recommended to use MySQL or Postgres instead.

    > NOTE: the app will automatically create the tables and thus needs to have the privileges to do so.
  - `VPNWA_REDIRECTDOMAIN`: the base URL that oAuth2/Google will redirect to after signing in. Default: http://`VPNWA_HOST`:`VPNWA_PORT`
  - `VPNWA_GOOGLECLIENTID`: Google Client ID. **Mandatory**.
  - `VPNWA_GOOGLECLIENTSECRET`: Google Client Secret. **Mandatory**.
  - `VPNWA_ENCRYPTIONKEY`: Key used to encrypt the users OTP secrets in the database. Must be 32 characters. **Mandatory** if `VPNWA_ENFORCEMFA` is set to `true`.
  - `VPNWA_SESSIONVALIDITY`: How long to allow (re)connections to the VPN after completing the web authentication, in seconds. Default: `3600` (1h).
    > This option aims at reducing the burden put on the users and avoids them having to go through the web auth again if they get disconnected within the configured delay, due for example to poor network connectivity or inactivity. 

    > NOTE: subsequent VPN connections must come from the same IP address used during the web authentication.
  - `VPNWA_ENFORCEMFA`: Whether to enforce additional 2FA after OAuth2 login. Default: `true`.
  - `VPNWA_MFAVALIDITY`: How long to allow re-authenticating only with Google, without having to use the additional auth again. Default: `VPNWA_SESSIONVALIDITY` (require 2FA during every login). Must be greater than, or equal to, `VPNWA_SESSIONVALIDITY`.
  - `VPNWA_MFAISSUER`: Name that appears on the users authenticator app or TouchID/Physical key prompt. Default: `VPN`.
  - `VPNWA_MFAOTP`: Whether to enable OTP token authrntication after OAuth2 login. Default: `true`. 
    > NOTE: This is not related to Google 2FA. By default Google will only require 2FA if your organization enforces it, and it will remember a device/browser for a very long time. This option adds a mandatory 2FA verifications upon each login, independently from your Google settings. Your users will have to register a new 2FA entry in their favorite authenticator app when using this web authentication for the first time.
  - `VPNWA_MFATOUCHID`: Whether to enable Apple TouchID/FaceID strong authentication after OAuth2 login, if a compatible device is detected. Default: `true`.
    > With compatible Apple devices and operating systems, this is certainly the fastest, most convenient and most secure additional authentication. 
    > If they choose this option, users will be prompted to identify using their fingerprint or face. This feature complies with the definiton of "Something you are" of the authentication factors.
    > NOTE: This feature is available in MacOS >= 11.x and iOS >= 14.x. The option will be shown to the user if a compatible OS is detected through the User Agent value. This does not guarantee that the user will have the required hardware (laptop or desktop device without TouchID, or TouchID/FaceID not setup by the user).
  - `VPNWA_MFAWEBAUTHN`: Whether to enable strong authentication using security devices such as Fido keys after OAuth2 login. Default: `true`.

  - `VPNWA_LOGOURL`: Add your organization logo on top of the webapp pages. Optional.
  - `VPNWA_SIGNINGKEY`: Key used to sign the user session tokens during the web authentication. By default, a new signing key will be generated each time this application starts.
    > These tokens have a very short duration since they are only required during the sign in process, so regenerating a new key every time the application starts shouldn't be too much of a problem even if that means that every existing session will be invalidated. 
    > If you plan to run multiple instances of this app behind a load-balancer, you should probably consider defining your own key, identical on all nodes, or use some form of session persistence.
  - `VPNWA_ORIGINALIPHEADER`: the header to use to fetch the real user/client source IP. Optional. If running this app behind Nginx for example, you will need to configure Nginx to pass the real client IP to the app using a specific header, and set its name here. Traditionally, `X-Forwarded-for` is used for this purpose.

  - `VPNWA_SSLMODE`: whether and how SSL is enabled. Default: `off`. Can be `auto`, `custom`, `proxy`, `off`.
    > `off` doesn't enforce SSL at all at the application level. In that case you can still place the app behind an HTTPS proxy.

    > `auto` automatically generates a private key and a Let'sEncrypt SSL certificate for the domain specified in `VPNWA_REDIRECTDOMAIN`. The generated key and certificates are stored into `VPNWA_SSLKEYPATH` and `VPNWA_SSLCERTPATH` and reused during future application restarts.

    > NOTE: `auto` will force the application to also listen on port 80 in order to generate the LetsEncrypt certificate. This port is privileged, meaning that you will need to start the application as root using `sudo`, or executing `chmod u+s vpn-webauth` to grant the binary admin permissions. Any user request to port 80 will redirect to the `VPNWA_PORT` HTTPS port.

    > `custom` will let you specify a custom certificate and key using `VPNWA_SSLCUSTOMCERTPATH` and `VPNWA_SSLCUSTOMKEYPATH`.

    > `proxy` delegates the responsibility of providing SSL termination to an external component or proxy. However, unlike `off`, it sets the `Secure` flag for the cookies generated by the application and add an HSTS HTTP header.
  - `VPNWA_SSLCUSTOMCERTPATH`: path to the SSL certificate. Optional. Default: `/ssl/key.pem`. If needed, this file can contain any additional certificate required to build the full chain, _after_ the leaf certificate.
  - `VPNWA_SSLCUSTOMKEYPATH`: path to the SSL certificate private key. Optional. Default: `/ssl/cert.pem`.
