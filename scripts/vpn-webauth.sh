#!/bin/sh

# Can be set to customize the title of browser notifications.
# Should ideally be the name of the VPN connection as is appears on users devices (Example: "My Company VPN")
VPN_NAME=""
curl -u :$2 -f -d "{ \"Identity\": \"${IKE_REMOTE_ID}\", \"SourceIP\": \"${IKE_REMOTE_HOST}\", \"CallerName\": \"${VPN_NAME}\" }" $1
