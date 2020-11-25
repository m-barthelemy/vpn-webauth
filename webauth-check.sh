#!/bin/sh

curl -u :$2 -f -d "{ \"Identity\": \"${IKE_REMOTE_ID}\", \"SourceIP\": \"${IKE_REMOTE_HOST}\"  }" $1
