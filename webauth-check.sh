#!/bin/sh

curl -f -d "{ \"Identity\": \"${IKE_REMOTE_ID}\", \"SourceIP\": \"${IKE_REMOTE_HOST}\"  }" $1
