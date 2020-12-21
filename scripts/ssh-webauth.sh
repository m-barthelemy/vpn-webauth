#!/bin/sh

# IMPORTANT: Make sure this script belongs to root and is not writeable
# example: chmod 500 /path/to/this/script.sh and then chattr +i /path/to/this/script.sh

CHECK_ENDPOINT_URL=$1
CHECK_ENDPOINT_PASSWORD=$2
HOSTNAME_CMD=$(which hostname)
SSH_INFO="${SSH_AUTH_INFO_0//$'\n'/','}"
EXIT_CODE=2

# Only track sessions openings, and exclude identities switch (su/sudo)
if [ "$PAM_TYPE" = "open_session" ] && [ -n "${PAM_RHOST}" ]; then
    TMP_RESPONSE_FILE=$(mktemp)
    # Debug from local dev env
    REQUEST_BODY="{ \"Identity\": \"${PAM_USER}\", \"SourceIP\": \"${PAM_RHOST}\", \"CallerName\": \"$($HOSTNAME_CMD)\", \"SSHAuthInfo\": \"${SSH_INFO}\" }"
    STATUS_CODE=$(curl -sL -w "%{http_code}" -XPOST -u :${CHECK_ENDPOINT_PASSWORD} -d "${REQUEST_BODY}" -o ${TMP_RESPONSE_FILE} "${CHECK_ENDPOINT_URL}")
    read VALIDATION_URL OTC < ${TMP_RESPONSE_FILE}

    if [ "${STATUS_CODE}" == "406" ]; then
	echo ""
	echo "***************************************************************"
	echo "⚠️  You need to validate your SSH key."
	echo "One-time code: ${OTC}"
	echo "Open ${VALIDATION_URL}"
	echo "***************************************************************"
	echo ""
        EXIT_CODE=1
    elif [ "${STATUS_CODE}" == "401" ]; then
	echo ""
	echo "***************************************************************"
        echo "🔒 Further authentication is required."
        echo "Open ${VALIDATION_URL}"
        echo "***************************************************************"
        echo ""
        EXIT_CODE=1
    elif [ "${STATUS_CODE}" == "200" ]; then
	EXIT_CODE=0
    fi

    rm -f ${TMP_RESPONSE_FILE}
    exit ${EXIT_CODE}
fi


exit 0
