#!/bin/bash

CSS="$(cat templates/assets/css.css | openssl dgst -sha384 -binary | openssl base64 -A)"
FONT_AWESOME="$(cat templates/assets/font-awesome.min-4.7.0.css | openssl dgst -sha384 -binary | openssl base64 -A)"
JQUERY="$(cat templates/assets/jquery-3.5.1.min.js | openssl dgst -sha384 -binary | openssl base64 -A)"
MATERIAL="$(cat templates/assets/material-icons.css | openssl dgst -sha384 -binary | openssl base64 -A)"
MATERIALIZE_JS="$(cat templates/assets/materialize.min-0.97.5.js | openssl dgst -sha384 -binary | openssl base64 -A)"
MATERIALIZE_CSS="$(cat templates/assets/materialize-0.97.5.min.css | openssl dgst -sha384 -binary | openssl base64 -A)"
SCRIPT="$(cat templates/assets/script.js | openssl dgst -sha384 -binary | openssl base64 -A)"

sed -i "s@<link href=\"/assets/material-icons.css\" rel=\"stylesheet\" integrity=\"[^\"]+\">@<link href=\"/assets/material-icons.css\" rel=\"stylesheet\" integrity=\"$MATERIAL\">@g" templates/header.html
sed -i "s@<link rel=\"stylesheet\" type=\"text/css\" href=\"/assets/materialize-0.97.5.min.css\" integrity=\"[^\"]+\">@<link rel=\"stylesheet\" type=\"text/css\" href=\"/assets/materialize-0.97.5.min.css\" integrity=\"$MATERIALIZE_CSS\">@g" templates/header.html
sed -i "s@<link rel=\"stylesheet\" type=\"text/css\" href=\"/assets/font-awesome.min-4.7.0.css\" integrity=\"[^\"]+\">@<link rel=\"stylesheet\" type=\"text/css\" href=\"/assets/font-awesome.min-4.7.0.css\" integrity=\"$FONT_AWESOME\">@g" templates/header.html
sed -i "s@<link rel=\"stylesheet\" type=\"text/css\" href=\"/assets/css.css\" integrity=\"[^\"]+\">@<link rel=\"stylesheet\" type=\"text/css\" href=\"/assets/css.css\" integrity=\"$CSS\">@g" templates/header.html
sed -i "s@<script type=\"text/javascript\" src=\"/assets/jquery-3.5.1.min.js\" integrity=\"[^\"]+\"></script>@<script type=\"text/javascript\" src=\"/assets/jquery-3.5.1.min.js\" integrity=\"$JQUERY\"></script>@g" templates/header.html
sed -i "s@<script type=\"text/javascript\" src=\"/assets/materialize.min-0.97.5.js\" integrity=\"[^\"]+\"></script>@<script type=\"text/javascript\" src=\"/assets/materialize.min-0.97.5.js\" integrity=\"$MATERIALIZE_JS\"></script>@g" templates/header.html
sed -i "s@<script type=\"text/javascript\" src=\"/assets/script.js\" integrity=\"[^\"]+\"></script>@<script type=\"text/javascript\" src=\"/assets/script.js\" integrity=\"$SCRIPT\"></script>@g" templates/header.html

~/go/bin/pkger