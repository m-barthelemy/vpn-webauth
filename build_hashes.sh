#!/bin/bash

CSS="sha384-$(cat templates/assets/css.css | openssl dgst -sha384 -binary | openssl base64 -A)"
FONT_AWESOME="sha384-$(cat templates/assets/font-awesome.min-4.7.0.css | openssl dgst -sha384 -binary | openssl base64 -A)"
JQUERY="sha384-$(cat templates/assets/jquery-3.5.1.min.js | openssl dgst -sha384 -binary | openssl base64 -A)"
MATERIAL="sha384-$(cat templates/assets/material-icons.css | openssl dgst -sha384 -binary | openssl base64 -A)"
MATERIALIZE_JS="sha384-$(cat templates/assets/materialize.min-0.97.5.js | openssl dgst -sha384 -binary | openssl base64 -A)"
MATERIALIZE_CSS="sha384-$(cat templates/assets/materialize-0.97.5.min.css | openssl dgst -sha384 -binary | openssl base64 -A)"
SCRIPT="sha384-$(cat templates/assets/script.js | openssl dgst -sha384 -binary | openssl base64 -A)"

sed -i "s@.*material-icons.css.*@<link href=\"/assets/material-icons.css\" rel=\"stylesheet\" integrity=\"$MATERIAL\">@g" templates/header.html
sed -i "s@.*materialize-0.97.5.min.css.*@<link rel=\"stylesheet\" type=\"text/css\" href=\"/assets/materialize-0.97.5.min.css\" integrity=\"$MATERIALIZE_CSS\">@g" templates/header.html
sed -i "s@.*font-awesome.min-4.7.0.css.*@<link rel=\"stylesheet\" type=\"text/css\" href=\"/assets/font-awesome.min-4.7.0.css\" integrity=\"$FONT_AWESOME\">@g" templates/header.html
sed -i "s@.*css.css.*@<link rel=\"stylesheet\" type=\"text/css\" href=\"/assets/css.css\" integrity=\"$CSS\">@g" templates/header.html
sed -i "s@.*jquery-3.5.1.min.js.*@<script type=\"text/javascript\" src=\"/assets/jquery-3.5.1.min.js\" integrity=\"$JQUERY\"></script>@g" templates/header.html
sed -i "s@.*materialize.min-0.97.5.js.*@<script type=\"text/javascript\" src=\"/assets/materialize.min-0.97.5.js\" integrity=\"$MATERIALIZE_JS\"></script>@g" templates/header.html
sed -i "s@.*script.js.*@<script type=\"text/javascript\" src=\"/assets/script.js\" integrity=\"$SCRIPT\"></script>@g" templates/header.html