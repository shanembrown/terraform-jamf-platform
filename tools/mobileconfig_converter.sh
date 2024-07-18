#!/bin/bash

## Define variables
path="support_files/computer_config_profiles/"
prefix="sonoma_cis_lvl1-"
file=$1

## Unsign mobile config
openssl smime -inform DER -verify -in "${path}${file}.mobileconfig" -noverify -out "${path}${prefix}${file}_unformatted.mobileconfig"

## Convert to XML
plutil -convert xml1 "${path}${prefix}${file}_unformatted.mobileconfig"

## Format properly
XMLLINT_INDENT="	" xmllint --format - < "${path}${prefix}${file}_unformatted.mobileconfig" > "${path}${prefix}${file}.mobileconfig"

## Remove trailing newline character
truncate -s -1 "${path}${prefix}${file}.mobileconfig"

## Remove temporary file
rm "${path}${prefix}${file}_unformatted.mobileconfig"

exit 0