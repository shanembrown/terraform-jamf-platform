#!/bin/zsh

### Variables
okta_verify_app_path="/Applications/Okta Verify.app"  
okta_verify_download_url="https://sso.tryjamf.com/api/v1/artifacts/OKTA_VERIFY_MACOS/download?releaseChannel=%OKTA_RELEASE_CHANNEL%" 


# Function to check for and install Okta Verify if not present
check_and_install_okta_verify() {
    while [ ! -d "$okta_verify_app_path" ]; do
        echo "Okta Verify not found. Downloading and installing Okta Verify..."
        curl -L -o "/tmp/OktaVerify.pkg" "$okta_verify_download_url"
        installer -pkg "/tmp/OktaVerify.pkg" -target /
        echo "Waiting for Okta Verify to be installed..."
        echo "Okta Verify Installation complete."
        sleep 2
    done
}


# Check and install Okta Verify if not present
check_and_install_okta_verify


# Open Okta Verify with the URL scheme
echo "Opening Okta Verify..."
# open "com-okta-authenticator:/actions/enroll?display_url=sso.tryjamf.com&login_hint=$TJE_USERNAME"
open "com-okta-authenticator:/actions/enroll?display_url=sso.tryjamf.com"
echo "Okta Verify opened with enrollment URL."
