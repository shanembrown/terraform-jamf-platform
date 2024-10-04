#!/bin/zsh
# ward
# 2024
# Jamf Pro API Endpoint & Object Validator

#########################################################################################
## This script authenticates with a Jamf Pro instance using either stored credentials  ##
## or user input. It allows the user to select various API endpoints, such as Computer ##
## Extension Attributes, Policies, Scripts, and more, to check for the existence of    ##
## specific objects using an Object ID. The script outputs the raw API response for    ##
## debugging purposes and invalidates the Bearer token at the end for security.        ##
#########################################################################################

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Configurable Options
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Toggle between stored credentials (true) and user input (false)
use_stored_creds=true

# Set the variables for username, password, and Jamf Pro URL
stored_username="username"
stored_password="yeahright"
stored_url="https://instance.jamfcloud.com"

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Available Jamf Pro API Endpoints
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

api_endpoints=("Computer Extension Attributes (/api/v1/computer-extension-attributes)"
               "Mobile Device Extension Attributes (/JSSResource/mobiledeviceextensionattributes/id/{id})"
               "Computer Policies (/JSSResource/policies/id/{id})"
               "Computer Groups (/JSSResource/computergroups/id/{id})"
               "Scripts (/JSSResource/scripts/id/{id})"
               "Computer Configuration Profiles (/JSSResource/osxconfigurationprofiles/id/{id})"
               "Categories (/JSSResource/categories/id/{id})"
               "Packages (/JSSResource/packages/id/{id})")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# User Input: Select API Endpoint
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

echo "\nPlease choose the API endpoint you want to check:\n"
select api_choice in "${api_endpoints[@]}"; do
  if [[ -n "$api_choice" ]]; then
    echo "\nAPI choice selected: $REPLY\n"
    echo "Selected API endpoint: $api_choice\n"  # Newline added for clarity
    break
  else
    echo "Invalid choice. Please select a valid number."
  fi
done

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Prompt for Object ID Input
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

echo -n "Enter the Object ID you want to check (e.g., 37): "
read object_id
echo "\nObject ID entered: $object_id\n"  # Newline added for clarity

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Credential Input (Prompt if Stored Credentials Not Used)
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

if [ "$use_stored_creds" = false ]; then
    echo -n "Enter Jamf Pro Username: "
    read username
    echo -n "Enter Jamf Pro Password: "
    read -s password
    echo
    echo -n "Enter Jamf Pro URL (e.g., https://example.jamfcloud.com): "
    read url
else
    username="$stored_username"
    password="$stored_password"
    url="$stored_url"
fi

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Obtain Bearer Token (for v1 endpoints)
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
if [[ "$REPLY" -eq 1 ]]; then
  authresponse=$(curl -s -u "$username:$password" "$url/api/v1/auth/token" -X POST)
  bearerToken=$(echo "$authresponse" | plutil -extract token raw -)

  if [ -z "$bearerToken" ]; then
    echo "Failed to retrieve Bearer token. Check your credentials and try again."
    exit 1
  fi
  echo "Bearer token retrieved successfully."
fi

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# API Endpoint Mapping Based on User Selection
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# API Endpoint Mapping Based on User Selection
case $REPLY in
  1)
    endpoint="api/v1/computer-extension-attributes/$object_id"
    ;;
  2)
    endpoint="JSSResource/mobiledeviceextensionattributes/id/$object_id"
    ;;
  3)
    endpoint="JSSResource/policies/id/$object_id"
    ;;
  4)
    endpoint="JSSResource/computergroups/id/$object_id"
    ;;
  5)
    endpoint="JSSResource/scripts/id/$object_id"
    ;;
  6)
    endpoint="JSSResource/osxconfigurationprofiles/id/$object_id"
    ;;
  7)
    endpoint="JSSResource/categories/id/$object_id"
    ;;
  8)
    endpoint="JSSResource/packages/id/$object_id"
    ;;
  *)
    echo "Invalid choice. Exiting."
    exit 1
    ;;
esac

# Debug: Print the selected endpoint and final API URL after it's been defined
echo "\nAPI URL: $url/$endpoint\n"

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Use Bearer Token (for v1) or Basic Auth (for classic endpoints)
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

if [[ "$REPLY" -eq 1 ]]; then
  # Use Bearer Token for v1 endpoint
  response=$(curl -s --request GET \
    --url "$url/$endpoint" \
    --header "authorization: Bearer $bearerToken" \
    --header 'accept: application/json')
else
  # Use Basic Auth for classic API endpoints
  response=$(curl -s --request GET \
    --url "$url/$endpoint" \
    --user "$username:$password" \
    --header 'accept: application/json')
fi

# Print the raw response for debugging purposes
echo "Raw response from API:\n$response\n"


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Invalidate Bearer Token (if applicable)
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

if [[ "$REPLY" -eq 1 ]]; then
  curl -s --request POST \
    --url "$url/api/v1/auth/invalidate-token" \
    --header "authorization: Bearer $bearerToken" \
    --header 'accept: application/json'

  echo "Bearer token invalidated."
fi