#!/usr/bin/env python3
# ward 2024

import json
import base64
import requests
import sys

"""
This script is designed to interact with the Jamf Security Cloud (JSC) API to manage the risk level of devices. It authenticates, using pagination retrieves a list of all devices, and allows for checking and updating the risk level of a specific device.

Key Features:
	•	Authenticates using an application_id and application_secret to obtain an access token
	•	Lists all device IDs present in JSC and checks if a specific device ID exists in the list (if provided as an argument at runtime)
	•	If the device is found, the script prompts the user to set a new risk level (e.g., HIGH, MEDIUM, LOW, SECURE)
	•	Sends a request to update the device’s risk level and confirms the successful update
    •	If no device ID argument is passed, choose the corespeonding number of the device ID you wish to change risk level

"""



# Variables for JSC API
private_access_url = 'https://api.wandera.com'
application_id = ''
application_secret = ''
content_type = 'application/json'

# Initialize a persistent session
persistent = requests.Session()

def create_radar_token(application_id, application_secret):
    """Authenticate and retrieve an access token for JSC."""
    print('Authenticating for Private Access Token...')
    private_access_auth = f'{application_id}:{application_secret}'
    private_access_token_url = f'{private_access_url}/v1/login'
    private_access_auth_base64 = base64.b64encode(private_access_auth.encode()).decode()
    auth_headers = {
        "Authorization": f'Basic {private_access_auth_base64}',
        "Content-Type": content_type,
        "Accept": content_type
    }
    private_access_token_request = persistent.post(private_access_token_url, headers=auth_headers)
    if private_access_token_request.status_code != 200:
        print(f'Error: Unable to authenticate to Private Access (status code: {private_access_token_request.status_code})')
        return None
    return private_access_token_request.json()['token']

def list_all_devices(private_api_token, page_size=100):
    """Retrieve and list all devices from JSC, handling pagination as needed."""
    print('Retrieving all devices from JSC...')
    private_access_device_url = f'{private_access_url}/risk/v1/devices'
    device_headers = {
        "Authorization": f'Bearer {private_api_token}',
        "Content-Type": content_type,
        "Accept": content_type
    }
    all_devices = []
    current_page = 0

    while True:
        response = persistent.get(f"{private_access_device_url}?page={current_page}&pageSize={page_size}", headers=device_headers)
        if response.status_code != 200:
            print(f'Error: Unable to retrieve devices (status code: {response.status_code})')
            break
        
        data = response.json()
        devices = data.get('records', [])
        pagination_info = data.get('pagination', {})

        if not devices:
            break
        
        all_devices.extend(devices)
        current_page += 1  # Move to the next page

        # Check if we have more pages to process
        if current_page >= pagination_info.get('totalPages', 0):
            break

    return all_devices

def update_private_access_risk(private_api_token, private_access_id, risk_level):
    """Update the risk level for a specific device."""
    print(f'Attempting to set device {private_access_id} to risk level {risk_level}')
    source = 'WANDERA' if risk_level == 'SECURE' else 'MANUAL'
    private_access_device_url = f'{private_access_url}/risk/v1/override'
    device_headers = {
        "Authorization": f'Bearer {private_api_token}',
        "Content-Type": content_type,
        "Accept": content_type
    }
    json_body = {
        "risk": risk_level,
        "source": source,
        "deviceIds": [private_access_id]
    }
    
    # Debug statements
    print(f"Request URL: {private_access_device_url}")
    print(f"Request Headers: {device_headers}")
    print(f"Request Body: {json.dumps(json_body, indent=4)}")
    
    device_override_request = persistent.put(private_access_device_url, headers=device_headers, json=json_body)
    
    # Debug statements for response
    print(f"Response Status Code: {device_override_request.status_code}")
    print(f"Response Content: {device_override_request.text}")
    
    if device_override_request.status_code != 204:
        print(f'Error: Failed to set risk level (status code: {device_override_request.status_code})')
        return False
    print('Device risk level updated successfully.')
    return True

if __name__ == '__main__':
    private_access_token = create_radar_token(application_id, application_secret)
    if not private_access_token:
        exit('Exiting due to authentication failure.')

    # Check if a Device ID was passed as an argument
    if len(sys.argv) > 1:
        device_id = sys.argv[1]
        devices = list_all_devices(private_access_token)
        if not devices:
            print('No devices found or unable to retrieve devices.')
            exit()

        # Check if the passed Device ID exists in the list
        matching_device = next((device for device in devices if device['deviceId'] == device_id), None)
        if matching_device:
            print(f"Device ID {device_id} found. Name: {matching_device.get('name', 'N/A')}, UDID: {matching_device.get('externalId', 'N/A')}")
            # Prompt for risk level
            risk_level = input('Enter the desired risk level (HIGH, MEDIUM, LOW, SECURE): ').upper()
            if risk_level not in ['HIGH', 'MEDIUM', 'LOW', 'SECURE']:
                print('Invalid risk level entered. Exiting...')
                exit()
            # Set risk level for the specified device
            update_result = update_private_access_risk(private_access_token, device_id, risk_level)
            if not update_result:
                print('Risk level update failed.')
        else:
            print(f'Device ID {device_id} not found in the list of devices.')
    else:
        # Existing logic to list all devices and allow user to choose one
        print('No Device ID provided. Listing all devices...')
        devices = list_all_devices(private_access_token)
        if not devices:
            print('No devices found or unable to retrieve devices.')
            exit()

        print('Devices in JSC:')
        for i, device in enumerate(devices, 1):
            print(f"{i}. Device ID: {device['deviceId']}, Name: {device.get('name', 'N/A')}, UDID: {device.get('externalId', 'N/A')}")

        # Prompt user to select a device
        try:
            selection = int(input('Select a device number to set its risk level: '))
            if selection < 1 or selection > len(devices):
                print('Invalid selection. Exiting...')
                exit()

            selected_device = devices[selection - 1]
            print(f"Selected Device: ID: {selected_device['deviceId']}, Name: {selected_device.get('name', 'N/A')}")
            
            # Prompt for risk level
            risk_level = input('Enter the desired risk level (HIGH, MEDIUM, LOW, SECURE): ').upper()
            if risk_level not in ['HIGH', 'MEDIUM', 'LOW', 'SECURE']:
                print('Invalid risk level entered. Exiting...')
                exit()

            # Set risk level for the selected device
            update_result = update_private_access_risk(private_access_token, selected_device['deviceId'], risk_level)
            if not update_result:
                print('Risk level update failed.')
        except ValueError:
            print('Invalid input. Exiting...')