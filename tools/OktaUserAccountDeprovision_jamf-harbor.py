#!/usr/bin/env python3

import asyncio
import os
from datetime import datetime, timezone
import time
from okta.client import Client as OktaClient

# An asynchronous Python script that interacts with the Okta API to manage user accounts based on their activation dates.

# Number of days after which an account is considered for deactivation or deletion if not used.
daysuntilexpire = 14

# Define configuration for the environment (Jamf Harbor tenant)
config = {
    'orgUrl': 'https://jamf-harbor.okta.com',
    # Okta API Token: TJE Account Deactivate, Token ID: 00TtdxonheaiY4lE11d6
    'token': '00E1YW0wjkuxWZ0aK2uCPmm6i8y6MZqOMrXSL_ye78'
}

# Specifies the search filter and sorting options for querying user accounts.
# Test mode searches for the user named "Barry Sanders", while production searches for accounts starting with "TJE".
search_params = {
    "production": {'search': 'profile.firstName eq "TJE"',
                   'sortBy': 'profile.lastName',
                   'sortOrder': 'asc'},
    "test": {'search': 'profile.firstName eq "Barry" and profile.lastName eq "Sanders"',
             'sortBy': 'profile.lastName',
             'sortOrder': 'asc'}
}

async def main(mode="production"):
    # Use the same configuration for both test and production environments
    query_params = search_params[mode]

    async with OktaClient(config) as client:
        # Perform all queries within same session
        users, okta_resp, err = await client.list_users(query_params=query_params)
        page_count = 0
        user_count = 0
        while True:

            if err:
                # Handle error
                print(f"Error: {err}")
                return

            if users is None:
                # Handle no users found
                print("No users found")
                return

            for user in users:
                print(f"Initial Status of {user.profile.first_name} {user.profile.last_name}: {user.status}")

                if user.status == 'DEPROVISIONED':
                    print(f"{user.profile.first_name} {user.profile.last_name} is already deactivated, skipping..")
                    continue

                user_count += 1

                print(f"Account ID: {user.profile.first_name} {user.profile.last_name}")
                date_object = datetime.strptime(user.activated, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
                print(f"Activated Date: {date_object}")
                print(f"Current Date: {datetime.now(timezone.utc)}")
                difference = datetime.now(timezone.utc) - date_object
                print(f"Days since activation: {difference.days}")
                
                # Proceed with deactivation in test mode or if the activation date exceeds the threshold
                if mode == "test" or difference.days >= daysuntilexpire:
                    print(f"Account active for more than {daysuntilexpire} days or in test mode, deactivating user {user.profile.first_name} {user.profile.last_name}")
                    
                    # Deactivate or delete the user
                    delete_resp, err = await client.deactivate_or_delete_user(user.id)
                    if err:
                        print(f"Error deactivating/deleting user: {err}")
                    else:
                        print("Deactivation Response:", delete_resp, "\n")

                        # Fetch the updated user information to verify deactivation status
                        try:
                            updated_user_tuple = await client.get_user(user.id)

                            # Extract the user object from the returned tuple
                            if isinstance(updated_user_tuple, tuple):
                                updated_user = updated_user_tuple[0]
                            else:
                                updated_user = updated_user_tuple

                            # Print the status after the deactivation attempt
                            if hasattr(updated_user, 'status'):
                                print(f"Updated Status of {updated_user.profile.first_name} {updated_user.profile.last_name}: {updated_user.status}\n")
                            else:
                                print("Unable to access user status directly.\n")
                        except Exception as e:
                            print(f"Error fetching updated user: {e}")

            if okta_resp.has_next():
                page_count += 1
                users, err = await okta_resp.next()
            else:
                break

if __name__ == "__main__":
    print("deactivate loop start")
    # Allow the user to easily toggle between test and production mode.
    mode = input("Enter mode ('test' or 'production'): ").strip().lower()
    asyncio.run(main(mode=mode))
