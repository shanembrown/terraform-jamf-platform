#!/bin/bash

UUID="$(ioreg -d2 -c IOPlatformExpertDevice | awk -F\" '/IOPlatformUUID/{print $(NF-1)}')"
CHALLENGE="114462661045031677246004832591719061792"
URL="https://experience.jamfcloud.com"

cat << EOF > ~/Desktop/mdm_enroll.mobileconfig
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>PayloadUUID</key>
        <string>${UUID}</string>
        <key>PayloadOrganization</key>
        <string>JAMF Software</string>
        <key>PayloadVersion</key>
        <integer>1</integer>
        <key>PayloadIdentifier</key>
        <string>${UUID}</string>
        <key>PayloadDescription</key>
        <string>MDM Profile for mobile device management</string>
        <key>PayloadType</key>
        <string>Profile Service</string>
        <key>PayloadDisplayName</key>
        <string>MDM Profile</string>
        <key>PayloadContent</key>
        <dict>
            <key>Challenge</key>
            <string>${CHALLENGE}</string>
            <key>URL</key>
            <string>${URL}/enroll/profile</string>
            <key>DeviceAttributes</key>
            <array>
                <string>UDID</string>
                <string>PRODUCT</string>
                <string>SERIAL</string>
                <string>VERSION</string>
                <string>DEVICE_NAME</string>
                <string>COMPROMISED</string>
            </array>
        </dict>
    </dict>
</plist>
EOF

# cirrus ssh vm experiencejamf 'bash -c "echo \"<?xml version=\\\"1.0\\\" encoding=\\\"UTF-8\\\"?><plist version=\\\"1.0\\\"><dict><key>URL</key><string>https://experience.jamfcloud.com/enroll?invitation=114462661045031677246004832591719061792</string></dict></plist>\" > /Users/admin/Desktop/mdm_enroll.webloc"'