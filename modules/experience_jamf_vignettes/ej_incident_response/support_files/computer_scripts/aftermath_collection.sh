#!/bin/zsh

aftermathRemnant="~/Desktop/Aftermath*"
aftermath="/Library/Application Support/JAMF/Receipts/Aftermath.pkg"

# Remove remnants of previous Aftermath scans
rm -rf ~/Desktop/Aftermath*
rm -rf /tmp/Aftermath*

touch /Library/.tje/analyze
rm -rf /Library/.tje/aftermath

dialog="/usr/local/bin/dialog"

if [[ ! -f ${dialog} ]]; then
    /usr/local/bin/jamf policy -event installSwiftDialog
fi

if [[ ! -f ${aftermath} ]]; then
    /usr/local/bin/jamf policy -event @installAftermath
    sleep 5
fi

# Run Aftermath collection and output to /tmp/
aftermath -o /tmp/

osascript -e 'quit application "Self Service"'

sleep 2

jamf recon

sleep 5

info_link="https://github.com/jamf/aftermath"
message="### What Happened?\n\n - Forensic threat analysis has been collected for further investigation\n\n	- Artifacts like the files involved, when they were created, accessed, or modified alongside a compelling storyline with browser info, database changes and file metadata are included\n\n - Jamf provides [SOAR playbooks](https://github.com/jamf/jamfprotect/tree/main/soar_playbooks/aftermath_collection) at our Jamf Protect Github prebuilt to upload this data to your cloud storage provider for further analysis\n\n - To review the collected information on this device, click and run the Aftermath Analysis policy in Self Service"
# button1_link="jamfselfservice://content?entity=policy&id=39&action=execute"


# button="Aftermath Analysis"
button="Open Self Service"

runDialog () {
    ${dialog} \
    --title "Aftermath Scan Complete" \
    --large \
    --ontop \
    --moveable \
    --icon 'SF=location.magnifyingglass,colour=green' \
    --message ${message} \
    --messagefont "size=18" \
    --infobuttontext "More Info" \
    --infobuttonaction ${info_link} \
   #--button1action ${button1_link} \
    --button1text ${button} \
}

# Run dialog
runDialog

open -a Self\ Service.app

exit