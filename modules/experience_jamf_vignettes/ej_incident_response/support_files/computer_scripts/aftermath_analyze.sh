#!/bin/zsh

computerName=$(/usr/sbin/scutil --get ComputerName)
serial=$(/usr/sbin/system_profiler SPHardwareDataType | /usr/bin/awk '/Serial\ Number\ \(system\)/ {print $NF}')
osVersion=$(/usr/bin/sw_vers -productVersion)
jpVersion=$(/usr/local/bin/protectctl version | /usr/bin/awk '/Version:/ {print $2}')

dialog="/usr/local/bin/dialog"

#Analyze the Aftermath zip file and output to /tmp/
/usr/local/bin/aftermath --analyze /tmp/Aftermath*.zip -o /tmp/

#Unzip the Aftermath file on and copy to the User's Desktop
ditto -xk /tmp/Aftermath_Analysis*.zip ~/Desktop/

sleep 2

#Remove Aftermath files
rm -rf /Library/.tje/aftermath
rm -rf /Library/.tje/analyze

sleep 2

osascript -e 'quit application "Self Service"'

#Open the Aftermath folder
open ~/Desktop/Aftermath*

#Display an alert saying the scan is done and explaining what's in the file
info_link2="https://github.com/jamf/aftermath"
message="### What Happened?\n\n - Forensic threat analysis has been collected for further investigation\n\n - Please look through the contents of the folder\n\n		~/Desktop/Aftermath_Analysis_$serial \n\n The *storyline.csv* file will present the events that happened on this Mac in chronological order to aid in the process of investigation"
button2="OK"

runDialog () {
	${dialog} \
	--title "Aftermath Analysis Complete" \
	--large \
	--ontop \
	--moveable \
	--icon 'SF=exclamationmark.shield.fill,colour=green' \
	--message ${message} \
	--messagefont "size=18" \
	--infobuttontext "More Info" \
	--infobuttonaction ${info_link2} \
	--button1text ${button2} \
}

runDialog

jamf recon

open -g -a Self\ Service.app

exit 0



# 
# 
# 
# #!/bin/zsh
# 
# dialog="/usr/local/bin/dialog"
# 
# #Analyze the Aftermath zip file and output to /tmp/
# /usr/local/bin/aftermath --analyze /tmp/Aftermath*.zip -o /tmp/
# 
# #Unzip the Aftermath file on and copy to the User's Desktop
# ditto -xk /tmp/Aftermath*.zip ~/Desktop/
# 
# sleep 2
# 
# #Remove Aftermath files
# rm -rf /tmp/Aftermath*.zip
# rm -rf /tmp/Aftermath*
# rm -rf /Library/.tje/aftermath
# rm -rf /Library/.tje/analyze
# 
# sleep 2
# 
# #Open the Aftermath folder
# open ~/Desktop/Aftermath*
# 
# #Display an alert saying the scan is done and explaining what's in the file
# info_link2="https://github.com/jamf/aftermath"
# message2="Please look through the contents of the folder for the output of the Aftermath analysis.\n\nThe Storyline file will present the events that happened on this Mac in chronological order to aid in the process of investigating threats on your endpoint."
# button2="OK"
# 
# runDialog () {
# 	${dialog} \
# 	--title "Aftermath Analysis Complete" \
# 	--large \
# 	--ontop \
# 	--moveable \
# 	--icon 'SF=exclamationmark.shield.fill,colour=green' \
# 	--message ${message2} \
# 	--messagefont "size=18" \
# 	--infobuttontext "More Info" \
# 	--infobuttonaction ${info_link2} \
# 	--button1text ${button2} \
# }
# 
# runDialog
# 
# exit 0