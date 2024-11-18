#!/bin/bash


###############################################################################
# Script Name: EJ_tart-VM-build.sh
# Description: Automated VM builder for Experience Jamf using Tart
# Author: Rob Potvin and Matthew Ward
# Version: 0.9
###############################################################################


# Enable strict error handling
set -euo pipefail

# Add common paths to PATH
export PATH="/usr/local/bin:/usr/bin:/bin:$PATH"

# Variables
VM="experiencejamf"
IMAGE="ghcr.io/cirruslabs/macos-sequoia-base:latest"
TART_PATH="/Users/Shared/tart/tart.app/Contents/MacOS/tart"
DIALOG="/usr/local/bin/dialog"
LOG_FILE="/tmp/ejtartinstall.log"
BUTTON_TEXT="Install"
TART_DOWNLOAD="https://github.com/cirruslabs/tart/releases/latest/download/tart-arm64.tar.gz"
currentUser=$( echo "show State:/Users/ConsoleUser" | scutil | awk '/Name :/ { print $3 }' )
uid=$(id -u "$currentUser")

# convenience function to run a command as the current user
# usage:
#   runAsUser command arguments...
runAsUser() {  
  if [ "$currentUser" != "loginwindow" ]; then
    launchctl asuser "$uid" sudo -u "$currentUser" "$@"
  else
    echo "no user logged in"
    # uncomment the exit command
    # to make the function exit with an error when no user is logged in
    exit 1
  fi
}

# Function to handle logging with timestamps
log() {
    local level="$1"
    local message="$2"
    local formatted_msg="[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message"
    printf '%s\n' "$formatted_msg" | tee -a "$LOG_FILE"
}


# System validation functions
check_requirements() {
    log "INFO" "Checking system requirements..."
    
    # Check if running on ARM Mac using multiple methods for reliability
    ARCH=$(uname -m)
    SYSCTL_ARCH=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "")
    
    if [ "$ARCH" != "arm64" ] && ! echo "$SYSCTL_ARCH" | grep -q "Apple"; then
        log "ERROR" "This script requires an Apple Silicon Mac (M1/M2/M3)"
        exit 1
    fi

    # Check for Dialog CLI tool
    if [ ! -f "/usr/local/bin/dialog" ]; then
        log "ERROR" "swiftdialog tool could not be found at /usr/local/bin/dialog"
        exit 1
    fi

    # Check for minimum 90GB free disk space
    FREE_SPACE=$(df -H / | awk 'NR==2 {print $4}' | sed 's/G//')
    FREE_SPACE_GB=${FREE_SPACE%.*} # Remove decimal places
    
    if [ "$FREE_SPACE_GB" -lt 90 ]; then
        log "ERROR" "Insufficient disk space. At least 100GB required, only ${FREE_SPACE_GB}GB available"
        exit 48
    fi

    # Check minimal macOS requirement
    if [[ $(/usr/bin/sw_vers -buildVersion ) < "21A" ]]; then
        log "ERROR" "This script requires at least macOS 12 Monterey"
        exit 98
    fi

    # Check network connectivity
    if ! curl --silent --head github.com > /dev/null; then
        log "ERROR" "No network connectivity to GitHub"
        exit 1
    fi
}

# Function to install Tart if needed
install_tart() {
    log "INFO" "Starting Tart installation..."

    # Create shared Tart directory first
    log "INFO" "Creating shared Tart directory..."
    runAsUser mkdir -p "/Users/Shared/tart"
    if [ $? -ne 0 ]; then
        log "ERROR" "Failed to create shared Tart directory"
        return 1
    fi

    # Create symbolic link before proceeding
    if [ -e "${HOME}/.tart" ]; then
        log "INFO" "Existing .tart found in home directory, skipping symbolic link creation"
    else
        log "INFO" "Creating symbolic link to shared Tart directory..."
        runAsUser ln -s "/Users/Shared/tart" "${HOME}/.tart"
        if [ $? -ne 0 ]; then
            log "ERROR" "Failed to create symbolic link"
            return 1
        fi
    fi

    # Now proceed with Tart installation if needed
    if [ -d "$TART_PATH" ]; then
        log "INFO" "Tart is already installed, skipping download..."
        return 0
    fi

    cd /Users/Shared/tart/ || exit 1

    # These operations need root
    log "INFO" "Downloading Tart..."
    curl -LO "$TART_DOWNLOAD" > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        log "ERROR" "Failed to download Tart"
        return 1
    fi

    log "INFO" "Extracting Tart..."
    tar -xzvf tart-arm64.tar.gz > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        log "ERROR" "Failed to extract Tart"
        return 1
    fi

    # Cleanup
    if [ -f "tart-arm64.tar.gz" ]; then
        rm -f tart-arm64.tar.gz
    fi

    return 0
}

# Function to check if VM exists
check_ej_exists() {
    log "INFO" "Checking if Experience Jamf VM exists..."
    if runAsUser "$TART_PATH" list | awk '/^local/ {print $2}' | grep -q "^${VM}$"; then
        log "INFO" "Experience Jamf VM exists. Run window will be shown"
        START_WINDOW=1
        return 0
    else
        log "INFO" "Experience Jamf VM does not exist. Install window will be shown"
        START_WINDOW=2
        return 1
    fi
}

# Function to check if base VM image exists
check_basevm_exists() {
    log "INFO" "Checking if base VM image exists..."
    if runAsUser "$TART_PATH" list | awk '/ghcr\.io\/cirruslabs\/macos-sequoia-base:latest/ {print $2}' | grep -q "^${IMAGE}$"; then
        log "INFO" "Base VM image exists."
        return 0
    else
        log "INFO" "Base VM image does not exist."
        return 1
    fi
}

# Function to show run dialog
show_run_dialog() {
    log "INFO" "Displaying run dialog..."
    "$DIALOG" \
        --title "Experience Jamf VM Edition" \
        --message "#### Welcome back to Experience Jamf!
Great news! We found the Experience Jamf VM installed and ready to go! Click 'Start VM' to begin your experience.

⚙️ Your virtual Mac environment is all set up and ready for you to enroll into Experience Jamf.

Ready to continue your journey?" \
        --icon "macwindow.on.rectangle" \
        --button1text "Start VM" \
        --button2text "Quit" \
        --infobuttontext "Learn More" \
        --infobuttonaction "https://github.com/jamf/experience-jamf" \
        --messagefont "size=18" \
        --moveable
    if [[ $? -eq 2 ]]; then
        log "INFO" "User chose to quit."
        exit
    fi
}

# Rename existing show_welcome_dialog to show_install_dialog
show_install_dialog() {
    log "INFO" "Displaying install dialog..."
    "$DIALOG" \
        --title "Experience Jamf VM Edition" \
        --message "#### Welcome to Experience Jamf!
This tool will help you create a **virtual Mac** for testing and exploring Jamf's device management capabilities.

⚙️ We'll set up everything you need to get started with a fresh macOS environment - no physical Mac required!

Ready to blast off?

The VM will automatically launch after installation is complete." \
        --icon "https://resources.jamf.com/images/logos/Jamf-Icon-color.png" \
        --button1text "Install" \
        --button2text "Quit" \
        --infobuttontext "Learn More" \
        --infobuttonaction "https://github.com/jamf/experience-jamf" \
        --messagefont "size=18" \
        --moveable
    if [[ $? -eq 2 ]]; then
        log "INFO" "User chose to quit installation."
        exit
    fi
}

# Function to perform Tart operations
tart_operations() {
    local command="$1"
    local vm_name="$2"
    local options="${3:-}"
    local dialog_cmd_file="/tmp/dialog.log"

    if [[ -z "$command" || -z "$vm_name" ]]; then
        log "ERROR" "Usage: tart_operations <command> <vm_name> [options]"
        exit 1
    fi

    case "$command" in
    pull)
        log "INFO" "Pulling image: $vm_name"
        echo "progresstext: Preparing to download image..." >"$dialog_cmd_file"
        echo "progress: 0" >>"$dialog_cmd_file"

        # Ensure the base VM image doesn't exist before proceeding
        if ! check_basevm_exists; then
            # Start SwiftDialog in the background
            "$DIALOG" --title "Downloading VM Image" \
                --message "Downloading image file..." \
                --icon "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/NetBootVolume.icns" \
                --progress 100 \
                --commandfile "$dialog_cmd_file" \
                --mini \
                --position center &
            local dialog_pid=$!

            runAsUser "$TART_PATH" pull "$vm_name" 2>&1 | while IFS= read -r line; do
                if [[ $line =~ ([0-9]+)% ]]; then
                    local percent="${BASH_REMATCH[1]}"
                    echo "progress: $percent" >"$dialog_cmd_file"
                    echo "progresstext: Downloading image... ($percent%)" >>"$dialog_cmd_file"
                fi
            done

            local pull_exit_code=$?

            # Function to gracefully terminate a process on macOS
            cleanup_process() {
                # Additional check to ensure the dialog window is closed
                if pgrep -f "dialog" > /dev/null; then
                    log "INFO" "Dialog process still running, attempting to kill..."
                    pkill -f "dialog"
                fi
            }

            # Cleanup the dialog process
            cleanup_process "$dialog_pid"

            rm -f "$dialog_cmd_file"

            if [[ $pull_exit_code -ne 0 ]]; then
                log "ERROR" "Failed to pull image: $vm_name"
                exit 1
            fi
        fi
        ;;
    clone)
        log "INFO" "Cloning image to VM: $vm_name"
        runAsUser "$TART_PATH" clone "$vm_name" "$options"
        ;;
    set)
        log "INFO" "Setting VM configuration: $vm_name"
        runAsUser "$TART_PATH" set "$vm_name" $options
        ;;
    run)
        log "INFO" "Starting VM: $vm_name"
        runAsUser "$TART_PATH" run "$vm_name" $options &
        ;;
    *)
        log "ERROR" "Invalid command: $command"
        exit 1
        ;;
    esac
}

# Main function
main() {
    log "DEBUG" "Starting main function."

    # Run system requirement checks
    check_requirements || {
        log "ERROR" "System requirements check failed"
        exit 1
    }

    # Install Tart if needed
    install_tart || {
        log "ERROR" "Failed to install Tart"
        exit 1
    }

    # Verify Tart executable exists after installation
    if [[ ! -x "$TART_PATH" ]]; then
        log "ERROR" "Tart executable not found at: $TART_PATH after installation"
        exit 1
    fi

    # Check if the VM exists
    if check_ej_exists; then
        log "DEBUG" "VM already exists. Button text set to '$BUTTON_TEXT'."
    else
        log "DEBUG" "VM does not exist. Button text set to '$BUTTON_TEXT'."
    fi

    # Show the appropriate dialog based on START_WINDOW
    if [ "$START_WINDOW" -eq 1 ]; then
        show_run_dialog
    else
        show_install_dialog
    fi

    # Only proceed with setup if the VM doesn't exist
    if ! check_ej_exists; then
        log "INFO" "Setting up VM '${VM}'."
        tart_operations pull "$IMAGE" || {
            log "ERROR" "Failed to pull image."
            exit 1
        }

        tart_operations clone "$IMAGE" "$VM" || {
            log "ERROR" "Failed to clone VM."
            exit 1
        }

        tart_operations set "$VM" "--random-mac --random-serial" || {
            log "ERROR" "Failed to configure VM."
            exit 1
        }
    else
        log "INFO" "VM '${VM}' already exists. Skipping setup."
    fi

    log "INFO" "Starting VM..."
    tart_operations run "$VM"
    log "INFO" "VM startup initiated. Exiting script."
}

# Execute the script
main
exit 0