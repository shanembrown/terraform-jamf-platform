#!/bin/bash

# Script configuration
LOG_FILE="/Users/Shared/experiencejamf.log"
DIALOG_CMD_FILE="/var/tmp/dialog.command"
VMNAME="experiencejamf"
DIALOG="/usr/local/bin/dialog"
TART_DOWNLOAD="https://github.com/cirruslabs/tart/releases/latest/download/tart-arm64.tar.gz"
TART_IMAGE="macos-sequoia-vanilla"
TART_DIR="/Users/Shared/tart.app/Contents/MacOS"
DEBUG=0

# Set PATH
export PATH=/usr/bin:/bin:/usr/sbin:/sbin

# Logging function
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

# Error checking function
check_error() {
    if [ $? -ne 0 ]; then
        log "ERROR" "$1"
        exit 1
    fi
}

# Dialog installation function
dialogInstall() {
    dialogURL=$(curl -L --silent --fail "https://api.github.com/repos/swiftDialog/swiftDialog/releases/latest" | awk -F '"' "/browser_download_url/ && /pkg\"/ { print \$4; exit }")
    expectedDialogTeamID="PWA5E9TQ59"

    log "INFO" "PRE-FLIGHT CHECK: Installing swiftDialog..."

    # Create temporary working directory
    workDirectory=$( /usr/bin/basename "$0" )
    tempDirectory=$( /usr/bin/mktemp -d "/private/tmp/$workDirectory.XXXXXX" )

    # Download the installer package
    /usr/bin/curl --location --silent "$dialogURL" -o "$tempDirectory/Dialog.pkg"

    # Verify the download
    teamID=$(/usr/sbin/spctl -a -vv -t install "$tempDirectory/Dialog.pkg" 2>&1 | awk '/origin=/ {print $NF }' | tr -d '()')

    # Install the package if Team ID validates
    if [[ "$expectedDialogTeamID" == "$teamID" ]]; then
        /usr/sbin/installer -pkg "$tempDirectory/Dialog.pkg" -target /
        sleep 2
        dialogVersion=$( /usr/local/bin/dialog --version )
        log "INFO" "PRE-FLIGHT CHECK: swiftDialog version ${dialogVersion} installed; proceeding..."
    else
        osascript -e 'display dialog "Please advise your Support Representative of the following error:\r\r• Dialog Team ID verification failed\r\r" with title "Setup Your Mac: Error" buttons {"Close"} with icon caution'
        exit 1
    fi

   # Remove the temporary working directory when done
    /bin/rm -Rf "$tempDirectory"
}

# System requirements check
check_requirements() {
    log "INFO" "Checking system requirements..."

    # Check if running on ARM Mac
    if [ "$(uname -m)" != "arm64" ]; then
        log "ERROR" "This script requires an ARM-based Mac"
        exit 1
    fi

    # Check if running with sudo/root
    if [ "$EUID" -eq 0 ]; then
        log "ERROR" "This script should not be run as root"
        exit 1
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

    # Check for Swift Dialog and install if missing
    if [[ ! -x $DIALOG ]]; then
        dialogInstall
    else
        log "INFO" "swiftDialog is already installed"
    fi
}

# Debug cleanup function
handle_debug_cleanup() {
    if [ "$DEBUG" -eq 1 ]; then
        log "INFO" "Debug mode enabled"
        read -p "Would you like to delete cached Tart items? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log "INFO" "Removing cached Tart items..."
            rm -rf ~/.tart
            rm -rf /Users/Shared/tart.app
            log "INFO" "Cached items removed"
        fi
    fi
}

# Install Tart function
install_tart() {
    log "INFO" "Starting Tart installation..."
    cd /Users/Shared || exit 1

    if [ -d "/Users/Shared/tart.app" ]; then
        log "INFO" "Tart is already installed, skipping download..."
        return
    fi

    log "INFO" "Downloading Tart..."
    curl -LO "$TART_DOWNLOAD" > /dev/null 2>&1
    check_error "Failed to download Tart"

    log "INFO" "Extracting Tart..."
    tar -xzvf tart-arm64.tar.gz > /dev/null 2>&1
    check_error "Failed to extract Tart"

    # Cleanup
    if [ -f "tart-arm64.tar.gz" ]; then
        rm -f tart-arm64.tar.gz
    fi

    # Verify installation
    if [ ! -f "$TART_DIR/tart" ]; then
        log "ERROR" "Tart installation failed"
        exit 1
    fi
}

# Setup and run VM function
setup_vm() {
    log "INFO" "Setting up VM..."
    cd "$TART_DIR" || exit 1

    # Verify tart executable exists and is accessible
    if [ ! -x "./tart" ]; then
        log "ERROR" "Tart executable not found or not executable"
        exit 1
    fi

    # Initialize dialog with progress bar
    "$DIALOG" \
        --title "Experience Jamf" \
        --message "Preparing and downloading your new Experience Jamf VM" \
        --progress 100 \
        --progresstext "0%" \
        --icon "https://i0.wp.com/macmule.com/wp-content/uploads/2020/08/2062092.png?resize=256%2C256&ssl=1" \
        --mini \
        --commandfile "$DIALOG_CMD_FILE" &

    DIALOG_PID=$!
    > "$DIALOG_CMD_FILE"

    # Pull the image and monitor progress with error handling
    log "INFO" "Pulling base image..."
    ./tart pull "ghcr.io/cirruslabs/$TART_IMAGE" 2>&1 | while read -r line; do
        echo "$line" # Print the line to see the output
        
        if [[ $line == *"image is already cached"* ]]; then
            echo "progresstext: Image already cached" > "$DIALOG_CMD_FILE"
            echo "progress: 100" > "$DIALOG_CMD_FILE"
            sleep 1
            break
        elif [[ $line =~ ([0-9]+)% ]]; then
            percent="${BASH_REMATCH[1]}"
            echo "progress: $percent" > "$DIALOG_CMD_FILE"
            echo "progresstext: Downloading... ${percent}%" > "$DIALOG_CMD_FILE"
        fi
    done

    # Check if the pull was successful
    if [[ $? -eq 0 ]] || [[ $PULL_OUTPUT == *"image is already cached"* ]]; then
        log "INFO" "Image ready to use"
        echo "quit:" > "$DIALOG_CMD_FILE"
        wait $DIALOG_PID
    else
        log "ERROR" "Failed to pull image. Please check your internet connection and try again"
        echo "quit:" > "$DIALOG_CMD_FILE"
        wait $DIALOG_PID
        exit 1
    fi

    log "INFO" "Cloning VM..."
    ./tart clone "ghcr.io/cirruslabs/$TART_IMAGE:latest" "$VMNAME"
    check_error "Failed to clone VM"

    log "INFO" "Configuring VM..."
    ./tart set --random-mac "$VMNAME"
    check_error "Failed to set random MAC"

    ./tart set --random-serial "$VMNAME"
    check_error "Failed to set random serial"

    log "INFO" "Starting VM..."
    ./tart run "$VMNAME" &
    check_error "Failed to start VM"
}

# Main execution
main() {
    # Parse command line arguments
    if [[ "$1" == "--debug" ]]; then
        DEBUG=1
    fi

    log "INFO" "Script started"
    check_requirements
    handle_debug_cleanup
    install_tart
    setup_vm
    log "INFO" "Script completed successfully"
}

# Run main function
main "$@"