#!/bin/bash

CDIR=$(dirname "$0")

# Install MIME type
echo "Installing MIME type..."
sudo xdg-mime install "$CDIR/application-x-azurite.xml"

# Install Desktop Entry
echo "Installing Desktop Entry..."
mkdir -p ~/.local/share/applications
cp "$CDIR/azurite.desktop" ~/.local/share/applications/

# Update databases
echo "Updating databases..."
update-desktop-database ~/.local/share/applications
update-mime-database ~/.local/share/mime

echo "Done! You may need to log out and back in for changes to take full effect."
