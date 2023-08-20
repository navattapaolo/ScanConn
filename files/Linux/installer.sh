#!/bin/bash

# Directory
destination="/usr/local/bin"

# Current script name
script_name="installer.sh"

# Copy all files in usr/local/bin
for entry in *; do
  if [ "$entry" != "$script_name" ]; then
    cp -r "$entry" "$destination"
  fi
done
