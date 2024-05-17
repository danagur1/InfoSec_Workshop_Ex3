#!/bin/bash

# Destination directory where files will be copied
destination_dir="$HOME/Desktop/hw4"

# Source directory (shared directory)
shared_dir="/media/sf_hw4"

# Copy the necessary files to the destination directory
cp -r "$shared_dir" "$destination_dir"

# Run the make command
if [ $# -eq 0 ]; then
    make    
fi
