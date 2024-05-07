#!/bin/bash

# Destination directory where files will be copied
destination_dir="/Desktop/hw4"
new_destination_dir="/Desktop/hw4/sf_hw4"

# Source directory (shared directory)
shared_dir="/media/sf_hw4"

# Copy the necessary files to the destination directory
cp -r "$shared_dir" "$destination_dir"

# Change directory to the destination directory
cd "$new_destination_dir" || exit

# Run the make command
if [ $# -eq 0 ]; then
    make    
fi
