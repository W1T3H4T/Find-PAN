#!/bin/bash

# Loop through all files in the current directory
for file in *.*; do
    # Extract the filename without the extension
    filename="${file%.*}"
    # Extract the file extension
    extension="${file##*.}"
    # Create the new filename with '-1' appended before the extension
    new_filename="${filename}-1.${extension}"
    # Copy the file to the new filename
    cp "$file" "$new_filename"
done
