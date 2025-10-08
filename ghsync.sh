#!/bin/bash

# Navigate to your project directory
#cd /home/fresh/gravepixel || exit

# Add all changes (including deletions)
git add --all

# Commit the changes with a message
read -p "Enter commit message: " commit_message
git commit -m "$commit_message"

# Push the changes to GitHub
git push origin main

