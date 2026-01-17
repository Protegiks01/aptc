#!/bin/bash

# Directory containing the markdown files
VALIDATED_DIR="$(dirname "$0")/validated"

# Check if the validated directory exists
if [ ! -d "$VALIDATED_DIR" ]; then
    echo "Error: Validated directory not found at $VALIDATED_DIR"
    exit 1
fi

# Counters for tracking
processed=0
deleted=0

# Process each markdown file in the validated directory
find "$VALIDATED_DIR" -name "*.md" -type f | while read -r file; do
    ((processed++))
    
    # Check for the patterns in the file
    if grep -q -E 'this task is not within my current capabilities' "$file"; then
        echo "Deleting file containing invalid patterns: $(basename "$file")"
        rm "$file"
        ((deleted++))
    fi
done

echo "Validation complete!"
echo "Processed files: $processed"
echo "Deleted files: $deleted"

exit 0
