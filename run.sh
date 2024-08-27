#!/bin/bash

echo "Preparing test directory..."
sudo rm -rf ../temp
echo "Removed ../temp"

mkdir ../temp
echo "Created ../temp"

cp -R ./* ../temp
echo "Copied current directory contents to ../temp"

echo "Running the python file $1..."
(cd ../temp/ && sudo python3 $1)
