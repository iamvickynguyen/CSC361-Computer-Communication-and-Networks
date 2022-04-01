#!/bin/bash
FILENAME=traceroute.py
DIRECTORY=./r2/tests/group2

for file in $DIRECTORY/*;
do
    echo "--------------------------------------------------------------------------------"
	echo "${file}"
    echo "--------------------------------------------------------------------------------"
	python3 $FILENAME $file
done