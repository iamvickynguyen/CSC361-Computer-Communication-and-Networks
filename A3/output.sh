#!/bin/bash
FILENAME=traceroute.py
DIRECTORY=./tests/group2

for file in $DIRECTORY/*;
do
    echo "--------------------------------------------------------------------------------"
	echo "${file}"
    echo "--------------------------------------------------------------------------------"
	python3 $FILENAME $file
done