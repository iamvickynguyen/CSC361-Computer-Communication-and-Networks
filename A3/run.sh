#!/bin/sh
FILE_NAME=traceroute.py
DIRECTORY=./PcapTracesAssignment3
echo "--------------------------------------------------------------------------------"
echo "Group 1 trace 1 (Linux)"
echo "--------------------------------------------------------------------------------"
if (( ! python3 $FILE_NAME $DIRECTORY/group1-trace1.pcap ));
then
    echo "FAIL!"
fi
echo "--------------------------------------------------------------------------------"
echo "Group 1 trace 2 (Linux)"
echo "--------------------------------------------------------------------------------"
if (( ! python3 $FILE_NAME $DIRECTORY/group1-trace2.pcap ));
then
    echo "FAIL!"
fi
echo "--------------------------------------------------------------------------------"
echo "Group 1 trace 3 (Linux)"
echo "--------------------------------------------------------------------------------"
if (( ! python3 $FILE_NAME $DIRECTORY/group1-trace3.pcap ));
then
    echo "FAIL!"
fi
echo "--------------------------------------------------------------------------------"
echo "Group 1 trace 4 (Linux)"
echo "--------------------------------------------------------------------------------"
if (( ! python3 $FILE_NAME $DIRECTORY/group1-trace4.pcap ));
then
    echo "FAIL!"
fi
echo "--------------------------------------------------------------------------------"
echo "Group 1 trace 5 (Linux)"
echo "--------------------------------------------------------------------------------"
if (( ! python3 $FILE_NAME $DIRECTORY/group1-trace5.pcap ));
then
    echo "FAIL!"
fi
echo "--------------------------------------------------------------------------------"
echo "Group 2 trace 1 (Windows)"
echo "--------------------------------------------------------------------------------"
if (( ! python3 $FILE_NAME $DIRECTORY/group2-trace1.pcap ));
then
    echo "FAIL!"
fi
echo "--------------------------------------------------------------------------------"
echo "Group 2 trace 2 (Windows)"
echo "--------------------------------------------------------------------------------"
if (( ! python3 $FILE_NAME $DIRECTORY/group2-trace2.pcap ));
then
    echo "FAIL!"
fi
echo "--------------------------------------------------------------------------------"
echo "Group 2 trace 3 (Windows)"
echo "--------------------------------------------------------------------------------"
if (( ! python3 $FILE_NAME $DIRECTORY/group2-trace3.pcap ));
then
    echo "FAIL!"
fi
echo "--------------------------------------------------------------------------------"
echo "Group 2 trace 4 (Windows)"
echo "--------------------------------------------------------------------------------"
if (( ! python3 $FILE_NAME $DIRECTORY/group2-trace4.pcap ));
then
    echo "FAIL!"
fi
echo "--------------------------------------------------------------------------------"
echo "Group 2 trace 5 (Windows)"
echo "--------------------------------------------------------------------------------"
if (( ! python3 $FILE_NAME $DIRECTORY/group2-trace5.pcap ));
then
    echo "FAIL!"
fi
echo "--------------------------------------------------------------------------------"
echo "Fragmented trace (Linux)"
echo "--------------------------------------------------------------------------------"
if (( ! python3 $FILE_NAME $DIRECTORY/traceroute-frag.pcap ));
then
    echo "FAIL!"
fi
echo "--------------------------------------------------------------------------------"
echo "Long windows tracefile 1"
echo "--------------------------------------------------------------------------------"
if (( ! python3 $FILE_NAME $DIRECTORY/win_trace1.pcap ));
then
    echo "FAIL!"
fi
echo "--------------------------------------------------------------------------------"
echo "Long windows tracefile 2"
echo "--------------------------------------------------------------------------------"
if (( ! python3 $FILE_NAME $DIRECTORY/win_trace2.pcap ));
then
    echo "FAIL!"
fi