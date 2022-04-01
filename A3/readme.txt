How to run:
    python3 traceroute.py <cap file>
    e.g. python3 traceroute.py PcapTracesAssignment3/group1-trace1.pcap

To run all the files in a test folder:
    Change DIRECTORY variable in output.sh
    ./output.sh


Answer to requirement 2 (also read r2.pdf)

----------------------------
GROUP 1
----------------------------
Determine the number of probes per “ttl” used in each trace file:
trace file 1: 3
trace file 2: 3
trace file 3: 3
trace file 4: 3
trace file 5: 3
We can see this information in Wireshark `ip.ttl == <number>` or command line


The sequence of intermediate routers is different in different trace files.

+--------+----------------+----------------+----------------+----------------+----------------+
| router | trace 1        | trace 2        | trace 3        | trace 4        | trace 5        |
+--------+----------------+----------------+----------------+----------------+----------------+
| 12     | 74.125.37.91   | 72.14.237.123  | 74.125.37.91   | 74.125.37.91   | 72.14.237.123  |
+--------+----------------+----------------+----------------+----------------+----------------+
| 13     | 72.14.237.123  | 74.125.37.91   | 72.14.237.123  | 72.14.237.123  | 209.85.249.153 |
+--------+----------------+----------------+----------------+----------------+----------------+
| 14     | 209.85.249.155 | 209.85.249.109 | 209.85.247.63  | 209.85.246.219 | 209.85.250.59  |
+--------+----------------+----------------+----------------+----------------+----------------+
| 15     | 209.85.250.121 | 209.85.250.57  | 209.85.245.65  | 209.85.250.123 | 209.85.247.61  |
+--------+----------------+----------------+----------------+----------------+----------------+
| 16     | 209.85.249.153 | 209.85.246.219 | 209.85.249.155 | 209.85.245.65  | x              |
+--------+----------------+----------------+----------------+----------------+----------------+

This may be because these routers use some routing protocols that can find shortest/fastest paths to avoid congestion.


----------------------------
GROUP 2
----------------------------
Determine the number of probes per “ttl” used in each trace file:
trace file 1: 3
trace file 2: 3
trace file 3: 3
trace file 4: 3
trace file 5: 3
We can see this information in Wireshark `ip.ttl == <number>` or command line

The sequence of intermediate routers is the same in different trace files

+-----+-----------+-------------+-----------+-----------+-----------+
| TTL | avg TTL 1 | avg TTL 2   | avg TTL 3 | avg TTL 4 | avg TTL 5 |
+-----+-----------+-------------+-----------+-----------+-----------+
| 1   | 3.329667  | 2.710667    | 7.854     | 3.415333  | 1.745667  |
+-----+-----------+-------------+-----------+-----------+-----------+
| 2   | 15.811667 | 17.118333   | 11.835333 | 13.245    | 16.153667 |
+-----+-----------+-------------+-----------+-----------+-----------+
| 3   | 18.869333 | 20.096667   | 22.579333 | 21.672333 | 21.601667 |
+-----+-----------+-------------+-----------+-----------+-----------+
| 4   | 22.843    | 19.42       | 19.460333 | 19.754667 | 18.558333 |
+-----+-----------+-------------+-----------+-----------+-----------+
| 5   | 26.502    | 21.555333   | 20.321333 | 35.771333 | 20.717    |
+-----+-----------+-------------+-----------+-----------+-----------+
| 6   | 24.263667 | 19.982333   | 21.849667 | 22.674667 | 43.472    |
+-----+-----------+-------------+-----------+-----------+-----------+
| 7   | 18.408    | 51.658      | 22.763333 | 18.337333 | 26.921333 |
+-----+-----------+-------------+-----------+-----------+-----------+
| 8   | 22.970667 | -224.262333 | 20.592    | 24.574333 | 25.623333 |
+-----+-----------+-------------+-----------+-----------+-----------+

Hop to router 7 or 8 is likely to incur the maximum delay. This may be because in the store and forward network,
some packets might be rerouted and there are many packets stuck in the queue, which causes delay.
Also this can be because it uses static routing table so the path to destination is always the same, so there are some
congestions.