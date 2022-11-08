# P4 Network Telemetry Switch Implementation
This is a P4 implementation of a dataplane network telemetry switch that updates counters in a hash table each time a packet passes through the switch. An example of a basic query would be summing the number of bytes seen for each source IP/dest IP pair. Many dataplane telemetry switches allow for concurrent queries, e.g. for packets originating from subnet A, sum the number of bytes per src/dst IP, while for packets originating from subnet B, count the number of packets per dst port. This is often accomplished by taking the fields of each packet and matching them against a TCAM table to figure out which operations should be applied to the packet, namely, what fields become the key to the hash table (in the above example, src/dst ip for the first query and dst port for the second), and what operation to apply and fields to use to update the hash table (add byte count for the first query and add 1 for the second).

The problem is that this TCAM approach only allows each packet to be assigned to one query, so if subnet A and subnet B overlap in the above example, whichever one has higher TCAM priority will override the lower priority one.

This is an attempt at allowing a dataplane telemetry switch to match a packet against two independent queries concurrently by setting up a number of "update pipelines" that are conditionally invoked depending on which filters the incoming packet matched. This takes a lot of silicon space as you need one copy of the update logic for each concurrent query you want to support, but it works. The provided code runs with two pipelines, there are a lot of P4 macro generators out there that can generalize this to `n` pipelines.

This is tested in `bmv2`, which has some relaxations (namely you can read and write to SRAM multiple times in one execution cycle), and some extra work needs to be put in to make this run on real FPGAs, but that should be possible by reading the entire row from SRAM at the start of the update, masking out the data you want to pass to each update pipeline, and then concatenating the updated values back together before the writeback.

As this is just a proof of concept, there is currently no nice interface is provided to control this, you have to manually update the data in the different fields using the bmv2 CLI. `data_table_0` and `data_table_1` contain the hash table where the results will be, `filter_match` is where you set which fields will trigger which queries (the match is the fields, the action is the queries), `unpack_match_N` is where the field to extract from the packet for the update operation is set, and `reduction_match_N` is where the actual operation is set.

This project depends on the P4 ecosystem, namely https://github.com/p4lang/behavioral-model and https://github.com/p4lang/p4c