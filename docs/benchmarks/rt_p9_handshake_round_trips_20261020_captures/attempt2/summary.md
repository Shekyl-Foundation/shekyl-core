## Completion

| Leg | Connections | Completed | Share | Accepted by the daemon, not completed |
|---|---:|---:|---:|---:|
| onion | 300 | 300 | 100.0% | 0 |
| lan | 300 | 300 | 100.0% | 0 |

## The daemon, from `accept` (ms)

| Leg | Stamp | n | median | p90 | p99 | max |
|---|---|---:|---:|---:|---:|---:|
| onion | message1_received | 300 | 550.8 | 1,027.9 | 1,803.4 | 4,488.8 |
| onion | message2_sent | 300 | 555.4 | 1,032.0 | 1,808.4 | 4,493.1 |
| onion | message3_received | 300 | 1,129.3 | 1,957.2 | 3,122.4 | 6,281.4 |
| onion | message4_sent | 300 | 1,131.3 | 1,959.4 | 3,124.5 | 6,283.5 |
| onion | first_record_opened | 300 | 1,704.5 | 2,802.4 | 5,231.9 | 7,791.1 |
| onion | reply_sent | 300 | 1,704.7 | 2,802.5 | 5,232.0 | 7,791.2 |
| lan | message1_received | 300 | 0.4 | 0.5 | 0.7 | 1.0 |
| lan | message2_sent | 300 | 5.2 | 5.3 | 5.5 | 5.6 |
| lan | message3_received | 300 | 5.9 | 6.1 | 6.3 | 6.7 |
| lan | message4_sent | 300 | 6.9 | 7.8 | 8.0 | 8.1 |
| lan | first_record_opened | 300 | 7.4 | 8.3 | 8.6 | 8.6 |
| lan | reply_sent | 300 | 7.4 | 8.3 | 8.6 | 8.6 |

## The client, from the start of its connect (ms)

| Leg | Stamp | n | median | p90 | p99 | max |
|---|---|---:|---:|---:|---:|---:|
| onion | connected | 300 | 2,040.7 | 3,552.6 | 16,852.9 | 45,107.3 |
| onion | message1_sent | 300 | 2,040.9 | 3,552.8 | 16,853.1 | 45,107.5 |
| onion | message2_received | 300 | 2,631.6 | 4,395.3 | 17,180.2 | 46,708.8 |
| onion | message3_sent | 300 | 2,631.8 | 4,395.5 | 17,180.4 | 46,709.0 |
| onion | message4_received | 300 | 3,234.3 | 5,426.8 | 17,513.6 | 47,857.8 |
| onion | first_record_sent | 300 | 3,234.4 | 5,427.0 | 17,513.7 | 47,857.9 |
| onion | reply_received | 300 | 3,782.1 | 6,361.7 | 17,848.8 | 49,466.8 |
| lan | connected | 300 | 0.4 | 0.5 | 0.5 | 0.6 |
| lan | message1_sent | 300 | 0.6 | 0.7 | 0.9 | 1.2 |
| lan | message2_received | 300 | 6.0 | 6.2 | 6.4 | 6.6 |
| lan | message3_sent | 300 | 6.2 | 6.4 | 6.6 | 7.0 |
| lan | message4_received | 300 | 7.7 | 8.6 | 8.9 | 8.9 |
| lan | first_record_sent | 300 | 7.8 | 8.7 | 9.0 | 9.0 |
| lan | reply_received | 300 | 8.1 | 9.0 | 9.3 | 9.4 |

## Gates

Met: every leg completed at least 95%, and on every completed sample the two sides' stamps describe one exchange.

## The deadlines

Each is 2 × the onion leg's 99th percentile from `accept`, rounded up to a whole second. The LAN figure beside it is the same rule applied to the LAN leg, reported, not used.

| Deadline | Onion p99 (ms) | Deadline (s) | LAN p99 (ms) | LAN by the same rule (s) |
|---|---:|---:|---:|---:|
| message 1 | 1,803.4 | 4 | 0.7 | 1 |
| whole handshake | 5,231.9 | 11 | 8.6 | 1 |
