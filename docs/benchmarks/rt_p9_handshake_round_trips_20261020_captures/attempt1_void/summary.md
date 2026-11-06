## Completion

| Leg | Connections | Completed | Share | Accepted by the daemon, not completed |
|---|---:|---:|---:|---:|
| onion | 300 | 300 | 100.0% | 0 |
| lan | 300 | 272 | 90.7% | 28 |

## The daemon, from `accept` (ms)

| Leg | Stamp | n | median | p90 | p99 | max |
|---|---|---:|---:|---:|---:|---:|
| onion | message1_received | 300 | 594.1 | 952.7 | 1,924.6 | 17,557.9 |
| onion | message2_sent | 300 | 596.4 | 956.5 | 1,928.9 | 17,562.0 |
| onion | message3_received | 300 | 1,243.3 | 2,031.3 | 3,719.5 | 18,334.9 |
| onion | message4_sent | 300 | 1,245.1 | 2,033.3 | 3,721.6 | 18,337.0 |
| onion | first_record_opened | 300 | 1,879.2 | 3,057.2 | 5,166.8 | 20,441.8 |
| onion | reply_sent | 300 | 1,879.3 | 3,057.3 | 5,166.9 | 20,442.0 |
| lan | message1_received | 272 | 0.3 | 0.4 | 0.5 | 0.8 |
| lan | message2_sent | 272 | 2.4 | 2.6 | 3.9 | 4.5 |
| lan | message3_received | 272 | 3.0 | 3.2 | 4.5 | 5.1 |
| lan | message4_sent | 272 | 3.9 | 4.1 | 5.8 | 6.4 |
| lan | first_record_opened | 272 | 4.3 | 4.6 | 6.2 | 6.8 |
| lan | reply_sent | 272 | 4.3 | 4.6 | 6.2 | 6.8 |

## The client, from the start of its connect (ms)

| Leg | Stamp | n | median | p90 | p99 | max |
|---|---|---:|---:|---:|---:|---:|
| onion | connected | 300 | 2,332.6 | 4,116.5 | 18,308.4 | 38,825.4 |
| onion | message1_sent | 300 | 2,332.8 | 4,116.7 | 18,308.6 | 38,825.8 |
| onion | message2_received | 300 | 3,048.9 | 5,397.2 | 18,796.7 | 39,404.5 |
| onion | message3_sent | 300 | 3,049.1 | 5,397.4 | 18,797.4 | 39,404.7 |
| onion | message4_received | 300 | 3,725.8 | 6,413.1 | 19,618.9 | 39,971.5 |
| onion | first_record_sent | 300 | 3,725.9 | 6,413.2 | 19,619.0 | 39,971.6 |
| onion | reply_received | 300 | 4,453.2 | 7,627.3 | 20,033.0 | 40,417.2 |
| lan | connected | 272 | 0.2 | 0.2 | 0.3 | 0.4 |
| lan | message1_sent | 272 | 0.4 | 0.4 | 0.6 | 0.7 |
| lan | message2_received | 272 | 3.0 | 3.2 | 7.0 | 9.1 |
| lan | message3_sent | 272 | 3.1 | 3.4 | 7.2 | 9.3 |
| lan | message4_received | 272 | 4.4 | 4.7 | 9.0 | 11.3 |
| lan | first_record_sent | 272 | 4.5 | 4.8 | 9.1 | 11.4 |
| lan | reply_received | 272 | 4.7 | 5.1 | 9.3 | 11.6 |

## Gates

**VOID.**
- lan: 272 of 300 completed, below 95%

