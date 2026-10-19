# RT-P5 classes: `registered` cell

Chain height 117; curve tree {"depth": 1, "height": 116, "leaf_count": 125, "root": "fb88c9c8ae364c2aca77a283cec5bfae993ba8ff69991f1a2f3be829db1708d0", "status": "OK"}.

1474 messages, 1500 records.

## HTTP message sizes per method

| Method | Direction | Count | Min | Median | Max | Records |
|---|---|---:|---:|---:|---:|---:|
| `/get_height` | request | 35 | 84 | 84 | 84 | 35 |
| `/get_height` | response | 35 | 287 | 288 | 288 | 35 |
| `/get_o_indexes.bin` | request | 325 | 168 | 168 | 168 | 325 |
| `/get_o_indexes.bin` | response | 325 | 234 | 234 | 266 | 325 |
| `/get_transactions` | request | 18 | 230 | 230 | 431 | 18 |
| `/get_transactions` | response | 18 | 16,684 | 63,124 | 338,644 | 34 |
| `/submit_transaction` | request | 12 | 26,599 | 104,920 | 153,688 | 22 |
| `/submit_transaction` | response | 12 | 207 | 207 | 207 | 12 |
| `json_rpc:get_block` | request | 325 | 201 | 203 | 204 | 325 |
| `json_rpc:get_block` | response | 325 | 11,038 | 11,104 | 44,912 | 325 |
| `json_rpc:get_fee_estimate` | request | 19 | 154 | 154 | 154 | 19 |
| `json_rpc:get_fee_estimate` | response | 19 | 263 | 263 | 263 | 19 |
| `json_rpc:get_version` | request | 3 | 161 | 161 | 161 | 3 |
| `json_rpc:get_version` | response | 3 | 509 | 509 | 510 | 3 |

## Candidate tables

Padding is the bytes added to reach each record's class, over every record in the trace. The largest class is fixed at 65,535.

| K | Classes | Padding | Padding / payload |
|---:|---|---:|---:|
| 1 | 65,535 | 91,577,059 | 1362.3% |
| 2 | 11,357, 65,535 | 13,452,383 | 200.1% |
| 3 | 290, 11,357, 65,535 | 1,123,745 | 16.7% |
| 4 | 290, 11,357, 27,534, 65,535 | 629,732 | 9.4% |
| 5 | 290, 11,357, 27,534, 52,278, 65,535 | 444,134 | 6.6% |
| 6 | 236, 512, 11,357, 27,534, 52,278, 65,535 | 345,485 | 5.1% |
| 7 | 236, 512, 11,144, 11,882, 27,534, 52,278, 65,535 | 257,190 | 3.8% |
| 8 | 236, 512, 11,144, 11,882, 27,534, 44,914, 52,278, 65,535 | 190,914 | 2.8% |

## What shares a submission's class

For each K, the classes a submission request's records fall in, and every other method and direction with records in those classes (records counted).

- **K = 1**: submission records in 65,535; shared with `/get_height` request ×35, `/get_height` response ×35, `/get_o_indexes.bin` request ×325, `/get_o_indexes.bin` response ×325, `/get_transactions` request ×18, `/get_transactions` response ×34, `/submit_transaction` response ×12, `json_rpc:get_block` request ×325, `json_rpc:get_block` response ×325, `json_rpc:get_fee_estimate` request ×19, `json_rpc:get_fee_estimate` response ×19, `json_rpc:get_version` request ×3, `json_rpc:get_version` response ×3.
- **K = 2**: submission records in 11,357, 65,535; shared with `/get_height` request ×35, `/get_height` response ×35, `/get_o_indexes.bin` request ×325, `/get_o_indexes.bin` response ×325, `/get_transactions` request ×18, `/get_transactions` response ×34, `/submit_transaction` response ×12, `json_rpc:get_block` request ×325, `json_rpc:get_block` response ×325, `json_rpc:get_fee_estimate` request ×19, `json_rpc:get_fee_estimate` response ×19, `json_rpc:get_version` request ×3, `json_rpc:get_version` response ×3.
- **K = 3**: submission records in 11,357, 65,535; shared with `/get_transactions` request ×2, `/get_transactions` response ×34, `json_rpc:get_block` response ×325, `json_rpc:get_version` response ×3.
- **K = 4**: submission records in 11,357, 27,534, 65,535; shared with `/get_transactions` request ×2, `/get_transactions` response ×34, `json_rpc:get_block` response ×325, `json_rpc:get_version` response ×3.
- **K = 5**: submission records in 11,357, 27,534, 52,278, 65,535; shared with `/get_transactions` request ×2, `/get_transactions` response ×34, `json_rpc:get_block` response ×325, `json_rpc:get_version` response ×3.
- **K = 6**: submission records in 11,357, 27,534, 52,278, 65,535; shared with `/get_transactions` response ×34, `json_rpc:get_block` response ×325.
- **K = 7**: submission records in 11,144, 27,534, 52,278, 65,535; shared with `/get_transactions` response ×34, `json_rpc:get_block` response ×307.
- **K = 8**: submission records in 11,144, 27,534, 44,914, 52,278, 65,535; shared with `/get_transactions` response ×34, `json_rpc:get_block` response ×307.

## A submission at greater tree depth

A submission body is 14 + 2 × the transaction's wire length, for every submission in this trace. Each row below is the submission message at that depth, from the weight crate's size predictor; the head is taken as unchanged except for the length of `content-length`'s digits.

| Tx | Wallet | Inputs × outputs | Built at depth | d=1 | d=2 | d=3 | d=4 | d=5 | d=6 | d=7 | d=8 |
|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 0 | funder | 4 × 16 | 2 | 99,799 | 104,920 | 103,768 | 104,920 | 106,456 | 106,584 | 106,200 | 108,248 |
| 1 | funder | 4 × 16 | 2 | 99,799 | 104,920 | 103,768 | 104,920 | 106,456 | 106,584 | 106,200 | 108,248 |
| 2 | funder | 4 × 16 | 2 | 99,799 | 104,920 | 103,768 | 104,920 | 106,456 | 106,584 | 106,200 | 108,248 |
| 3 | funder | 4 × 16 | 2 | 99,799 | 104,920 | 103,768 | 104,920 | 106,456 | 106,584 | 106,200 | 108,248 |
| 4 | wallet | 1 × 2 | 2 | 25,319 | 26,599 | 27,367 | 28,647 | 29,415 | 30,695 | 29,543 | 30,823 |
| 5 | wallet | 2 × 2 | 2 | 40,007 | 42,567 | 40,903 | 43,463 | 44,487 | 44,103 | 43,207 | 44,743 |
| 6 | wallet | 4 × 2 | 2 | 63,879 | 68,999 | 67,847 | 68,999 | 70,535 | 70,663 | 70,279 | 72,327 |
| 7 | wallet | 8 × 2 | 2 | 111,496 | 117,768 | 117,640 | 119,816 | 122,376 | 123,528 | 124,168 | 127,242 |
| 8 | wallet | 1 × 16 | 2 | 61,239 | 62,519 | 63,287 | 64,567 | 65,335 | 66,615 | 65,463 | 66,743 |
| 9 | wallet | 2 × 16 | 2 | 75,927 | 78,487 | 76,823 | 79,383 | 80,407 | 80,023 | 79,127 | 80,663 |
| 10 | wallet | 4 × 16 | 2 | 99,799 | 104,920 | 103,768 | 104,920 | 106,456 | 106,584 | 106,200 | 108,248 |
| 11 | wallet | 8 × 16 | 2 | 147,416 | 153,688 | 153,560 | 155,736 | 158,296 | 159,448 | 160,088 | 163,162 |
