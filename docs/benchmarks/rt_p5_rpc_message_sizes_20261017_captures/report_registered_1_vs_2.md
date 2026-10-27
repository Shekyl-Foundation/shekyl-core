# RT-P5: the candidate tables, per method

Tables are the first registered run's, by the registered rule. Records: 1500 in the first run, 1500 in the second. Padding is the bytes added to bring each record to its class; the percentage is of that method's payload (the record bytes less the two-byte occupancy).

Categories: a **block batch** is a `/get_transactions` response (up to 100 transaction bodies of the blocks being synced); **wallet sync** is every other message of a refresh (`get_block`, `get_o_indexes.bin`, `get_height`, `get_version`, and the `/get_transactions` request); **spend building** is `get_fee_estimate`; a **submission** is a `/submit_transaction` request. A path observer sees each record's direction, so where a submission stands is given in its own direction first.

## K = 1: 65,535

Overall padding: 91,577,059 bytes, 1362.3% of the payload.

| Method | Direction | Records | Payload | Padding | Padding % |
|---|---|---:|---:|---:|---:|
| `/get_height` | request | 35 | 2,940 | 2,290,715 | 77915.5% |
| `/get_height` | response | 35 | 10,064 | 2,283,591 | 22690.7% |
| `/get_o_indexes.bin` | request | 325 | 54,600 | 21,243,625 | 38907.7% |
| `/get_o_indexes.bin` | response | 325 | 76,146 | 21,222,079 | 27870.2% |
| `/get_transactions` | request | 18 | 4,542 | 1,175,052 | 25870.8% |
| `/get_transactions` | response | 34 | 1,706,278 | 521,844 | 30.6% |
| `/submit_transaction` | request | 22 | 1,075,227 | 366,499 | 34.1% |
| `/submit_transaction` | response | 12 | 2,484 | 783,912 | 31558.5% |
| `json_rpc:get_block` | request | 325 | 65,949 | 21,232,276 | 32195.0% |
| `json_rpc:get_block` | response | 325 | 3,714,277 | 17,583,948 | 473.4% |
| `json_rpc:get_fee_estimate` | request | 19 | 2,926 | 1,242,201 | 42453.9% |
| `json_rpc:get_fee_estimate` | response | 19 | 4,997 | 1,240,130 | 24817.5% |
| `json_rpc:get_version` | request | 3 | 483 | 196,116 | 40603.7% |
| `json_rpc:get_version` | response | 3 | 1,528 | 195,071 | 12766.4% |

| Class | Requests in it | Responses in it |
|---:|---|---|
| 65,535 | `/get_height` ×35, `/get_o_indexes.bin` ×325, `/get_transactions` ×18, `/submit_transaction` ×22, `json_rpc:get_block` ×325, `json_rpc:get_fee_estimate` ×19, `json_rpc:get_version` ×3 | `/get_height` ×35, `/get_o_indexes.bin` ×325, `/get_transactions` ×34, `/submit_transaction` ×12, `json_rpc:get_block` ×325, `json_rpc:get_fee_estimate` ×19, `json_rpc:get_version` ×3 |

**Where a submission stands**, per class its records fall in:

- 65,535: 22 of its 22 records. In its own direction it shares with wallet sync (706 records) and spend building (19 records); counting both directions it shares with block batch (34 records) and wallet sync (1394 records) and spend building (38 records) and submission reply (12 records).

**Second run in the first run's classes:** **yes**: every one of the second run's 1500 records lands in the same class as its first-run counterpart. Its padding under this table: 91,576,476 bytes, 1362.1%. The second run's own optimal table at this K is the same.

## K = 2: 11,357, 65,535

Overall padding: 13,452,383 bytes, 200.1% of the payload.

| Method | Direction | Records | Payload | Padding | Padding % |
|---|---|---:|---:|---:|---:|
| `/get_height` | request | 35 | 2,940 | 394,485 | 13417.9% |
| `/get_height` | response | 35 | 10,064 | 387,361 | 3849.0% |
| `/get_o_indexes.bin` | request | 325 | 54,600 | 3,635,775 | 6658.9% |
| `/get_o_indexes.bin` | response | 325 | 76,146 | 3,614,229 | 4746.4% |
| `/get_transactions` | request | 18 | 4,542 | 199,848 | 4400.0% |
| `/get_transactions` | response | 34 | 1,706,278 | 413,488 | 24.2% |
| `/submit_transaction` | request | 22 | 1,075,227 | 312,321 | 29.0% |
| `/submit_transaction` | response | 12 | 2,484 | 133,776 | 5385.5% |
| `json_rpc:get_block` | request | 325 | 65,949 | 3,624,426 | 5495.8% |
| `json_rpc:get_block` | response | 325 | 3,714,277 | 246,988 | 6.6% |
| `json_rpc:get_fee_estimate` | request | 19 | 2,926 | 212,819 | 7273.4% |
| `json_rpc:get_fee_estimate` | response | 19 | 4,997 | 210,748 | 4217.5% |
| `json_rpc:get_version` | request | 3 | 483 | 33,582 | 6952.8% |
| `json_rpc:get_version` | response | 3 | 1,528 | 32,537 | 2129.4% |

| Class | Requests in it | Responses in it |
|---:|---|---|
| 11,357 | `/get_height` ×35, `/get_o_indexes.bin` ×325, `/get_transactions` ×18, `/submit_transaction` ×1, `json_rpc:get_block` ×325, `json_rpc:get_fee_estimate` ×19, `json_rpc:get_version` ×3 | `/get_height` ×35, `/get_o_indexes.bin` ×325, `/get_transactions` ×2, `/submit_transaction` ×12, `json_rpc:get_block` ×320, `json_rpc:get_fee_estimate` ×19, `json_rpc:get_version` ×3 |
| 65,535 | `/submit_transaction` ×21 | `/get_transactions` ×32, `json_rpc:get_block` ×5 |

**Where a submission stands**, per class its records fall in:

- 11,357: 1 of its 22 records. In its own direction it shares with wallet sync (706 records) and spend building (19 records); counting both directions it shares with block batch (2 records) and wallet sync (1389 records) and spend building (38 records) and submission reply (12 records).
- 65,535: 21 of its 22 records. In its own direction it stands alone; counting both directions it shares with block batch (32 records) and wallet sync (5 records).

**Second run in the first run's classes:** **no**: 2 of the second run's 1500 records land in a different class from their first-run counterpart (`json_rpc:get_block` response 2). Its padding under this table: 13,560,156 bytes, 201.7%. The second run's own optimal table at this K differs: 11,379, 65,535.

## K = 3: 290, 11,357, 65,535

Overall padding: 1,123,745 bytes, 16.7% of the payload.

| Method | Direction | Records | Payload | Padding | Padding % |
|---|---|---:|---:|---:|---:|
| `/get_height` | request | 35 | 2,940 | 7,140 | 242.9% |
| `/get_height` | response | 35 | 10,064 | 16 | 0.2% |
| `/get_o_indexes.bin` | request | 325 | 54,600 | 39,000 | 71.4% |
| `/get_o_indexes.bin` | response | 325 | 76,146 | 17,454 | 22.9% |
| `/get_transactions` | request | 18 | 4,542 | 22,776 | 501.5% |
| `/get_transactions` | response | 34 | 1,706,278 | 413,488 | 24.2% |
| `/submit_transaction` | request | 22 | 1,075,227 | 312,321 | 29.0% |
| `/submit_transaction` | response | 12 | 2,484 | 972 | 39.1% |
| `json_rpc:get_block` | request | 325 | 65,949 | 27,651 | 41.9% |
| `json_rpc:get_block` | response | 325 | 3,714,277 | 246,988 | 6.6% |
| `json_rpc:get_fee_estimate` | request | 19 | 2,926 | 2,546 | 87.0% |
| `json_rpc:get_fee_estimate` | response | 19 | 4,997 | 475 | 9.5% |
| `json_rpc:get_version` | request | 3 | 483 | 381 | 78.9% |
| `json_rpc:get_version` | response | 3 | 1,528 | 32,537 | 2129.4% |

| Class | Requests in it | Responses in it |
|---:|---|---|
| 290 | `/get_height` ×35, `/get_o_indexes.bin` ×325, `/get_transactions` ×16, `json_rpc:get_block` ×325, `json_rpc:get_fee_estimate` ×19, `json_rpc:get_version` ×3 | `/get_height` ×35, `/get_o_indexes.bin` ×325, `/submit_transaction` ×12, `json_rpc:get_fee_estimate` ×19 |
| 11,357 | `/get_transactions` ×2, `/submit_transaction` ×1 | `/get_transactions` ×2, `json_rpc:get_block` ×320, `json_rpc:get_version` ×3 |
| 65,535 | `/submit_transaction` ×21 | `/get_transactions` ×32, `json_rpc:get_block` ×5 |

**Where a submission stands**, per class its records fall in:

- 11,357: 1 of its 22 records. In its own direction it shares with wallet sync (2 records); counting both directions it shares with block batch (2 records) and wallet sync (325 records).
- 65,535: 21 of its 22 records. In its own direction it stands alone; counting both directions it shares with block batch (32 records) and wallet sync (5 records).

**Second run in the first run's classes:** **no**: 2 of the second run's 1500 records land in a different class from their first-run counterpart (`json_rpc:get_block` response 2). Its padding under this table: 1,231,518 bytes, 18.3%. The second run's own optimal table at this K differs: 290, 11,379, 65,535.

## K = 4: 290, 11,357, 27,534, 65,535

Overall padding: 629,732 bytes, 9.4% of the payload.

| Method | Direction | Records | Payload | Padding | Padding % |
|---|---|---:|---:|---:|---:|
| `/get_height` | request | 35 | 2,940 | 7,140 | 242.9% |
| `/get_height` | response | 35 | 10,064 | 16 | 0.2% |
| `/get_o_indexes.bin` | request | 325 | 54,600 | 39,000 | 71.4% |
| `/get_o_indexes.bin` | response | 325 | 76,146 | 17,454 | 22.9% |
| `/get_transactions` | request | 18 | 4,542 | 22,776 | 501.5% |
| `/get_transactions` | response | 34 | 1,706,278 | 109,480 | 6.4% |
| `/submit_transaction` | request | 22 | 1,075,227 | 198,318 | 18.4% |
| `/submit_transaction` | response | 12 | 2,484 | 972 | 39.1% |
| `json_rpc:get_block` | request | 325 | 65,949 | 27,651 | 41.9% |
| `json_rpc:get_block` | response | 325 | 3,714,277 | 170,986 | 4.6% |
| `json_rpc:get_fee_estimate` | request | 19 | 2,926 | 2,546 | 87.0% |
| `json_rpc:get_fee_estimate` | response | 19 | 4,997 | 475 | 9.5% |
| `json_rpc:get_version` | request | 3 | 483 | 381 | 78.9% |
| `json_rpc:get_version` | response | 3 | 1,528 | 32,537 | 2129.4% |

| Class | Requests in it | Responses in it |
|---:|---|---|
| 290 | `/get_height` ×35, `/get_o_indexes.bin` ×325, `/get_transactions` ×16, `json_rpc:get_block` ×325, `json_rpc:get_fee_estimate` ×19, `json_rpc:get_version` ×3 | `/get_height` ×35, `/get_o_indexes.bin` ×325, `/submit_transaction` ×12, `json_rpc:get_fee_estimate` ×19 |
| 11,357 | `/get_transactions` ×2, `/submit_transaction` ×1 | `/get_transactions` ×2, `json_rpc:get_block` ×320, `json_rpc:get_version` ×3 |
| 27,534 | `/submit_transaction` ×3 | `/get_transactions` ×8, `json_rpc:get_block` ×2 |
| 65,535 | `/submit_transaction` ×18 | `/get_transactions` ×24, `json_rpc:get_block` ×3 |

**Where a submission stands**, per class its records fall in:

- 11,357: 1 of its 22 records. In its own direction it shares with wallet sync (2 records); counting both directions it shares with block batch (2 records) and wallet sync (325 records).
- 27,534: 3 of its 22 records. In its own direction it stands alone; counting both directions it shares with block batch (8 records) and wallet sync (2 records).
- 65,535: 18 of its 22 records. In its own direction it stands alone; counting both directions it shares with block batch (24 records) and wallet sync (3 records).

**Second run in the first run's classes:** **no**: 2 of the second run's 1500 records land in a different class from their first-run counterpart (`json_rpc:get_block` response 2). Its padding under this table: 661,503 bytes, 9.8%. The second run's own optimal table at this K differs: 290, 11,379, 27,534, 65,535.

## K = 5: 290, 11,357, 27,534, 52,278, 65,535

Overall padding: 444,134 bytes, 6.6% of the payload.

| Method | Direction | Records | Payload | Padding | Padding % |
|---|---|---:|---:|---:|---:|
| `/get_height` | request | 35 | 2,940 | 7,140 | 242.9% |
| `/get_height` | response | 35 | 10,064 | 16 | 0.2% |
| `/get_o_indexes.bin` | request | 325 | 54,600 | 39,000 | 71.4% |
| `/get_o_indexes.bin` | response | 325 | 76,146 | 17,454 | 22.9% |
| `/get_transactions` | request | 18 | 4,542 | 22,776 | 501.5% |
| `/get_transactions` | response | 34 | 1,706,278 | 56,452 | 3.3% |
| `/submit_transaction` | request | 22 | 1,075,227 | 105,519 | 9.8% |
| `/submit_transaction` | response | 12 | 2,484 | 972 | 39.1% |
| `json_rpc:get_block` | request | 325 | 65,949 | 27,651 | 41.9% |
| `json_rpc:get_block` | response | 325 | 3,714,277 | 131,215 | 3.5% |
| `json_rpc:get_fee_estimate` | request | 19 | 2,926 | 2,546 | 87.0% |
| `json_rpc:get_fee_estimate` | response | 19 | 4,997 | 475 | 9.5% |
| `json_rpc:get_version` | request | 3 | 483 | 381 | 78.9% |
| `json_rpc:get_version` | response | 3 | 1,528 | 32,537 | 2129.4% |

| Class | Requests in it | Responses in it |
|---:|---|---|
| 290 | `/get_height` ×35, `/get_o_indexes.bin` ×325, `/get_transactions` ×16, `json_rpc:get_block` ×325, `json_rpc:get_fee_estimate` ×19, `json_rpc:get_version` ×3 | `/get_height` ×35, `/get_o_indexes.bin` ×325, `/submit_transaction` ×12, `json_rpc:get_fee_estimate` ×19 |
| 11,357 | `/get_transactions` ×2, `/submit_transaction` ×1 | `/get_transactions` ×2, `json_rpc:get_block` ×320, `json_rpc:get_version` ×3 |
| 27,534 | `/submit_transaction` ×3 | `/get_transactions` ×8, `json_rpc:get_block` ×2 |
| 52,278 | `/submit_transaction` ×7 | `/get_transactions` ×4, `json_rpc:get_block` ×3 |
| 65,535 | `/submit_transaction` ×11 | `/get_transactions` ×20 |

**Where a submission stands**, per class its records fall in:

- 11,357: 1 of its 22 records. In its own direction it shares with wallet sync (2 records); counting both directions it shares with block batch (2 records) and wallet sync (325 records).
- 27,534: 3 of its 22 records. In its own direction it stands alone; counting both directions it shares with block batch (8 records) and wallet sync (2 records).
- 52,278: 7 of its 22 records. In its own direction it stands alone; counting both directions it shares with block batch (4 records) and wallet sync (3 records).
- 65,535: 11 of its 22 records. In its own direction it stands alone; counting both directions it shares with block batch (20 records).

**Second run in the first run's classes:** **no**: 2 of the second run's 1500 records land in a different class from their first-run counterpart (`json_rpc:get_block` response 2). Its padding under this table: 475,905 bytes, 7.1%. The second run's own optimal table at this K differs: 290, 11,379, 27,534, 52,278, 65,535.

## K = 6: 236, 512, 11,357, 27,534, 52,278, 65,535

Overall padding: 345,485 bytes, 5.1% of the payload.

| Method | Direction | Records | Payload | Padding | Padding % |
|---|---|---:|---:|---:|---:|
| `/get_height` | request | 35 | 2,940 | 5,250 | 178.6% |
| `/get_height` | response | 35 | 10,064 | 7,786 | 77.4% |
| `/get_o_indexes.bin` | request | 325 | 54,600 | 21,450 | 39.3% |
| `/get_o_indexes.bin` | response | 325 | 76,146 | 732 | 1.0% |
| `/get_transactions` | request | 18 | 4,542 | 222 | 4.9% |
| `/get_transactions` | response | 34 | 1,706,278 | 56,452 | 3.3% |
| `/submit_transaction` | request | 22 | 1,075,227 | 105,519 | 9.8% |
| `/submit_transaction` | response | 12 | 2,484 | 324 | 13.0% |
| `json_rpc:get_block` | request | 325 | 65,949 | 10,101 | 15.3% |
| `json_rpc:get_block` | response | 325 | 3,714,277 | 131,215 | 3.5% |
| `json_rpc:get_fee_estimate` | request | 19 | 2,926 | 1,520 | 51.9% |
| `json_rpc:get_fee_estimate` | response | 19 | 4,997 | 4,693 | 93.9% |
| `json_rpc:get_version` | request | 3 | 483 | 219 | 45.3% |
| `json_rpc:get_version` | response | 3 | 1,528 | 2 | 0.1% |

| Class | Requests in it | Responses in it |
|---:|---|---|
| 236 | `/get_height` ×35, `/get_o_indexes.bin` ×325, `/get_transactions` ×16, `json_rpc:get_block` ×325, `json_rpc:get_fee_estimate` ×19, `json_rpc:get_version` ×3 | `/get_o_indexes.bin` ×322, `/submit_transaction` ×12 |
| 512 | `/get_transactions` ×2 | `/get_height` ×35, `/get_o_indexes.bin` ×3, `json_rpc:get_fee_estimate` ×19, `json_rpc:get_version` ×3 |
| 11,357 | `/submit_transaction` ×1 | `/get_transactions` ×2, `json_rpc:get_block` ×320 |
| 27,534 | `/submit_transaction` ×3 | `/get_transactions` ×8, `json_rpc:get_block` ×2 |
| 52,278 | `/submit_transaction` ×7 | `/get_transactions` ×4, `json_rpc:get_block` ×3 |
| 65,535 | `/submit_transaction` ×11 | `/get_transactions` ×20 |

**Where a submission stands**, per class its records fall in:

- 11,357: 1 of its 22 records. In its own direction it stands alone; counting both directions it shares with block batch (2 records) and wallet sync (320 records).
- 27,534: 3 of its 22 records. In its own direction it stands alone; counting both directions it shares with block batch (8 records) and wallet sync (2 records).
- 52,278: 7 of its 22 records. In its own direction it stands alone; counting both directions it shares with block batch (4 records) and wallet sync (3 records).
- 65,535: 11 of its 22 records. In its own direction it stands alone; counting both directions it shares with block batch (20 records).

**Second run in the first run's classes:** **no**: 2 of the second run's 1500 records land in a different class from their first-run counterpart (`json_rpc:get_block` response 2). Its padding under this table: 377,256 bytes, 5.6%. The second run's own optimal table at this K differs: 236, 512, 11,379, 27,534, 52,278, 65,535.

## K = 7: 236, 512, 11,144, 11,882, 27,534, 52,278, 65,535

Overall padding: 257,190 bytes, 3.8% of the payload.

| Method | Direction | Records | Payload | Padding | Padding % |
|---|---|---:|---:|---:|---:|
| `/get_height` | request | 35 | 2,940 | 5,250 | 178.6% |
| `/get_height` | response | 35 | 10,064 | 7,786 | 77.4% |
| `/get_o_indexes.bin` | request | 325 | 54,600 | 21,450 | 39.3% |
| `/get_o_indexes.bin` | response | 325 | 76,146 | 732 | 1.0% |
| `/get_transactions` | request | 18 | 4,542 | 222 | 4.9% |
| `/get_transactions` | response | 34 | 1,706,278 | 56,026 | 3.3% |
| `/submit_transaction` | request | 22 | 1,075,227 | 105,306 | 9.8% |
| `/submit_transaction` | response | 12 | 2,484 | 324 | 13.0% |
| `json_rpc:get_block` | request | 325 | 65,949 | 10,101 | 15.3% |
| `json_rpc:get_block` | response | 325 | 3,714,277 | 43,559 | 1.2% |
| `json_rpc:get_fee_estimate` | request | 19 | 2,926 | 1,520 | 51.9% |
| `json_rpc:get_fee_estimate` | response | 19 | 4,997 | 4,693 | 93.9% |
| `json_rpc:get_version` | request | 3 | 483 | 219 | 45.3% |
| `json_rpc:get_version` | response | 3 | 1,528 | 2 | 0.1% |

| Class | Requests in it | Responses in it |
|---:|---|---|
| 236 | `/get_height` ×35, `/get_o_indexes.bin` ×325, `/get_transactions` ×16, `json_rpc:get_block` ×325, `json_rpc:get_fee_estimate` ×19, `json_rpc:get_version` ×3 | `/get_o_indexes.bin` ×322, `/submit_transaction` ×12 |
| 512 | `/get_transactions` ×2 | `/get_height` ×35, `/get_o_indexes.bin` ×3, `json_rpc:get_fee_estimate` ×19, `json_rpc:get_version` ×3 |
| 11,144 | `/submit_transaction` ×1 | `/get_transactions` ×2, `json_rpc:get_block` ×304 |
| 11,882 | — | `json_rpc:get_block` ×18 |
| 27,534 | `/submit_transaction` ×3 | `/get_transactions` ×8 |
| 52,278 | `/submit_transaction` ×7 | `/get_transactions` ×4, `json_rpc:get_block` ×3 |
| 65,535 | `/submit_transaction` ×11 | `/get_transactions` ×20 |

**Where a submission stands**, per class its records fall in:

- 11,144: 1 of its 22 records. In its own direction it stands alone; counting both directions it shares with block batch (2 records) and wallet sync (304 records).
- 27,534: 3 of its 22 records. In its own direction it stands alone; counting both directions it shares with block batch (8 records).
- 52,278: 7 of its 22 records. In its own direction it stands alone; counting both directions it shares with block batch (4 records) and wallet sync (3 records).
- 65,535: 11 of its 22 records. In its own direction it stands alone; counting both directions it shares with block batch (20 records).

**Second run in the first run's classes:** **no**: 10 of the second run's 1500 records land in a different class from their first-run counterpart (`json_rpc:get_block` response 10). Its padding under this table: 293,815 bytes, 4.4%. The second run's own optimal table at this K differs: 236, 512, 11,158, 11,925, 27,534, 52,278, 65,535.

## K = 8: 236, 512, 11,144, 11,882, 27,534, 44,914, 52,278, 65,535

Overall padding: 190,914 bytes, 2.8% of the payload.

| Method | Direction | Records | Payload | Padding | Padding % |
|---|---|---:|---:|---:|---:|
| `/get_height` | request | 35 | 2,940 | 5,250 | 178.6% |
| `/get_height` | response | 35 | 10,064 | 7,786 | 77.4% |
| `/get_o_indexes.bin` | request | 325 | 54,600 | 21,450 | 39.3% |
| `/get_o_indexes.bin` | response | 325 | 76,146 | 732 | 1.0% |
| `/get_transactions` | request | 18 | 4,542 | 222 | 4.9% |
| `/get_transactions` | response | 34 | 1,706,278 | 56,026 | 3.3% |
| `/submit_transaction` | request | 22 | 1,075,227 | 61,122 | 5.7% |
| `/submit_transaction` | response | 12 | 2,484 | 324 | 13.0% |
| `json_rpc:get_block` | request | 325 | 65,949 | 10,101 | 15.3% |
| `json_rpc:get_block` | response | 325 | 3,714,277 | 21,467 | 0.6% |
| `json_rpc:get_fee_estimate` | request | 19 | 2,926 | 1,520 | 51.9% |
| `json_rpc:get_fee_estimate` | response | 19 | 4,997 | 4,693 | 93.9% |
| `json_rpc:get_version` | request | 3 | 483 | 219 | 45.3% |
| `json_rpc:get_version` | response | 3 | 1,528 | 2 | 0.1% |

| Class | Requests in it | Responses in it |
|---:|---|---|
| 236 | `/get_height` ×35, `/get_o_indexes.bin` ×325, `/get_transactions` ×16, `json_rpc:get_block` ×325, `json_rpc:get_fee_estimate` ×19, `json_rpc:get_version` ×3 | `/get_o_indexes.bin` ×322, `/submit_transaction` ×12 |
| 512 | `/get_transactions` ×2 | `/get_height` ×35, `/get_o_indexes.bin` ×3, `json_rpc:get_fee_estimate` ×19, `json_rpc:get_version` ×3 |
| 11,144 | `/submit_transaction` ×1 | `/get_transactions` ×2, `json_rpc:get_block` ×304 |
| 11,882 | — | `json_rpc:get_block` ×18 |
| 27,534 | `/submit_transaction` ×3 | `/get_transactions` ×8 |
| 44,914 | `/submit_transaction` ×6 | `json_rpc:get_block` ×3 |
| 52,278 | `/submit_transaction` ×1 | `/get_transactions` ×4 |
| 65,535 | `/submit_transaction` ×11 | `/get_transactions` ×20 |

**Where a submission stands**, per class its records fall in:

- 11,144: 1 of its 22 records. In its own direction it stands alone; counting both directions it shares with block batch (2 records) and wallet sync (304 records).
- 27,534: 3 of its 22 records. In its own direction it stands alone; counting both directions it shares with block batch (8 records).
- 44,914: 6 of its 22 records. In its own direction it stands alone; counting both directions it shares with wallet sync (3 records).
- 52,278: 1 of its 22 records. In its own direction it stands alone; counting both directions it shares with block batch (4 records).
- 65,535: 11 of its 22 records. In its own direction it stands alone; counting both directions it shares with block batch (20 records).

**Second run in the first run's classes:** **no**: 10 of the second run's 1500 records land in a different class from their first-run counterpart (`json_rpc:get_block` response 10). Its padding under this table: 227,539 bytes, 3.4%. The second run's own optimal table at this K differs: 236, 512, 11,158, 11,925, 27,534, 44,914, 52,278, 65,535.

