# RT-P5: the candidate tables, per method

Tables are the first registered run's, by the registered rule. Records: 797 in the first run, 797 in the second. Padding is the bytes added to bring each record to its class; the percentage is of that method's payload (the record bytes less the two-byte occupancy).

Categories: a **block batch** is a `block_show` response (one block being synced, with its transactions); **wallet sync** is every other message of a refresh (`chain_height`, `version`, and the `block_show` request among them); **spend building** is `fee`; a **submission** is a `tx_submit` request. A path observer sees each record's direction, so where a submission stands is given in its own direction first.

## K = 1: 65,535

Overall padding: 49,980,724 bytes, 2222.3% of the payload.

| Method | Direction | Records | Payload | Padding | Padding % |
|---|---|---:|---:|---:|---:|
| `json_rpc:block_show` | request | 325 | 63,704 | 21,234,521 | 33333.1% |
| `json_rpc:block_show` | response | 327 | 1,437,406 | 19,991,885 | 1390.8% |
| `json_rpc:chain_height` | request | 35 | 5,670 | 2,287,985 | 40352.5% |
| `json_rpc:chain_height` | response | 35 | 11,568 | 2,282,087 | 19727.6% |
| `json_rpc:fee` | request | 19 | 2,907 | 1,242,220 | 42732.0% |
| `json_rpc:fee` | response | 19 | 5,206 | 1,239,921 | 23817.2% |
| `json_rpc:tx_submit` | request | 19 | 717,845 | 527,282 | 73.5% |
| `json_rpc:tx_submit` | response | 12 | 2,892 | 783,504 | 27092.1% |
| `json_rpc:version` | request | 3 | 471 | 196,128 | 41640.8% |
| `json_rpc:version` | response | 3 | 1,408 | 195,191 | 13863.0% |

| Class | Requests in it | Responses in it |
|---:|---|---|
| 65,535 | `json_rpc:block_show` ×325, `json_rpc:chain_height` ×35, `json_rpc:fee` ×19, `json_rpc:tx_submit` ×19, `json_rpc:version` ×3 | `json_rpc:block_show` ×327, `json_rpc:chain_height` ×35, `json_rpc:fee` ×19, `json_rpc:tx_submit` ×12, `json_rpc:version` ×3 |

**Where a submission stands**, per class its records fall in:

- 65,535: 19 of its 19 records. In its own direction it shares with wallet sync (363 records) and spend building (19 records); counting both directions it shares with block batch (327 records) and wallet sync (401 records) and spend building (38 records) and submission reply (12 records).

**Second run in the first run's classes:** **yes**: every one of the second run's 797 records lands in the same class as its first-run counterpart. Its padding under this table: 49,980,861 bytes, 2222.4%. The second run's own optimal table at this K is the same.

## K = 2: 2,905, 65,535

Overall padding: 2,695,074 bytes, 119.8% of the payload.

| Method | Direction | Records | Payload | Padding | Padding % |
|---|---|---:|---:|---:|---:|
| `json_rpc:block_show` | request | 325 | 63,704 | 879,771 | 1381.0% |
| `json_rpc:block_show` | response | 327 | 1,437,406 | 952,365 | 66.3% |
| `json_rpc:chain_height` | request | 35 | 5,670 | 95,935 | 1692.0% |
| `json_rpc:chain_height` | response | 35 | 11,568 | 90,037 | 778.3% |
| `json_rpc:fee` | request | 19 | 2,907 | 52,250 | 1797.4% |
| `json_rpc:fee` | response | 19 | 5,206 | 49,951 | 959.5% |
| `json_rpc:tx_submit` | request | 19 | 717,845 | 527,282 | 73.5% |
| `json_rpc:tx_submit` | response | 12 | 2,892 | 31,944 | 1104.6% |
| `json_rpc:version` | request | 3 | 471 | 8,238 | 1749.0% |
| `json_rpc:version` | response | 3 | 1,408 | 7,301 | 518.5% |

| Class | Requests in it | Responses in it |
|---:|---|---|
| 2,905 | `json_rpc:block_show` ×325, `json_rpc:chain_height` ×35, `json_rpc:fee` ×19, `json_rpc:version` ×3 | `json_rpc:block_show` ×304, `json_rpc:chain_height` ×35, `json_rpc:fee` ×19, `json_rpc:tx_submit` ×12, `json_rpc:version` ×3 |
| 65,535 | `json_rpc:tx_submit` ×19 | `json_rpc:block_show` ×23 |

**Where a submission stands**, per class its records fall in:

- 65,535: 19 of its 19 records. In its own direction it stands alone; counting both directions it shares with block batch (23 records).

**Second run in the first run's classes:** **yes**: every one of the second run's 797 records lands in the same class as its first-run counterpart. Its padding under this table: 2,695,211 bytes, 119.8%. The second run's own optimal table at this K is the same.

## K = 3: 333, 2,905, 65,535

Overall padding: 1,542,818 bytes, 68.6% of the payload.

| Method | Direction | Records | Payload | Padding | Padding % |
|---|---|---:|---:|---:|---:|
| `json_rpc:block_show` | request | 325 | 63,704 | 43,871 | 68.9% |
| `json_rpc:block_show` | response | 327 | 1,437,406 | 952,365 | 66.3% |
| `json_rpc:chain_height` | request | 35 | 5,670 | 5,915 | 104.3% |
| `json_rpc:chain_height` | response | 35 | 11,568 | 17 | 0.1% |
| `json_rpc:fee` | request | 19 | 2,907 | 3,382 | 116.3% |
| `json_rpc:fee` | response | 19 | 5,206 | 1,083 | 20.8% |
| `json_rpc:tx_submit` | request | 19 | 717,845 | 527,282 | 73.5% |
| `json_rpc:tx_submit` | response | 12 | 2,892 | 1,080 | 37.3% |
| `json_rpc:version` | request | 3 | 471 | 522 | 110.8% |
| `json_rpc:version` | response | 3 | 1,408 | 7,301 | 518.5% |

| Class | Requests in it | Responses in it |
|---:|---|---|
| 333 | `json_rpc:block_show` ×325, `json_rpc:chain_height` ×35, `json_rpc:fee` ×19, `json_rpc:version` ×3 | `json_rpc:chain_height` ×35, `json_rpc:fee` ×19, `json_rpc:tx_submit` ×12 |
| 2,905 | — | `json_rpc:block_show` ×304, `json_rpc:version` ×3 |
| 65,535 | `json_rpc:tx_submit` ×19 | `json_rpc:block_show` ×23 |

**Where a submission stands**, per class its records fall in:

- 65,535: 19 of its 19 records. In its own direction it stands alone; counting both directions it shares with block batch (23 records).

**Second run in the first run's classes:** **yes**: every one of the second run's 797 records lands in the same class as its first-run counterpart. Its padding under this table: 1,542,955 bytes, 68.6%. The second run's own optimal table at this K is the same.

## K = 4: 333, 2,905, 30,781, 65,535

Overall padding: 604,460 bytes, 26.9% of the payload.

| Method | Direction | Records | Payload | Padding | Padding % |
|---|---|---:|---:|---:|---:|
| `json_rpc:block_show` | request | 325 | 63,704 | 43,871 | 68.9% |
| `json_rpc:block_show` | response | 327 | 1,437,406 | 292,039 | 20.3% |
| `json_rpc:chain_height` | request | 35 | 5,670 | 5,915 | 104.3% |
| `json_rpc:chain_height` | response | 35 | 11,568 | 17 | 0.1% |
| `json_rpc:fee` | request | 19 | 2,907 | 3,382 | 116.3% |
| `json_rpc:fee` | response | 19 | 5,206 | 1,083 | 20.8% |
| `json_rpc:tx_submit` | request | 19 | 717,845 | 249,250 | 34.7% |
| `json_rpc:tx_submit` | response | 12 | 2,892 | 1,080 | 37.3% |
| `json_rpc:version` | request | 3 | 471 | 522 | 110.8% |
| `json_rpc:version` | response | 3 | 1,408 | 7,301 | 518.5% |

| Class | Requests in it | Responses in it |
|---:|---|---|
| 333 | `json_rpc:block_show` ×325, `json_rpc:chain_height` ×35, `json_rpc:fee` ×19, `json_rpc:version` ×3 | `json_rpc:chain_height` ×35, `json_rpc:fee` ×19, `json_rpc:tx_submit` ×12 |
| 2,905 | — | `json_rpc:block_show` ×304, `json_rpc:version` ×3 |
| 30,781 | `json_rpc:tx_submit` ×8 | `json_rpc:block_show` ×19 |
| 65,535 | `json_rpc:tx_submit` ×11 | `json_rpc:block_show` ×4 |

**Where a submission stands**, per class its records fall in:

- 30,781: 8 of its 19 records. In its own direction it stands alone; counting both directions it shares with block batch (19 records).
- 65,535: 11 of its 19 records. In its own direction it stands alone; counting both directions it shares with block batch (4 records).

**Second run in the first run's classes:** **yes**: every one of the second run's 797 records lands in the same class as its first-run counterpart. Its padding under this table: 604,597 bytes, 26.9%. The second run's own optimal table at this K differs: 333, 2,905, 30,780, 65,535.

## K = 5: 333, 2,905, 9,699, 30,781, 65,535

Overall padding: 267,148 bytes, 11.9% of the payload.

| Method | Direction | Records | Payload | Padding | Padding % |
|---|---|---:|---:|---:|---:|
| `json_rpc:block_show` | request | 325 | 63,704 | 43,871 | 68.9% |
| `json_rpc:block_show` | response | 327 | 1,437,406 | 60,137 | 4.2% |
| `json_rpc:chain_height` | request | 35 | 5,670 | 5,915 | 104.3% |
| `json_rpc:chain_height` | response | 35 | 11,568 | 17 | 0.1% |
| `json_rpc:fee` | request | 19 | 2,907 | 3,382 | 116.3% |
| `json_rpc:fee` | response | 19 | 5,206 | 1,083 | 20.8% |
| `json_rpc:tx_submit` | request | 19 | 717,845 | 143,840 | 20.0% |
| `json_rpc:tx_submit` | response | 12 | 2,892 | 1,080 | 37.3% |
| `json_rpc:version` | request | 3 | 471 | 522 | 110.8% |
| `json_rpc:version` | response | 3 | 1,408 | 7,301 | 518.5% |

| Class | Requests in it | Responses in it |
|---:|---|---|
| 333 | `json_rpc:block_show` ×325, `json_rpc:chain_height` ×35, `json_rpc:fee` ×19, `json_rpc:version` ×3 | `json_rpc:chain_height` ×35, `json_rpc:fee` ×19, `json_rpc:tx_submit` ×12 |
| 2,905 | — | `json_rpc:block_show` ×304, `json_rpc:version` ×3 |
| 9,699 | `json_rpc:tx_submit` ×5 | `json_rpc:block_show` ×11 |
| 30,781 | `json_rpc:tx_submit` ×3 | `json_rpc:block_show` ×8 |
| 65,535 | `json_rpc:tx_submit` ×11 | `json_rpc:block_show` ×4 |

**Where a submission stands**, per class its records fall in:

- 9,699: 5 of its 19 records. In its own direction it stands alone; counting both directions it shares with block batch (11 records).
- 30,781: 3 of its 19 records. In its own direction it stands alone; counting both directions it shares with block batch (8 records).
- 65,535: 11 of its 19 records. In its own direction it stands alone; counting both directions it shares with block batch (4 records).

**Second run in the first run's classes:** **yes**: every one of the second run's 797 records lands in the same class as its first-run counterpart. Its padding under this table: 267,285 bytes, 11.9%. The second run's own optimal table at this K differs: 333, 2,905, 9,699, 30,780, 65,535.

## K = 6: 333, 2,905, 9,699, 30,781, 48,121, 65,535

Overall padding: 180,078 bytes, 8.0% of the payload.

| Method | Direction | Records | Payload | Padding | Padding % |
|---|---|---:|---:|---:|---:|
| `json_rpc:block_show` | request | 325 | 63,704 | 43,871 | 68.9% |
| `json_rpc:block_show` | response | 327 | 1,437,406 | 25,309 | 1.8% |
| `json_rpc:chain_height` | request | 35 | 5,670 | 5,915 | 104.3% |
| `json_rpc:chain_height` | response | 35 | 11,568 | 17 | 0.1% |
| `json_rpc:fee` | request | 19 | 2,907 | 3,382 | 116.3% |
| `json_rpc:fee` | response | 19 | 5,206 | 1,083 | 20.8% |
| `json_rpc:tx_submit` | request | 19 | 717,845 | 91,598 | 12.8% |
| `json_rpc:tx_submit` | response | 12 | 2,892 | 1,080 | 37.3% |
| `json_rpc:version` | request | 3 | 471 | 522 | 110.8% |
| `json_rpc:version` | response | 3 | 1,408 | 7,301 | 518.5% |

| Class | Requests in it | Responses in it |
|---:|---|---|
| 333 | `json_rpc:block_show` ×325, `json_rpc:chain_height` ×35, `json_rpc:fee` ×19, `json_rpc:version` ×3 | `json_rpc:chain_height` ×35, `json_rpc:fee` ×19, `json_rpc:tx_submit` ×12 |
| 2,905 | — | `json_rpc:block_show` ×304, `json_rpc:version` ×3 |
| 9,699 | `json_rpc:tx_submit` ×5 | `json_rpc:block_show` ×11 |
| 30,781 | `json_rpc:tx_submit` ×3 | `json_rpc:block_show` ×8 |
| 48,121 | `json_rpc:tx_submit` ×3 | `json_rpc:block_show` ×2 |
| 65,535 | `json_rpc:tx_submit` ×8 | `json_rpc:block_show` ×2 |

**Where a submission stands**, per class its records fall in:

- 9,699: 5 of its 19 records. In its own direction it stands alone; counting both directions it shares with block batch (11 records).
- 30,781: 3 of its 19 records. In its own direction it stands alone; counting both directions it shares with block batch (8 records).
- 48,121: 3 of its 19 records. In its own direction it stands alone; counting both directions it shares with block batch (2 records).
- 65,535: 8 of its 19 records. In its own direction it stands alone; counting both directions it shares with block batch (2 records).

**Second run in the first run's classes:** **yes**: every one of the second run's 797 records lands in the same class as its first-run counterpart. Its padding under this table: 180,215 bytes, 8.0%. The second run's own optimal table at this K differs: 333, 2,905, 9,699, 30,780, 48,120, 65,535.

## K = 7: 199, 333, 2,905, 9,699, 30,781, 48,121, 65,535

Overall padding: 128,890 bytes, 5.7% of the payload.

| Method | Direction | Records | Payload | Padding | Padding % |
|---|---|---:|---:|---:|---:|
| `json_rpc:block_show` | request | 325 | 63,704 | 321 | 0.5% |
| `json_rpc:block_show` | response | 327 | 1,437,406 | 25,309 | 1.8% |
| `json_rpc:chain_height` | request | 35 | 5,670 | 1,225 | 21.6% |
| `json_rpc:chain_height` | response | 35 | 11,568 | 17 | 0.1% |
| `json_rpc:fee` | request | 19 | 2,907 | 836 | 28.8% |
| `json_rpc:fee` | response | 19 | 5,206 | 1,083 | 20.8% |
| `json_rpc:tx_submit` | request | 19 | 717,845 | 91,598 | 12.8% |
| `json_rpc:tx_submit` | response | 12 | 2,892 | 1,080 | 37.3% |
| `json_rpc:version` | request | 3 | 471 | 120 | 25.5% |
| `json_rpc:version` | response | 3 | 1,408 | 7,301 | 518.5% |

| Class | Requests in it | Responses in it |
|---:|---|---|
| 199 | `json_rpc:block_show` ×325, `json_rpc:chain_height` ×35, `json_rpc:fee` ×19, `json_rpc:version` ×3 | — |
| 333 | — | `json_rpc:chain_height` ×35, `json_rpc:fee` ×19, `json_rpc:tx_submit` ×12 |
| 2,905 | — | `json_rpc:block_show` ×304, `json_rpc:version` ×3 |
| 9,699 | `json_rpc:tx_submit` ×5 | `json_rpc:block_show` ×11 |
| 30,781 | `json_rpc:tx_submit` ×3 | `json_rpc:block_show` ×8 |
| 48,121 | `json_rpc:tx_submit` ×3 | `json_rpc:block_show` ×2 |
| 65,535 | `json_rpc:tx_submit` ×8 | `json_rpc:block_show` ×2 |

**Where a submission stands**, per class its records fall in:

- 9,699: 5 of its 19 records. In its own direction it stands alone; counting both directions it shares with block batch (11 records).
- 30,781: 3 of its 19 records. In its own direction it stands alone; counting both directions it shares with block batch (8 records).
- 48,121: 3 of its 19 records. In its own direction it stands alone; counting both directions it shares with block batch (2 records).
- 65,535: 8 of its 19 records. In its own direction it stands alone; counting both directions it shares with block batch (2 records).

**Second run in the first run's classes:** **yes**: every one of the second run's 797 records lands in the same class as its first-run counterpart. Its padding under this table: 129,027 bytes, 5.7%. The second run's own optimal table at this K differs: 199, 333, 2,905, 9,699, 30,780, 48,120, 65,535.

## K = 8: 199, 333, 2,905, 7,088, 13,068, 30,781, 48,121, 65,535

Overall padding: 87,341 bytes, 3.9% of the payload.

| Method | Direction | Records | Payload | Padding | Padding % |
|---|---|---:|---:|---:|---:|
| `json_rpc:block_show` | request | 325 | 63,704 | 321 | 0.5% |
| `json_rpc:block_show` | response | 327 | 1,437,406 | 14,528 | 1.0% |
| `json_rpc:chain_height` | request | 35 | 5,670 | 1,225 | 21.6% |
| `json_rpc:chain_height` | response | 35 | 11,568 | 17 | 0.1% |
| `json_rpc:fee` | request | 19 | 2,907 | 836 | 28.8% |
| `json_rpc:fee` | response | 19 | 5,206 | 1,083 | 20.8% |
| `json_rpc:tx_submit` | request | 19 | 717,845 | 60,830 | 8.5% |
| `json_rpc:tx_submit` | response | 12 | 2,892 | 1,080 | 37.3% |
| `json_rpc:version` | request | 3 | 471 | 120 | 25.5% |
| `json_rpc:version` | response | 3 | 1,408 | 7,301 | 518.5% |

| Class | Requests in it | Responses in it |
|---:|---|---|
| 199 | `json_rpc:block_show` ×325, `json_rpc:chain_height` ×35, `json_rpc:fee` ×19, `json_rpc:version` ×3 | — |
| 333 | — | `json_rpc:chain_height` ×35, `json_rpc:fee` ×19, `json_rpc:tx_submit` ×12 |
| 2,905 | — | `json_rpc:block_show` ×304, `json_rpc:version` ×3 |
| 7,088 | `json_rpc:tx_submit` ×5 | `json_rpc:block_show` ×8 |
| 13,068 | `json_rpc:tx_submit` ×1 | `json_rpc:block_show` ×3 |
| 30,781 | `json_rpc:tx_submit` ×2 | `json_rpc:block_show` ×8 |
| 48,121 | `json_rpc:tx_submit` ×3 | `json_rpc:block_show` ×2 |
| 65,535 | `json_rpc:tx_submit` ×8 | `json_rpc:block_show` ×2 |

**Where a submission stands**, per class its records fall in:

- 7,088: 5 of its 19 records. In its own direction it stands alone; counting both directions it shares with block batch (8 records).
- 13,068: 1 of its 19 records. In its own direction it stands alone; counting both directions it shares with block batch (3 records).
- 30,781: 2 of its 19 records. In its own direction it stands alone; counting both directions it shares with block batch (8 records).
- 48,121: 3 of its 19 records. In its own direction it stands alone; counting both directions it shares with block batch (2 records).
- 65,535: 8 of its 19 records. In its own direction it stands alone; counting both directions it shares with block batch (2 records).

**Second run in the first run's classes:** **yes**: every one of the second run's 797 records lands in the same class as its first-run counterpart. Its padding under this table: 87,478 bytes, 3.9%. The second run's own optimal table at this K differs: 199, 333, 2,905, 7,079, 13,068, 30,780, 48,120, 65,535.

