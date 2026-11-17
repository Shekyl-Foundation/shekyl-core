# RT-P5 classes: `registered` cell

Chain height 117; curve tree {"height": 116, "layers": 1, "leaf_count": 125, "root": "b494f96270a2fc2b5daa97d345e985f241dbe06d3466b7789a954018a41d1596"}.

788 messages, 797 records.

## HTTP message sizes per method

| Method | Direction | Count | Min | Median | Max | Records |
|---|---|---:|---:|---:|---:|---:|
| `json_rpc:block_show` | request | 325 | 195 | 196 | 197 | 325 |
| `json_rpc:block_show` | response | 325 | 2,888 | 2,900 | 113,652 | 327 |
| `json_rpc:chain_height` | request | 35 | 162 | 162 | 162 | 35 |
| `json_rpc:chain_height` | response | 35 | 330 | 331 | 331 | 35 |
| `json_rpc:fee` | request | 19 | 153 | 153 | 153 | 19 |
| `json_rpc:fee` | response | 19 | 274 | 274 | 274 | 19 |
| `json_rpc:tx_submit` | request | 12 | 17,819 | 70,031 | 102,544 | 19 |
| `json_rpc:tx_submit` | response | 12 | 241 | 241 | 241 | 12 |
| `json_rpc:version` | request | 3 | 157 | 157 | 157 | 3 |
| `json_rpc:version` | response | 3 | 469 | 469 | 470 | 3 |

## Candidate tables

Padding is the bytes added to reach each record's class, over every record in the trace. The largest class is fixed at 65,535.

| K | Classes | Padding | Padding / payload |
|---:|---|---:|---:|
| 1 | 65,535 | 49,980,724 | 2222.3% |
| 2 | 2,905, 65,535 | 2,695,074 | 119.8% |
| 3 | 333, 2,905, 65,535 | 1,542,818 | 68.6% |
| 4 | 333, 2,905, 30,781, 65,535 | 604,460 | 26.9% |
| 5 | 333, 2,905, 9,699, 30,781, 65,535 | 267,148 | 11.9% |
| 6 | 333, 2,905, 9,699, 30,781, 48,121, 65,535 | 180,078 | 8.0% |
| 7 | 199, 333, 2,905, 9,699, 30,781, 48,121, 65,535 | 128,890 | 5.7% |
| 8 | 199, 333, 2,905, 7,088, 13,068, 30,781, 48,121, 65,535 | 87,341 | 3.9% |

## What shares a submission's class

For each K, the classes a submission request's records fall in, and every other method and direction with records in those classes (records counted).

- **K = 1**: submission records in 65,535; shared with `json_rpc:block_show` request ×325, `json_rpc:block_show` response ×327, `json_rpc:chain_height` request ×35, `json_rpc:chain_height` response ×35, `json_rpc:fee` request ×19, `json_rpc:fee` response ×19, `json_rpc:tx_submit` response ×12, `json_rpc:version` request ×3, `json_rpc:version` response ×3.
- **K = 2**: submission records in 65,535; shared with `json_rpc:block_show` response ×23.
- **K = 3**: submission records in 65,535; shared with `json_rpc:block_show` response ×23.
- **K = 4**: submission records in 30,781, 65,535; shared with `json_rpc:block_show` response ×23.
- **K = 5**: submission records in 9,699, 30,781, 65,535; shared with `json_rpc:block_show` response ×23.
- **K = 6**: submission records in 9,699, 30,781, 48,121, 65,535; shared with `json_rpc:block_show` response ×23.
- **K = 7**: submission records in 9,699, 30,781, 48,121, 65,535; shared with `json_rpc:block_show` response ×23.
- **K = 8**: submission records in 7,088, 13,068, 30,781, 48,121, 65,535; shared with `json_rpc:block_show` response ×23.

## A submission at greater tree depth

The submission bodies do not fit one encoding of the transaction bytes; no projection is made.
