Recorded from the epee host at `88a202195`. That commit contains the
deadline clocks (`0ca144aa0`, `45929ffcf`).

Each seed is two transcripts, `seed-<n>-peer.txt` and `seed-<n>-host.txt`.
The first line is the transcript version. The fields are the parity
scope: wire bytes and the session outcome. Events are omitted. A
send-over suffix past the script's handshake response is omitted.
The six deferred invariants are not transcript fields.
Option-off goldens; re-recorded at the flip per §Goldens.
