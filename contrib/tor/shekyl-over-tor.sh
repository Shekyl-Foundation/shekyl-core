#!/bin/bash

DIR=$(realpath $(dirname $0))

echo "Checking shekyld..."
shekyld=""
for dir in \
  . \
  "$DIR" \
  "$DIR/../.." \
  "$DIR/build/release/bin" \
  "$DIR/../../build/release/bin" \
  "$DIR/build/Linux/master/release/bin" \
  "$DIR/../../build/Linux/master/release/bin" \
  "$DIR/build/Windows/master/release/bin" \
  "$DIR/../../build/Windows/master/release/bin"
do
  if test -x "$dir/shekyld"
  then
    shekyld="$dir/shekyld"
    break
  fi
done
if test -z "$shekyld"
then
  echo "shekyld not found"
  exit 1
fi
echo "Found: $shekyld"

TORDIR="$DIR/shekyl-over-tor"
TORRC="$TORDIR/torrc"
HOSTNAMEFILE="$TORDIR/hostname"
echo "Creating configuration..."
mkdir -p "$TORDIR"
chmod 700 "$TORDIR"
rm -f "$TORRC"
cat << EOF > "$TORRC"
ControlSocket $TORDIR/control
ControlSocketsGroupWritable 1
CookieAuthentication 1
CookieAuthFile $TORDIR/control.authcookie
CookieAuthFileGroupReadable 1
HiddenServiceDir $TORDIR
HiddenServicePort 18083 127.0.0.1:18083
EOF

echo "Starting Tor..."
nohup tor -f "$TORRC" 2> "$TORDIR/tor.stderr" 1> "$TORDIR/tor.stdout" &
ready=0
for i in `seq 10`
do
  sleep 1
  if test -f "$HOSTNAMEFILE"
  then
    ready=1
    break
  fi
done
if test "$ready" = 0
then
  echo "Error starting Tor"
  cat "$TORDIR/tor.stdout"
  exit 1
fi

echo "Starting shekyld..."
HOSTNAME=$(cat "$HOSTNAMEFILE")
"$shekyld" \
  --anonymous-inbound "$HOSTNAME":18083,127.0.0.1:18083,25 --tx-proxy tor,127.0.0.1:9050 \
  --detach
ready=0
for i in `seq 10`
do
  sleep 1
  status=$("$shekyld" status)
  echo "$status" | grep -q "Height:"
  if test $? = 0
  then
    ready=1
    break
  fi
done
if test "$ready" = 0
then
  echo "Error starting shekyld"
  tail -n 400 "$HOME/.bitmonero/bitmonero.log" | grep -Ev stacktrace\|"Error: Couldn't connect to daemon:"\|"src/daemon/main.cpp:.*Monero\ \'" | tail -n 20
  exit 1
fi

echo "Ready. Your Tor hidden service is $HOSTNAME"
