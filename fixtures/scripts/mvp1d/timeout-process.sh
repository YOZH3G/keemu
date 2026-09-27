#!/bin/sh
/opt/bin/busybox sleep 120 &
child=$!
printf 'child=%s\n' "$child"
wait "$child"
