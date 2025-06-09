#!/bin/bash

target_pid=$1
buf_size=$2

echo "target_pid: $target_pid" >&2
echo "buf_size: $buf_size" >&2

sed 's/^/[write] /g'
