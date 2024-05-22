#!/bin/sh
port=3000
if [ $# -gt 0 ]; then
    port=$1
fi

python3 -m http.server $port --directory ./shellcodes