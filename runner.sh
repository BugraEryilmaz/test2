#!/bin/bash
pname=$1
output={$pname}_nophlt.txt

make $pname
./exec/$pname data_caching/data_caching_x86.gz > data_caching/$output &
disown
./exec/$pname data_serving/data_serving_x86.gz > data_serving/$output &
disown
./exec/$pname media_streaming/media_streaming_x86.gz > media_streaming/$output &
disown
./exec/$pname web_search/web_search_x86.gz > web_search/$output &
disown
./exec/$pname web_serving_db/web_serving_db_x86.gz > web_serving_db/$output &
disown
./exec/$pname web_serving_web_server/web_serving_web_server_x86.gz > web_serving_web_server/$output &
disown