#!/bin/bash
pname=$1
output={$pname}.txt

# make $pname
cd data_caching/
# perf script --itrace=i0ns --ns -F pid,ip,insnlen,insn|awk '{$3="";$5="";print $0}'| ../exec/$pname > $output &
# disown
cd ../data_serving/
perf script --itrace=i0ns --ns -F pid,ip,insnlen,insn|awk '{$3="";$5="";print $0}'| ../exec/$pname > $output &
disown
cd ../media_streaming/
# perf script --itrace=i0ns --ns -F pid,ip,insnlen,insn|awk '{$3="";$5="";print $0}'| ../exec/$pname > $output &
# disown
cd ../web_search/
# perf script --itrace=i0ns --ns -F pid,ip,insnlen,insn|awk '{$3="";$5="";print $0}'| ../exec/$pname > $output &
# disown
cd ../web_serving_db/
# perf script --itrace=i0ns --ns -F pid,ip,insnlen,insn|awk '{$3="";$5="";print $0}'| ../exec/$pname > $output &
# disown
cd ../web_serving_web_server/
# perf script --itrace=i0ns --ns -F pid,ip,insnlen,insn|awk '{$3="";$5="";print $0}'| ../exec/$pname > $output &
# disown
cd ..