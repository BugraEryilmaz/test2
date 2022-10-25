#! /bin/bash

#if ! [ -x "$(command -v clang)" ]; then
#  echo 'Error: clang is not installed, please install clang or add clang on the path.' >&2
#  exit 1
#fi

perf record -C 2 -m 1G,1G -e intel_pt// -- sleep 20
#rm -rf a.out
# If you want all instructions make full_trace true
full_trace=false
if [ "$full_trace" = true ] ; then
    perf script --itrace=i0ns --ns -F ip,insnlen,insn|awk '{$2="";$4="";print $0}'|gzip -9 > ${2}.gz
else
# takes five minutes to run in my machine
    perf script -C 2 --itrace=i0ns --ns -F pid,ip,insnlen,insn|awk '{$3="";$5="";print $0}'|head -1000000|gzip -9 > data_caching_x86.gz
    echo "later"
fi
#rm -rf perf.data*

