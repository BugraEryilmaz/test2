all:
	g++ -O2 test.cpp gzip.cpp zlib.cpp -o test -static -lboost_iostreams -lz -lcapstone

%:
	rm -rf exec/*
	g++ -O2 test.cpp gzip.cpp zlib.cpp -o ./exec/$@ -static -lboost_iostreams -lz -lcapstone
