/**
 * myzcat.cpp
 * A zcat replacement, for educational purpose.
 * Uses boost::iostream and zlib.
 * 
 * Compile like this:
 *   clang++ -o myzcat myzcat.cpp -lz -lboost_iostreams
 * 
 * This code is published as public domain.
 */

#include <fstream>
#include <iostream>
#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <vector>
#include <sstream>
#include "Disassembler/Disassembler.h"

using namespace std;

int main(int argc, char** argv) {
    if(argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <gzipped input file>" << std::endl;
    }
    //Read from the first command line argument, assume it's gzipped
    std::ifstream file(argv[1], std::ios_base::in | std::ios_base::binary);
    boost::iostreams::filtering_streambuf<boost::iostreams::input> inbuf;
    inbuf.push(boost::iostreams::gzip_decompressor());
    inbuf.push(file);
    //Convert streambuf to istream
    std::istream instream(&inbuf);
    //Iterate lines
    std::string line;
    uint64_t instrs = 0, pid, ip, length;

    vector<uint64_t> length_histo;
    length_histo.resize(16);     
    while(std::getline(instream, line)) {
        // std::cout << line << std::endl;
        // std::cout << int(line[22]) << "\t" << int(line[23]) << "\n";
        istringstream iss(line);
        int x = 0;
        // while(getline(iss, line, ' ')){
        //     if(int(line[0]) != 0){
        //         //cout << line << "\t" << int(line[0]) << "\n";
        //         x++;
        //         if(x == 3){
        //             //cout << "line: " << line << "\n";
        //             length = stoi(line);
        //             length_histo[length]++;
        //         }
        //     }
        // }
        
        iss >> pid;
        iss >> line;
        // line = "ff08";
        ip = std::stoull(line, nullptr, 16);
        iss >> length;
        unsigned char data[20];
        // cout << std::hex << "pid: " << pid << " ip: " << ip << " length: " << length;
        for (int i=0; i<length ; i++) {
            iss >> line;
            data[i] = stoi(line, nullptr, 16);
        }
        // cout << " bytes: ";
        // for (int i=0; i<length ; i++) {
        //     cout << std::dec << data[i] << " ";
        // }
        // cout << "\n";

        Disassembler disasm(data, length);
        if (ip < (uint64_t) 0xffffffff00000000){
            disasm.Print();
        }

        // std::cin >> line;
        instrs++;
        // if(instrs % 10000000 == 0){
        //     uint64_t total = 0, current = 0, w_sum = 0;
        //     for(int i = 0; i < length_histo.size(); i++){
        //     //    cout << "histo[" << i << "]: " << length_histo[i] << "\n";
        //         total += length_histo[i];
        //     }
        //     for(int i = 0; i < length_histo.size(); i++){
        //         current += length_histo[i];
        //         w_sum += (i * length_histo[i]);
        //         cout << "histo[" << i << "]: " << length_histo[i] << "\t" << (double)current*100/total << "%\n";
        //     //    total += length_histo[i];
        //     }
        //     cout << "average length: " << (double)w_sum/total << "\ttotal: " << instrs << "\n";

        // }
    }
    //Cleanup
    file.close();
    std::cout << instrs << "\n";
}
