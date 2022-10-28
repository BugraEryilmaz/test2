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

#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/iostreams/filtering_streambuf.hpp>
#include <capstone/capstone.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

using namespace std;

int check_dependency(cs_x86 *arg1, cs_x86 *arg2) {
    // args are x86 instructions and find dependencies between them
    return 0;
}

string ins_type(cs_insn *insn) {
    // return the type of instruction
    /*
    INT	Call to interrupt		0xCC, 0xCD
    INTO	Call to interrupt if overflow		0xCE
    IRET	Return from interrupt
    Jcc	Jump if condition	(JA, JAE, JB, JBE, JC, JE, JG, JGE, JL, JLE, JNA, JNAE, JNB, JNBE, JNC, JNE, JNG,
    JNGE, JNL, JNLE, JNO, JNP, JNS, JNZ, JO, JP, JPE, JPO, JS, JZ)	0x70…0x7F, 0x0F80…0x0F8F (since 80386) JCXZ
    Jump if CX is zero
    JMP
    LOOP/LOOPx	Loop control	(LOOPE, LOOPNE, LOOPNZ, LOOPZ) if (x && --CX) goto lbl;
    RET	Return from procedure	Not a real instruction. The assembler will translate these to a RETN or a RETF
        depending on the memory model of the target system. RETN	Return from near procedure		0xC2, 0xC3
   RETF Return from far procedure
*/
    if (insn->mnemonic[0] == 'j' || !strncmp(insn->mnemonic, "int", 3) || !strncmp(insn->mnemonic, "iret", 4) ||
        !strncmp(insn->mnemonic, "loop", 4) || !strncmp(insn->mnemonic, "ret", 3) ||
        !strncmp(insn->mnemonic, "call", 4))
        return "branch";
    // alu instructions
    else if (!strncmp(insn->mnemonic, "add", 3) || !strncmp(insn->mnemonic, "sub", 3) ||
             !strncmp(insn->mnemonic, "adc", 3) || !strncmp(insn->mnemonic, "ado", 3) ||
             !strncmp(insn->mnemonic, "test", 4) || !strncmp(insn->mnemonic, "cmp", 3) ||
             !strncmp(insn->mnemonic, "xor", 3) || !strncmp(insn->mnemonic, "and", 3) ||
             !strncmp(insn->mnemonic, "or", 2) || !strncmp(insn->mnemonic, "inc", 3) ||
             !strncmp(insn->mnemonic, "dec", 3))
        return "alu";
    // stack operations
    else if (!strncmp(insn->mnemonic, "push", 4) || !strncmp(insn->mnemonic, "pop", 3))
        return "stack";
    // mov
    else if (!strncmp(insn->mnemonic, "mov", 3))
        return "mov";
    // floating point
    else if (!strncmp(insn->mnemonic, "f", 1))
        return "fpu";
    // mul and div
    else if (!strncmp(insn->mnemonic, "mul", 3) || !strncmp(insn->mnemonic, "div", 3))
        return "muldiv";
    // pause and halt
    else if (!strncmp(insn->mnemonic, "pause", 5) || !strncmp(insn->mnemonic, "hlt", 3))
        return "hlt";

    return insn->mnemonic;
}

int main(int argc, char **argv) {
    // if (argc < 2) {
    //     std::cerr << "Usage: " << argv[0] << " <gzipped input file>" << std::endl;
    // }
    // Read from the first command line argument, assume it's gzipped
    // std::ifstream file(argv[1], std::ios_base::in | std::ios_base::binary);
    boost::iostreams::filtering_streambuf<boost::iostreams::input> inbuf;
    // inbuf.push(boost::iostreams::gzip_decompressor());
    inbuf.push(std::cin);
    // Convert streambuf to istream
    std::istream instream(&inbuf);
    // Iterate lines
    std::string line;
    uint64_t instr_count = 0, pid, ip, length;

    // Disassembler
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) return -1;
    vector<cs_insn *> instrs;

    unordered_map<string, int64_t> block_histo;
    unordered_map<int64_t, int64_t> blocksize_histo;
    int64_t hlt = 0, nop = 0, aes = 0, blockcount = 0;
    int64_t popcnt = 0, pushcount = 0;
    // length_histo.resize(16);
    while (std::getline(instream, line)) {
        // std::cout << line << std::endl;
        // std::cout << int(line[22]) << "\t" << int(line[23]) << "\n";
        istringstream iss(line);
        int x = 0;

        iss >> pid;
        iss >> line;
        // line = "ff08";
        ip = std::stoull(line, nullptr, 16);
        iss >> length;
        unsigned char data[20];
        // cout << std::hex << "pid: " << pid << " ip: " << ip << " length: " << length;
        for (int i = 0; i < length; i++) {
            iss >> line;
            data[i] = stoi(line, nullptr, 16);
        }
        // cout << " bytes: ";
        // for (int i=0; i<length ; i++) {
        //     cout << std::dec << data[i] << " ";
        // }
        // cout << "\n";

        count = cs_disasm(handle, (const uint8_t *)data, length, ip, 0, &insn);
        if (count == 1) {
            size_t j = 0;
            // printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
            string mnemonic = ins_type(&insn[j]);
            if (mnemonic == "hlt") hlt++;
            if (mnemonic == "nop") nop++;
            if (mnemonic.find("aes") != string::npos) {
                aes++;
                // cout << "aes: " << mnemonic << "\n";
            } else {
                // cout << "not aes: " << mnemonic << "\n";
            }
            if (!strncmp(insn[j].mnemonic, "pop", 3)) popcnt++;
            if (!strncmp(insn[j].mnemonic, "push", 4)) pushcount++;
            // if (hlt != 0) {
            //     cout << std::hex << insn[j].address << " " << insn[j].mnemonic << " " << insn[j].op_str << "\n";
            // }
            // if (hlt >= 6) exit(1);
            if (mnemonic == "branch") {
                // cout << "\n";
                instrs.push_back(&insn[j]);
                blocksize_histo[instrs.size()] += 1;
                string key;
                blockcount++;
                for (auto instr : instrs) {
                    key += instr->mnemonic;
                    key += " ";
                    // key += instr->op_str;
                    // key += "\n";
                }
                block_histo[key] += 1;
                for (auto i : instrs)
                    cs_free(i, 1);
                instrs.clear();
            } else {
                instrs.push_back(&insn[j]);
            }

        } else {
            printf("ERROR: Failed to disassemble given code!\n");
            cout << std::hex << "pid: " << pid << " ip: " << ip << " length: " << length << " bytes: ";
            for (int i = 0; i < length; i++) {
                cout << std::hex << (unsigned int)data[i] << " ";
            }
            cout << "\n";
        }
        // std::cin >> line;
        instr_count++;
        // if (instr_count % 10000000 == 0) {
        if (blockcount % 1000000 == 0) {
            //     break;
            // }
            double avg = 0;
            // for (auto ins : ins_histo) {
            //     double rate = ins.second * 100.0 / instr_count;
            //     if (rate > 1) printf("%s \t %lf\n", ins.first.c_str(), rate);
            // }
            printf("hlt_cnt = %lu, nop_cnt = %lu, aes_cnt=%lu\n", hlt, nop, aes);
            printf("hlt_cnt = %lf, nop_cnt = %lf, aes_cnt=%lf\n", hlt * 100.0 / instr_count, nop * 100.0 / instr_count,
                   aes * 100.0 / instr_count);
            printf("push = %lu, pop = %lu\n", pushcount, popcnt);
            printf("Total instructions: %lu\n", instr_count);
            printf("\n-------------------------------------------\n");
            printf("Block count: %lu\n", blockcount);
            for (auto block : block_histo) {
                double rate = block.second * 100.0 / blockcount;
                if (rate > 1) printf("%s \t %lf\n", block.first.c_str(), rate);
            }
            printf("\n-------------------------------------------\n");
            for (auto blocksize : blocksize_histo) {
                double rate = blocksize.second * 100.0 / blockcount;
                avg += rate * blocksize.first / 100.0;
                if (rate > 1) printf("block size :%lu \t freq :%lf\n", blocksize.first, rate);
            }
            printf("Average block size: %lf\n", avg);
            printf("\n--------------------------------------------------------------------------------------\n");
        }
    }
    // Cleanup
    // file.close();
    std::cout << instr_count << "\n";
}
