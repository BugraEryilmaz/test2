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

#include <arpa/inet.h>
#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/iostreams/filtering_streambuf.hpp>
#include <capstone/capstone.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <unordered_map>
#include <vector>
#define RAFAEL

class myInsn {
public:
    myInsn(cs_insn *ref) {
        this->address = ref->address;
        this->mnemonic = ref->mnemonic;
        this->op_str = ref->op_str;
    }
    uint64_t address;
    std::string mnemonic;
    std::string op_str;
};

using namespace std;
bool parse(istream &iss, uint64_t &pid, uint64_t &ip, uint16_t &length, uint8_t *data);

#define USER_SPACE_END 0x7fffffffffff // 64-bit user space end

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
    cout << argc << endl;
    boost::iostreams::filtering_streambuf<boost::iostreams::input> inbuf;
    std::ifstream file;
    if (argc > 1) {
#ifdef RAFAEL
        file = std::ifstream(argv[1], std::ios_base::in | std::ios_base::binary);
#else
        file = std::ifstream(argv[1], std::ios_base::in | std::ios_base::binary);
        inbuf.push(boost::iostreams::gzip_decompressor());
#endif
        inbuf.push(file);
    } else {
        inbuf.push(std::cin);
    }
    // Convert streambuf to istream
    std::istream instream(&inbuf);

    std::string line;

    // Iterate lines
    uint64_t pid, ip;
    uint64_t last_ip = 0;
    uint16_t length;

    // Disassembler
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) return -1;
    vector<myInsn> instrs;

    unordered_map<string, int64_t> block_histo;
    unordered_map<int64_t, unordered_map<string, int64_t>> insn_histo;
    unordered_map<int64_t, int64_t> blocksize_histo;
    unordered_map<int64_t, int64_t> insnsize_histo;
    unordered_map<int64_t, int64_t> aes_insnsize_histo;
    int64_t hlt = 0, nop = 0, aes = 0, blockcount = 1;
    int64_t popcnt = 0, pushcount = 0;
    int64_t rep_count_kernel = 0, rep_count = 0;
    int64_t vectorop_count_kernel = 0, vectorop_count = 0;
    int64_t instr_count_kernel = 0, instr_count = 0;
    // length_histo.resize(16);
    uint8_t data[1000];
    while (parse(instream, pid, ip, length, data) /*std::getline(instream, line)*/) {
        // std::cout << line << std::endl;
        // std::cout << int(line[22]) << "\t" << int(line[23]) << "\n";
        // istringstream iss(line);
        int x = 0;

        // uint8_t data[20];
        // parse(iss, pid, ip, length, data);

        // cout << "pid: " << pid << "\tip: " << ip << "\tlength: " << length << "\tdata: ";
        // for (int i = 0; i < length; i++) {
        //     cout << hex << (int)data[i] << " ";
        // }
        // cout << endl;

        count = cs_disasm(handle, (const uint8_t *)data, length, ip, 0, &insn);
        for (size_t j = 0; j < count; j++) {
            if (last_ip == insn[j].address) {
                // cout << "last_ip: " << last_ip << "\tinsn[j].address: " << insn[j].address << endl;
                continue;
            }
            last_ip = insn[j].address;
            // if (ip > USER_SPACE_END) // kernel
            //     printf("kernel: 0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
            // else
            //     printf("user: 0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
            insnsize_histo[insn[j].size]++;
            insn_histo[insn[j].size][insn[j].mnemonic]++;
            string mnemonic = ins_type(&insn[j]);
            if (mnemonic == "hlt") hlt++;
            if (mnemonic == "nop") nop++;
            if (mnemonic.find("aes") != string::npos) {
                aes++;
                aes_insnsize_histo[insn[j].size]++;
                // cout << "aes: " << mnemonic << "\n";
            }
            if (!strncmp(insn[j].mnemonic, "rep", 3)) {
                rep_count++;
                if (ip > USER_SPACE_END) // kernel
                    rep_count_kernel++;
            }
            if (!strncmp(insn[j].mnemonic, "v", 1)) {
                vectorop_count++;
                if (ip > USER_SPACE_END) // kernel
                    vectorop_count_kernel++;
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
                    key += instr.mnemonic;
                    key += " ";
                    // key += instr->op_str;
                    // key += "\n";
                }
                block_histo[key] += 1;
                instrs.clear();
            } else {
                instrs.push_back(&insn[j]);
            }

            instr_count++;
        }
        cs_free(insn, count);
        // else {
        //     printf("ERROR: Failed to disassemble given code!\n");
        //     cout << std::hex << "pid: " << pid << " ip: " << ip << " length: " << length << " bytes: ";
        //     for (int i = 0; i < length; i++) {
        //         cout << std::hex << (unsigned int)data[i] << " ";
        //     }
        //     cout << "\n";
        // }
        // std::cin >> line;

        if (ip > USER_SPACE_END) // kernel
            instr_count_kernel++;
        // if (instr_count % 10000000 == 0) {
        if (blockcount % 3000000 == 0) {
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
            printf("rep = %lu, \t rep_kernel = %lu\n", rep_count, rep_count_kernel);
            printf("rep/total_instructions = %lf, \t rep_kernel/kernel_instructions = %lf\n",
                   rep_count * 100.0 / instr_count, rep_count_kernel * 100.0 / instr_count_kernel);
            printf("vectorop = %lu, \t vectorop_kernel = %lu\n", vectorop_count, vectorop_count_kernel);
            printf("vectorop/total_instructions = %lf, \t vectorop_kernel/kernel_instructions = %lf\n",
                   vectorop_count * 100.0 / instr_count, vectorop_count_kernel * 100.0 / instr_count_kernel);
            printf("Total instructions: %lu, \t Total kernel instructions: %lu\n", instr_count, instr_count_kernel);
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
                if (rate > 1)
                    printf("block size :%lu \t freq :%lf\t number :%lu\n", blocksize.first, rate, blocksize.second);
            }
            printf("Average block size: %lf\n", avg);
            printf("\n-------------------------------------------\n");
            avg = 0;
            for (auto insnsize : insnsize_histo) {
                double rate = insnsize.second * 100.0 / instr_count;
                avg += rate * insnsize.first / 100.0;
                if (rate > 1)
                    printf("instruction size :%lu \t freq :%lf\t number :%lu\n", insnsize.first, rate, insnsize.second);
            }
            printf("Average instruction size: %lf\n", avg);
            printf("\n-------------------------------------------\n");
            avg = 0;
            for (auto insnsize : aes_insnsize_histo) {
                double rate = insnsize.second * 100.0 / aes;
                avg += rate * insnsize.first / 100.0;
                if (rate > 1)
                    printf("aes instruction size :%lu \t freq :%lf\t number :%lu\n", insnsize.first, rate,
                           insnsize.second);
            }
            printf("Average aes instruction size: %lf\n", avg);
            printf("\n-------------------------------------------\n");
            for (auto ins_len : insn_histo) {
                printf("%ld byte instruction count: %lu\n", ins_len.first, insnsize_histo[ins_len.first]);
                for (auto insn : ins_len.second) {
                    double rate = insn.second * 100.0 / insnsize_histo[ins_len.first];
                    if (rate > 1) printf("rate: %lf \tcount: %lu\t%s\n", rate, insn.second, insn.first.c_str());
                }
                printf("\n-------------------------------------------\n");
            }
            printf("\n--------------------------------------------------------------------------------------\n");
        }
    }
    // Cleanup
    // file.close();
    std::cout << instr_count << "\n";
}
bool parse(istream &iss, uint64_t &pid, uint64_t &ip, uint16_t &length, uint8_t *data) {
#ifdef RAFAEL
    pid = 0;
    // cout << "start:";
    uint32_t val[2] = {0};
    iss.read((char *)val, sizeof(val));
    if (iss.eof()) return false;
    // ip = (uint64_t)ntohl(val[0]) << 32 | (uint64_t)ntohl(val[1]);
    ip = (uint64_t)val[1] << 32 | (uint64_t)val[0];
    // cout << ip << ' ';

    iss.read((char *)&length, sizeof(length));
    pid = length;
    iss.read((char *)&length, sizeof(length));
    // length = ntohs(length);

    // cout << std::hex << "pid: " << pid << " ip: " << ip << " length: " << length << " bytes: ";
    if (length > 900) {
        exit(1);
    }
    for (int i = 0; i < length; i++) {
        iss.read((char *)&data[i], 1);
        // cout << std::hex << (uint16_t)data[i] << " ";
    }
    // cout << "\n";
    return true;
#else
    string line;
    if (!std::getline(instream, line)) return false;
    istringstream iss(line);
    iss >> pid;
    string temp;
    iss >> temp;
    // line = "ff08";
    ip = std::stoull(temp, nullptr, 16);
    iss >> length;
    unsigned char data[20];
    // cout << std::hex << "pid: " << pid << " ip: " << ip << " length: " << length;
    for (int i = 0; i < length; i++) {
        iss >> temp;
        data[i] = stoi(temp, nullptr, 16);
    }
    return true;
#endif
}
