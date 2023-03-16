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
bool parse(istream &iss, uint64_t &pid, uint64_t &ip, uint16_t &length,
           uint8_t *data);
void print_all();

#define USER_SPACE_END 0x7fffffffffff // 64-bit user space end

int check_dependency(cs_x86 *arg1, cs_x86 *arg2) {
  // args are x86 instructions and find dependencies between them
  return 0;
}

unordered_map<string, int64_t> instruction_mnemonic_histo;
unordered_map<string, pair<int64_t, uint64_t>> block_histo;
unordered_map<string, unordered_map<string, int64_t>> instruction_histo;
unordered_map<string, int64_t> group_histo;
unordered_map<int64_t, unordered_map<string, int64_t>> insn_histo;
unordered_map<int64_t, int64_t> blocksize_histo;
unordered_map<int64_t, int64_t> insnsize_histo;
unordered_map<int64_t, int64_t> aes_insnsize_histo;
int64_t hlt = 0, nop = 0, aes = 0, blockcount = 1;
int64_t popcnt = 0, pushcount = 0;
int64_t rep_count_kernel = 0, rep_count = 0;
int64_t vectorop_count_kernel = 0, vectorop_count = 0;
int64_t instr_count_kernel = 0, instr_count = 0;

string ins_type(cs_insn *insn) {
  // return the type of instruction
  /*
  INT	Call to interrupt		0xCC, 0xCD
  INTO	Call to interrupt if overflow		0xCE
  IRET	Return from interrupt
  Jcc	Jump if condition	(JA, JAE, JB, JBE, JC, JE, JG, JGE, JL, JLE,
 JNA, JNAE, JNB, JNBE, JNC, JNE, JNG, JNGE, JNL, JNLE, JNO, JNP, JNS, JNZ, JO,
 JP, JPE, JPO, JS, JZ)	0x70…0x7F, 0x0F80…0x0F8F (since 80386) JCXZ Jump if CX
 is zero JMP LOOP/LOOPx	Loop control	(LOOPE, LOOPNE, LOOPNZ, LOOPZ) if (x &&
 --CX) goto lbl; RET	Return from procedure	Not a real instruction. The
 assembler will translate these to a RETN or a RETF depending on the memory
 model of the target system. RETN	Return from near procedure
 0xC2, 0xC3 RETF Return from far procedure
*/
  if (insn->mnemonic[0] == 'j' || !strncmp(insn->mnemonic, "int", 3) ||
      !strncmp(insn->mnemonic, "iret", 4) ||
      !strncmp(insn->mnemonic, "loop", 4) ||
      !strncmp(insn->mnemonic, "ret", 3) || !strncmp(insn->mnemonic, "call", 4))
    return "branch";
  // alu instructions
  else if (!strncmp(insn->mnemonic, "add", 3) ||
           !strncmp(insn->mnemonic, "sub", 3) ||
           !strncmp(insn->mnemonic, "adc", 3) ||
           !strncmp(insn->mnemonic, "ado", 3) ||
           !strncmp(insn->mnemonic, "test", 4) ||
           !strncmp(insn->mnemonic, "cmp", 3) ||
           !strncmp(insn->mnemonic, "xor", 3) ||
           !strncmp(insn->mnemonic, "and", 3) ||
           !strncmp(insn->mnemonic, "or", 2) ||
           !strncmp(insn->mnemonic, "inc", 3) ||
           !strncmp(insn->mnemonic, "dec", 3))
    return "alu";
  // stack operations
  else if (!strncmp(insn->mnemonic, "push", 4) ||
           !strncmp(insn->mnemonic, "pop", 3))
    return "stack";
  // mov
  else if (!strncmp(insn->mnemonic, "mov", 3))
    return "mov";
  // floating point
  else if (!strncmp(insn->mnemonic, "f", 1))
    return "fpu";
  // mul and div
  else if (!strncmp(insn->mnemonic, "mul", 3) ||
           !strncmp(insn->mnemonic, "div", 3))
    return "muldiv";
  // pause and halt
  else if (!strncmp(insn->mnemonic, "pause", 5) ||
           !strncmp(insn->mnemonic, "hlt", 3))
    return "hlt";

  return insn->mnemonic;
}
uint64_t print_interval = 20000000;
uint64_t print_count = 1;
bool qemu = false;
int main(int argc, char **argv) {
  // if (argc < 2) {
  //     std::cerr << "Usage: " << argv[0] << " <gzipped input file>" <<
  //     std::endl;
  // }
  // Read from the first command line argument, assume it's gzipped
  cout << argc << endl;
  boost::iostreams::filtering_streambuf<boost::iostreams::input> inbuf;
  std::ifstream file;
  int filearg = 0;
  bool gzip = false;
  if (argc > 1 && strncmp(argv[1], "-help", 5) == 0) {
    std::cerr
        << "Usage: " << argv[0]
        << " <-gzip> <-fname input_file> <-qemu> <-print_interval number> "
        << std::endl;
    exit(0);
  }
  for (int i = 1; i < argc; i++) {
    if (strncmp(argv[i], "-fname", 6) == 0) {
      filearg = i + 1;
    }
    if (strncmp(argv[i], "-qemu", 5) == 0) {
      qemu = true;
    }
    if (strncmp(argv[i], "-print_interval", 15) == 0) {
      print_interval = atoi(argv[i + 1]);
    }
    if (strncmp(argv[i], "-gzip", 5) == 0) {
      gzip = true;
    }
  }

  if (filearg == 0 && gzip == false) {
    inbuf.push(std::cin);
  } else if (filearg == 0 && gzip == true) {
    inbuf.push(boost::iostreams::gzip_decompressor());
    inbuf.push(std::cin);
  } else {
    file =
        std::ifstream(argv[filearg], std::ios_base::in | std::ios_base::binary);
    if (gzip) {
      inbuf.push(boost::iostreams::gzip_decompressor());
    }
    inbuf.push(file);
  }
  // Convert streambuf to istream
  std::istream instream(&inbuf);

  std::string line;

  // Iterate lines
  uint64_t pid_hlt = 0;
  uint64_t pid, ip;
  uint64_t last_ip = 0;
  uint16_t length;

  // Disassembler
  csh handle;
  cs_insn *insn;
  size_t count;

  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    return -1;
  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
  vector<myInsn> instrs;

  // length_histo.resize(16);
  uint8_t data[10000];
  while (
      parse(instream, pid, ip, length, data) /*std::getline(instream, line)*/) {
    int x = 0;
    count = cs_disasm(handle, (const uint8_t *)data, length, ip, 0, &insn);
    if (count < 1) {
      std::cerr << "ERROR: Failed to disassemble given code!" << std::endl;
      // print data
      for (int i = 0; i < length; i++) {
        fprintf(stderr, "%02x ", data[i]);
      }
      fprintf(stderr, "\n");
      continue;
    }
    for (size_t j = 0; j < count; j++) {
      if (last_ip == insn[j].address) {
        // cout << "last_ip: " << last_ip << "\tinsn[j].address: " <<
        // insn[j].address << endl;
        continue;
      }
      last_ip = insn[j].address;
      // if (ip > USER_SPACE_END) // kernel
      //     printf("kernel: 0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address,
      //     insn[j].mnemonic, insn[j].op_str);
      // else
      //     printf("user: 0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address,
      //     insn[j].mnemonic, insn[j].op_str);
      instruction_mnemonic_histo[insn[j].mnemonic]++;
      string grp = "";
      for (int i = 0; i < insn[j].detail->groups_count; i++) {
        grp += cs_group_name(handle, insn[j].detail->groups[i]);
        grp += " ";
      }
      group_histo[grp]++;
      instruction_histo[grp][insn[j].mnemonic]++;
      insnsize_histo[insn[j].size]++;
      insn_histo[insn[j].size][insn[j].mnemonic]++;
      string mnemonic = ins_type(&insn[j]);
      // if (pid_hlt) {
      //   printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address,
      //   insn[j].mnemonic,
      //          insn[j].op_str);
      //   if (pid_hlt > 50)
      //     exit(1);
      // }
      if (mnemonic == "hlt") {
        hlt++;
        pid_hlt += 1;
      }
      if (mnemonic == "nop")
        nop++;
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
      if (!strncmp(insn[j].mnemonic, "pop", 3))
        popcnt++;
      if (!strncmp(insn[j].mnemonic, "push", 4))
        pushcount++;
      if (mnemonic == "branch") {
        // cout << "\n";
        instrs.push_back(&insn[j]);
        blocksize_histo[instrs.size()] += 1;
        string key;
        blockcount++;
        key = +"blocksize ";
        key += to_string(instrs.size());
        if (instrs[0].address > USER_SPACE_END)
          key += " kernel ";
        else
          key += " user ";
        for (auto instr : instrs) {
          key += instr.mnemonic;
          key += " ";
          // key += instr->op_str;
          // key += "\n";
        }
        if (block_histo.find(key) == block_histo.end())
          block_histo[key] = make_pair(instrs.size(), 1);
        else
          block_histo[key] =
              make_pair(instrs.size(), block_histo[key].second + 1);
        instrs.clear();
      } else {
        instrs.push_back(&insn[j]);
      }

      instr_count++;
    }
    cs_free(insn, count);

    if (ip > USER_SPACE_END) // kernel
      instr_count_kernel++;
    if (instr_count > print_count * print_interval) {
      // if (blockcount % 3000000 == 0) {
      print_all();
      print_count++;
    }
  }
  // Cleanup
  print_all();

  cs_close(&handle);
  if (filearg)
    file.close();
  std::cout << instr_count << "\n";
}
bool parse(istream &iss, uint64_t &pid, uint64_t &ip, uint16_t &length,
           uint8_t *data) {
  if (qemu) {
    pid = 0;
    // cout << "start:";
    uint32_t val[2] = {0};
    iss.read((char *)val, sizeof(val));
    if (iss.eof())
      return false;
    // ip = (uint64_t)ntohl(val[0]) << 32 | (uint64_t)ntohl(val[1]);
    ip = (uint64_t)val[1] << 32 | (uint64_t)val[0];
    // cout << ip << ' ';

    iss.read((char *)&length, sizeof(length));
    pid = length;
    iss.read((char *)&length, sizeof(length));
    // length = ntohs(length);

    // cout << std::hex << "pid: " << pid << " ip: " << ip << " length: " <<
    // length << " bytes: ";
    if (length > 9000) {
      std::cerr << "length too large: " << length << "\n";
      exit(1);
    }
    for (int i = 0; i < length; i++) {
      iss.read((char *)&data[i], 1);
      // cout << std::hex << (uint16_t)data[i] << " ";
    }
    // cout << "\n";
    return true;
  } else {
    string line;
    if (!std::getline(iss, line))
      return false;
    istringstream iss2(line);
    iss2 >> pid;
    string temp;
    iss2 >> temp;
    // line = "ff08";
    ip = std::stoull(temp, nullptr, 16);
    iss2 >> length;
    // cout << std::hex << "pid: " << pid << " ip: " << ip << " length: " <<
    // length;
    for (int i = 0; i < length; i++) {
      iss2 >> temp;
      data[i] = stoi(temp, nullptr, 16);
    }
    return true;
  }
}

void print_all() {
  double avg = 0;
  printf("hlt_cnt = %lu, nop_cnt = %lu, aes_cnt=%lu\n", hlt, nop, aes);
  printf("hlt_rate = %lf, nop_rate = %lf, aes_rate=%lf\n",
         hlt * 100.0 / instr_count, nop * 100.0 / instr_count,
         aes * 100.0 / instr_count);
  printf("push = %lu, pop = %lu\n", pushcount, popcnt);
  printf("rep = %lu, \t rep_kernel = %lu\n", rep_count, rep_count_kernel);
  printf(
      "rep/total_instructions = %lf, \t rep_kernel/kernel_instructions = %lf\n",
      rep_count * 100.0 / instr_count,
      rep_count_kernel * 100.0 / instr_count_kernel);
  printf("vectorop = %lu, \t vectorop_kernel = %lu\n", vectorop_count,
         vectorop_count_kernel);
  printf("vectorop/total_instructions = %lf, \t "
         "vectorop_kernel/kernel_instructions = %lf\n",
         vectorop_count * 100.0 / instr_count,
         vectorop_count_kernel * 100.0 / instr_count_kernel);
  printf("Total instructions: %lu, \t Total kernel instructions: %lu\n",
         instr_count, instr_count_kernel);
  printf("\n-------------------------------------------\n");
  ////      Instruction histogram for each group. (e.g. AVX group: 1000 addps,
  /// 2000 mulps, ...)
  // for (auto instruction : instruction_histo) {
  //     printf("%s\n", instruction.first.c_str());
  //     vector<pair<string, int64_t>> v4(instruction.second.begin(),
  //     instruction.second.end()); sort(v4.begin(), v4.end(),
  //             [](const pair<string, int> &a, const pair<string, int> &b) {
  //             return a.second > b.second; });
  //     for (auto instr : v4) {
  //         double rate = instr.second * 100.0 /
  //         group_histo[instruction.first]; printf("rate:%lf \tcount:%lu \t
  //         %s\n", rate, instr.second, instr.first.c_str());
  //     }
  //     printf("\n-------------------------------------------\n");
  //     // if (rate > 1)
  // }

  ////      Group histogram. (e.g. 1000 AVX, 2000 SSE, ...)
  // vector<pair<string, int64_t>> v3(group_histo.begin(), group_histo.end());
  // sort(v3.begin(), v3.end(),
  //         [](const pair<string, int> &a, const pair<string, int> &b) { return
  //         a.second > b.second; });
  // for (auto instruction : v3) {
  //     double rate = instruction.second * 100.0 / instr_count;
  //     // if (rate > 1)
  //     printf("rate:%lf \tcount:%lu \t %s\n", rate, instruction.second,
  //     instruction.first.c_str());
  // }

  ////      Block histogram. (e.g. add mul sub jmp 2%, test beq 5%, ...)
  vector<pair<string, pair<int64_t, uint64_t>>> v(block_histo.begin(),
                                                  block_histo.end());
  sort(v.begin(), v.end(),
       [](const pair<string, pair<int64_t, uint64_t>> &a,
          const pair<string, pair<int64_t, uint64_t>> &b) {
         return a.second.first * a.second.second >
                b.second.first * b.second.second;
       });
  printf("Block count: %lu\n", blockcount);
  printf("Unique Basic Block count: %lu\n", block_histo.size());
  uint64_t total_importance = 0;
  for (auto block : v) {
    total_importance += block.second.first * block.second.second;
  }
  uint64_t importance_blockcount = 0;
  uint64_t cumulative_importance = 0;
  vector<uint64_t> required_blocks_forimportance;
  for (auto block : v) {
    double rate = block.second.second * 100.0 / blockcount;
    cumulative_importance += block.second.first * block.second.second;
    importance_blockcount++;
    if (cumulative_importance * 100.0 / total_importance >
        required_blocks_forimportance.size() * 10) {
      required_blocks_forimportance.push_back(importance_blockcount);
    }
    if (importance_blockcount < 1000)
      printf("importance:%lf\trate:%lf\tcount:%lu\t%s\n",
             block.second.first * block.second.second * 100.0 /
                 total_importance,
             rate, block.second.second, block.first.c_str());
  }
  printf("\n-------------------------------------------\n");

  for (int i = 0; i < required_blocks_forimportance.size(); i++) {
    printf("Required blocks for %d%% importance: %lu\n", i * 10,
           required_blocks_forimportance[i]);
  }
  printf("\n-------------------------------------------\n");

  ////      Blocksize histogram. (e.g. blocksize=5 with 2%, ...)
  vector<pair<int64_t, int64_t>> v2(blocksize_histo.begin(),
                                    blocksize_histo.end());
  sort(v2.begin(), v2.end(),
       [](const pair<int64_t, int> &a, const pair<int64_t, int> &b) {
         return a.second > b.second;
       });
  for (auto blocksize : v2) {
    double rate = blocksize.second * 100.0 / blockcount;
    avg += rate * blocksize.first / 100.0;
    if (rate > 1)
      printf("block size :%lu \t freq :%lf\t number :%lu\n", blocksize.first,
             rate, blocksize.second);
  }
  printf("Average block size: %lf\n", avg);
  printf("\n-------------------------------------------\n");

  ////      Instruction histogram (e.g. %10 add, %20 mul, ...)
  vector<pair<string, int64_t>> v8(instruction_mnemonic_histo.begin(),
                                   instruction_mnemonic_histo.end());
  sort(v8.begin(), v8.end(),
       [](const pair<string, int> &a, const pair<string, int> &b) {
         return a.second > b.second;
       });
  for (auto instruction : v8) {
    double rate = instruction.second * 100.0 / instr_count;
    if (rate > 1)
      printf("rate:%lf \tcount:%lu \t %s\n", rate, instruction.second,
             instruction.first.c_str());
  }
  printf("\n-------------------------------------------\n");

  ////      Instruction size histogram. (e.g. 3 byte instructions with 20%, ...)
  vector<pair<int64_t, int64_t>> v5(insnsize_histo.begin(),
                                    insnsize_histo.end());
  sort(v5.begin(), v5.end(),
       [](const pair<int64_t, int> &a, const pair<int64_t, int> &b) {
         return a.second > b.second;
       });
  avg = 0;
  for (auto insnsize : v5) {
    double rate = insnsize.second * 100.0 / instr_count;
    avg += rate * insnsize.first / 100.0;
    if (rate > 1)
      printf("instruction size :%lu \t freq :%lf\t number :%lu\n",
             insnsize.first, rate, insnsize.second);
  }
  printf("Average instruction size: %lf\n", avg);
  printf("\n-------------------------------------------\n");

  ////      aes Instruction size histogram. (e.g. 5 byte aes instructions with
  /// 60%, ...)
  // vector<pair<int64_t, int64_t>> v6(aes_insnsize_histo.begin(),
  // aes_insnsize_histo.end()); sort(v6.begin(), v6.end(),
  //         [](const pair<int64_t, int> &a, const pair<int64_t, int> &b) {
  //         return a.second > b.second; });
  // avg = 0;
  // for (auto insnsize : v6) {
  //     double rate = insnsize.second * 100.0 / aes;
  //     avg += rate * insnsize.first / 100.0;
  //     if (rate > 1)
  //         printf("aes instruction size :%lu \t freq :%lf\t number :%lu\n",
  //         insnsize.first, rate,
  //                 insnsize.second);
  // }
  // printf("Average aes instruction size: %lf\n", avg);
  // printf("\n-------------------------------------------\n");

  ////      Instruction breakdown for each length. (e.g. 3 byte instructions: 5%
  /// add, 10% mul, ...)
  // for (auto ins_len : insn_histo) {
  //     printf("%ld byte instruction count: %lu\n", ins_len.first,
  //     insnsize_histo[ins_len.first]); vector<pair<string, int64_t>>
  //     v7(ins_len.second.begin(), ins_len.second.end()); sort(v7.begin(),
  //     v7.end(),
  //             [](const pair<string, int> &a, const pair<string, int> &b) {
  //             return a.second > b.second; });
  //     for (auto insn : v7) {
  //         double rate = insn.second * 100.0 / insnsize_histo[ins_len.first];
  //         if (rate > 1) printf("rate: %lf \tcount: %lu\t%s\n", rate,
  //         insn.second, insn.first.c_str());
  //     }
  //     printf("\n-------------------------------------------\n");
  // }
  printf("\n-------------------------------------------------------------------"
         "-------------------\n");
}