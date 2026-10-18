#pragma once
#include <chrono>
#include <iostream>
#include <vector>
#include <stdexcept>
#include <string>
#include "field.h"
using Clock=std::chrono::steady_clock;
inline double ms(Clock::time_point start) { return std::chrono::duration<double,std::milli>(Clock::now()-start).count(); }
inline void read_exact(char* dst,size_t n) {
 if(!std::cin.read(dst,n)) throw std::runtime_error("truncated GPU input");
}
struct Input { uint k; std::vector<Field> a,b; };
inline Input read_input() {
 // Private helper IPC is little-endian: uint32 K, then 16 uint32 limbs/entry.
 Input x; read_exact(reinterpret_cast<char*>(&x.k),4);
 if(x.k==0 || x.k>65535) throw std::runtime_error("invalid GPU input K");
 size_t count=size_t(x.k)*x.k;
 x.a.resize(count); x.b.resize(count);
 read_exact(reinterpret_cast<char*>(x.a.data()),count*sizeof(Field));
 read_exact(reinterpret_cast<char*>(x.b.data()),count*sizeof(Field));
 return x;
}
inline void write_output(const std::vector<Field>& c) {
 std::cout.write(reinterpret_cast<const char*>(c.data()),c.size()*sizeof(Field));
 if(!std::cout) throw std::runtime_error("GPU output write failed");
}
// Device names are escaped for the one JSON metrics line on stderr.
inline std::string quote(const std::string& s) {
 std::string out="\"";
 for(unsigned char ch:s) { if(ch=='"'||ch=='\\') out+='\\'; if(ch>=32) out+=ch; }
 return out+'"';
}
inline void metrics(const std::string& device,double setup,double kernel) {
 std::cerr << "{\"device_name\":" << quote(device)
 << ",\"setup_ms\":" << setup << ",\"kernel_ms\":" << kernel << "}\n";
}
