// Shared Metal/CUDA/host arithmetic for BN254 Fr (NOT the curve base field).
// Montgomery radix R=2^256 matches gnark-crypto fr.Element. Each of 16 limbs
// uses 16 bits stored in uint32, avoiding 64-bit integer requirements on GPUs.
#pragma once
#if defined(__METAL_VERSION__)
#include <metal_stdlib>
using namespace metal;
#define FN inline
#define CONST constant
#else
#include <cstdint>
using uint = uint32_t;
#if defined(__CUDACC__)
#define FN __device__ inline
#define CONST __device__ __constant__
#else
#define FN inline
#define CONST static const
#endif
#endif
struct Field { uint v[16]; };
CONST uint MOD[16] = {0x0001,0xf000,0xf593,0x43e1,0x7091,0x79b9,0xe848,0x2833,
                     0x585d,0x8181,0x45b6,0xb850,0xa029,0xe131,0x4e72,0x3064};
FN Field zero_field() { Field a; for(int i=0;i<16;i++) a.v[i]=0; return a; }
FN Field reduce_once(Field a) {
 bool ge=true;
 for(int i=15;i>=0;i--) {
  if(a.v[i]!=MOD[i]) { ge=a.v[i]>MOD[i]; break; }
 }
 if(ge) {
  uint borrow=0;
  for(int i=0;i<16;i++) {
   uint sub=MOD[i]+borrow, old=a.v[i];
   a.v[i]=(old-sub)&65535u;
   borrow=old<sub;
  }
 }
 return a;
}
FN Field add_field(Field a,Field b) {
 Field c; uint carry=0;
 for(int i=0;i<16;i++) { uint s=a.v[i]+b.v[i]+carry; c.v[i]=s&65535u; carry=s>>16; }
 // a,b < p and 2p < R, so there is no final carry.
 return reduce_once(c);
}
FN Field mul_field(Field a,Field b) {
 uint t[33]; for(int i=0;i<33;i++) t[i]=0;
 // Schoolbook product. Each intermediate fits exactly in uint32.
 for(int i=0;i<16;i++) {
  uint carry=0;
  for(int j=0;j<16;j++) {
   uint s=a.v[i]*b.v[j]+t[i+j]+carry;
   t[i+j]=s&65535u; carry=s>>16;
  }
  t[i+16]=carry;
 }
 // Montgomery reduction, -p[0]^-1 mod 2^16 = 65535.
 for(int i=0;i<16;i++) {
  uint m=(t[i]*65535u)&65535u, carry=0;
  for(int j=0;j<16;j++) {
   uint s=m*MOD[j]+t[i+j]+carry;
   t[i+j]=s&65535u; carry=s>>16;
  }
  for(int j=i+16;j<33;j++) {
   uint s=t[j]+carry; t[j]=s&65535u; carry=s>>16;
  }
 }
 Field c; for(int i=0;i<16;i++) c.v[i]=t[i+16];
 return reduce_once(c); // REDC < 2p < R
}
