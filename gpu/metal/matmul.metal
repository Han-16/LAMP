#include "field.h"
kernel void matmul(device const Field* a [[buffer(0)]],
                   device const Field* b [[buffer(1)]],
                   device Field* c [[buffer(2)]],
                   constant uint& k [[buffer(3)]],
                   uint2 block [[threadgroup_position_in_grid]],
                   uint2 local [[thread_position_in_threadgroup]]) {
 threadgroup Field aa[8][8],bb[8][8];
 uint x=local.x,y=local.y,row=block.y*8+y,col=block.x*8+x;
 Field sum=zero_field();
 for(uint base=0;base<k;base+=8) {
  // Explicit copies avoid cross-address-space struct assignment overloads.
  for(uint limb=0;limb<16;limb++) {
   aa[y][x].v[limb]=(row<k && base+x<k)?a[row*k+base+x].v[limb]:0;
   bb[y][x].v[limb]=(base+y<k && col<k)?b[(base+y)*k+col].v[limb]:0;
  }
  threadgroup_barrier(mem_flags::mem_threadgroup);
  for(uint l=0;l<8;l++) {
   Field av,bv;
   for(uint limb=0;limb<16;limb++) { av.v[limb]=aa[y][l].v[limb]; bv.v[limb]=bb[l][x].v[limb]; }
   sum=add_field(sum,mul_field(av,bv));
  }
  threadgroup_barrier(mem_flags::mem_threadgroup);
 }
 if(row<k && col<k) for(uint limb=0;limb<16;limb++) c[row*k+col].v[limb]=sum.v[limb];
}
