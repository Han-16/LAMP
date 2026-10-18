#include <cuda_runtime.h>
#include "../host_io.h"
#define CHECK(call) do { cudaError_t e=(call); if(e!=cudaSuccess) throw std::runtime_error(cudaGetErrorString(e)); } while(0)

// 8x8 tile. All threads participate in barriers, including padding threads.
__global__ void matmul(const Field* a,const Field* b,Field* c,uint k) {
 __shared__ Field aa[8][8],bb[8][8];
 uint x=threadIdx.x,y=threadIdx.y;
 uint row=blockIdx.y*8+y,col=blockIdx.x*8+x;
 Field sum=zero_field();
 for(uint base=0;base<k;base+=8) {
  aa[y][x]=(row<k && base+x<k)?a[size_t(row)*k+base+x]:zero_field();
  bb[y][x]=(base+y<k && col<k)?b[size_t(base+y)*k+col]:zero_field();
  __syncthreads();
  for(int l=0;l<8;l++) sum=add_field(sum,mul_field(aa[y][l],bb[l][x]));
  __syncthreads();
 }
 if(row<k && col<k) c[size_t(row)*k+col]=sum;
}
int main() {
 try {
  Input in=read_input(); size_t bytes=in.a.size()*sizeof(Field);
  auto start=Clock::now();
  CHECK(cudaSetDevice(0));
  cudaDeviceProp prop; CHECK(cudaGetDeviceProperties(&prop,0));
  Field *a=nullptr,*b=nullptr,*c=nullptr;
  CHECK(cudaMalloc((void**)&a,bytes)); CHECK(cudaMalloc((void**)&b,bytes)); CHECK(cudaMalloc((void**)&c,bytes));
  cudaEvent_t begin,end; CHECK(cudaEventCreate(&begin)); CHECK(cudaEventCreate(&end));
  double setup=ms(start);
  CHECK(cudaMemcpy(a,in.a.data(),bytes,cudaMemcpyHostToDevice));
  CHECK(cudaMemcpy(b,in.b.data(),bytes,cudaMemcpyHostToDevice));
  CHECK(cudaEventRecord(begin));
  matmul<<<dim3((in.k+7)/8,(in.k+7)/8),dim3(8,8)>>>(a,b,c,in.k);
  CHECK(cudaGetLastError()); CHECK(cudaEventRecord(end)); CHECK(cudaEventSynchronize(end));
  float kernel; CHECK(cudaEventElapsedTime(&kernel,begin,end));
  std::vector<Field> out(in.a.size());
  CHECK(cudaMemcpy(out.data(),c,bytes,cudaMemcpyDeviceToHost));
  CHECK(cudaFree(a)); CHECK(cudaFree(b)); CHECK(cudaFree(c));
  CHECK(cudaEventDestroy(begin)); CHECK(cudaEventDestroy(end));
  write_output(out); metrics(prop.name,setup,kernel);
 } catch(const std::exception& e) { std::cerr<<e.what()<<"\n"; return 1; }
}
