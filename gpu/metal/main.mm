#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include "../host_io.h"
#include <cstring>

int main(int argc,char** argv) {
 @autoreleasepool {
  try {
   if(argc!=2) throw std::runtime_error("usage: lamp-metal kernel.metal");
   Input in=read_input(); size_t bytes=in.a.size()*sizeof(Field);
   auto start=Clock::now();
   id<MTLDevice> device=MTLCreateSystemDefaultDevice();
   if(!device) throw std::runtime_error("no Metal device");
   NSError* error=nil;
   NSString* path=[NSString stringWithUTF8String:argv[1]];
   NSString* source=[NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:&error];
   if(!source) throw std::runtime_error([[error localizedDescription] UTF8String]);
   // Use the system Metal runtime compiler, not the offline xcrun metal tool.
   id<MTLLibrary> library=[device newLibraryWithSource:source options:nil error:&error];
   if(!library) throw std::runtime_error([[error localizedDescription] UTF8String]);
   id<MTLFunction> function=[library newFunctionWithName:@"matmul"];
   if(!function) throw std::runtime_error("Metal kernel missing");
   id<MTLComputePipelineState> pipeline=[device newComputePipelineStateWithFunction:function error:&error];
   if(!pipeline) throw std::runtime_error([[error localizedDescription] UTF8String]);
   if(pipeline.maxTotalThreadsPerThreadgroup<64) throw std::runtime_error("Metal device cannot launch 8x8 tile");
   id<MTLCommandQueue> queue=[device newCommandQueue];
   id<MTLBuffer> a=[device newBufferWithLength:bytes options:MTLResourceStorageModeShared];
   id<MTLBuffer> b=[device newBufferWithLength:bytes options:MTLResourceStorageModeShared];
   id<MTLBuffer> c=[device newBufferWithLength:bytes options:MTLResourceStorageModeShared];
   if(!queue || !a || !b || !c) throw std::runtime_error("Metal allocation failed");
   double setup=ms(start);
   memcpy(a.contents,in.a.data(),bytes); memcpy(b.contents,in.b.data(),bytes);
   id<MTLCommandBuffer> command=[queue commandBuffer];
   id<MTLComputeCommandEncoder> encoder=[command computeCommandEncoder];
   if(!command || !encoder) throw std::runtime_error("Metal command creation failed");
   [encoder setComputePipelineState:pipeline];
   [encoder setBuffer:a offset:0 atIndex:0]; [encoder setBuffer:b offset:0 atIndex:1];
   [encoder setBuffer:c offset:0 atIndex:2]; [encoder setBytes:&in.k length:4 atIndex:3];
   [encoder dispatchThreadgroups:MTLSizeMake((in.k+7)/8,(in.k+7)/8,1) threadsPerThreadgroup:MTLSizeMake(8,8,1)];
   [encoder endEncoding]; [command commit]; [command waitUntilCompleted];
   if(command.status!=MTLCommandBufferStatusCompleted) throw std::runtime_error([[command.error localizedDescription] UTF8String]);
   double kernel=(command.GPUEndTime-command.GPUStartTime)*1000.0;
   std::vector<Field> out(in.a.size()); memcpy(out.data(),c.contents,bytes);
   write_output(out); metrics([device.name UTF8String],setup,kernel);
  } catch(const std::exception& e) { std::cerr<<e.what()<<"\n"; return 1; }
 }
}
