// CPU executable for testing the exact shared GPU arithmetic against Python.
#include "field.h"
#include <iostream>
int main() {
 Field a,b;
 while(std::cin>>a.v[0]) {
  for(int i=1;i<16;i++) std::cin>>a.v[i];
  for(int i=0;i<16;i++) std::cin>>b.v[i];
  if(!std::cin) return 1;
  Field c=mul_field(a,b),d=add_field(a,b);
  for(int i=0;i<16;i++) std::cout<<c.v[i]<<' ';
  for(int i=0;i<16;i++) std::cout<<d.v[i]<<' ';
  std::cout<<'\n';
 }
}
