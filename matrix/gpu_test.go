package matrix

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// A host-only helper exercises the binary boundary with the exact shared
// arithmetic. It is explicitly NOT validation of CUDA/Metal compilation.
func TestGPUHelperBoundaryOnHost(t *testing.T) {
	compiler, err := exec.LookPath("c++")
	if err != nil {
		t.Skip("C++ compiler unavailable")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "helper.cpp")
	exe := filepath.Join(dir, "helper")
	code := `#include "host_io.h"
int main(){try {Input x=read_input();std::vector<Field> c(x.a.size());
for(uint i=0;i<x.k;i++)for(uint j=0;j<x.k;j++) {Field s=zero_field();
for(uint l=0;l<x.k;l++)s=add_field(s,mul_field(x.a[i*x.k+l],x.b[l*x.k+j]));c[i*x.k+j]=s;}
write_output(c);metrics("HOST TEST ONLY",0,0);
}catch(const std::exception& e){std::cerr<<e.what();return 1;}}`
	if err := os.WriteFile(src, []byte(code), 0600); err != nil {
		t.Fatal(err)
	}
	include, err := filepath.Abs("../gpu")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(compiler, "-std=c++17", "-O2", "-I", include, src, "-o", exe).CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if err := GPUSelfTest("cuda", exe); err != nil {
		t.Fatal(err)
	}
	testGPUFiles(t, exe)
	a, err := Random(7)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Random(7)
	if err != nil {
		t.Fatal(err)
	}
	c, stats, err := MultiplyGPU(a, b, "cuda", exe)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Device != "HOST TEST ONLY" {
		t.Fatal("wrong metrics")
	}
	if err := CheckProductRandom(a, b, c); err != nil {
		t.Fatal(err)
	}
	// Change a full diagonal: the error is invertible, so detection is certain
	// unless the entire random vector is zero.
	one := testVector(1)[0]
	for i := range c {
		c[i][i].Add(&c[i][i], &one)
	}
	if err := CheckProductRandom(a, b, c); err == nil {
		t.Fatal("corrupted product passed")
	}
	if _, _, err := MultiplyGPU(a, b, "cuda", filepath.Join(dir, "absent")); err == nil {
		t.Fatal("missing helper accepted")
	}
}
