# clang-cast
A Clang libtool project that changes all C-style casts to C++ static casts.

To build this in clang's environment, do the following:

```shell script
cmake -G Ninja ../llvm -DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra" -DLLVM_BUILD_TESTS=ON -DCMAKE_CXX_STANDARD=20
ninja clang-cast
```