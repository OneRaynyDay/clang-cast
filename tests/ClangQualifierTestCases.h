#ifndef LLVM_CLANG_TOOLS_EXTRA_UNITTESTS_CLANG_CAST_CLANGQUALIFIERTESTCASES_H
#define LLVM_CLANG_TOOLS_EXTRA_UNITTESTS_CLANG_CAST_CLANGQUALIFIERTESTCASES_H

namespace testcases {

/// No-op
static const char QualNoOp[] = R"(
void f() {
  (bool) 0;
}
)";

/// Const
static const char QualAddConst[] = R"(
void f() {
  int x = 0;
  (const int) x;
}
)";
static const char QualAddConstPtr[] = R"(
void f() {
  int* x = nullptr;
  const int* y = (const int*) x;
}
)";
static const char QualAddConstDoublePtr[] = R"(
void f() {
  int** x = nullptr;
  const int** y = (const int**) x;
}
)";
static const char QualAddConstRef[] = R"(
void f() {
  int x = 1;
  int& y = x;
  const int& z = (const int&) y;
}
)";

/// Volatile
static const char QualAddVolatile[] = R"(
void f() {
  int x = 0;
  (volatile int) x;
}
)";
static const char QualAddVolatilePtr[] = R"(
void f() {
  int* x = nullptr;
  volatile int* y = (volatile int*) x;
}
)";
static const char QualAddVolatileDoublePtr[] = R"(
void f() {
  int** x = nullptr;
  volatile int** y = (volatile int**) x;
}
)";
static const char QualAddVolatileRef[] = R"(
void f() {
  int x = 1;
  int& y = x;
  volatile int& z = (volatile int&) y;
}
)";

/// Restricted
static const char QualAddRestrictedPtr[] = R"(
void f() {
  int* x = nullptr;
  int* __restrict y = (int* __restrict) x;
}
)";
static const char QualAddRestrictedDoublePtr[] = R"(
void f() {
  int** x = nullptr;
  int** __restrict y = (int** __restrict) x;
}
)";
static const char QualAddRestrictedRef[] = R"(
void f() {
  int x = 1;
  int& y = x;
  int& __restrict z = (int& __restrict) x;
}
)";

} // namespace testcases

#endif // LLVM_PROJECT_CLANGQUALIFIERTESTCASES_H
