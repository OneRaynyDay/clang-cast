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
/// Adding const doesn't require const_cast
static const char QualAddConst[] = R"(
void f() {
  int x = 0;
  (const int) x;
}
)";
static const char QualAddPtrToConst[] = R"(
void f() {
  int* x = nullptr;
  const int* y = (const int*) x;
}
)";
static const char QualAddConstPtr[] = R"(
void f() {
  int* x = nullptr;
  int* const y = (int* const) x;
}
)";
static const char QualAddConstDoublePtr[] = R"(
void f() {
  int** x = nullptr;
  int* const * const y = (int* const * const) x;
}
)";
static const char QualAddConstRef[] = R"(
void f() {
  int x = 1;
  int& y = x;
  const int& z = (const int&) y;
}
)";
static const char QualAddConstArr[] = R"(
void f() {
  double a[2] {1, 2};
  const double* ca = (const double*) a;
}
)";
static const char QualAddConstPtrToArr[] = R"(
void f() {
  double (*a)[2] {};
  (double(* const)[2]) a;
}
)";
static const char QualAddConstPtrToArrOfConstPtrs[] = R"(
void f() {
  double* (*a)[2] {};
  (double * const (* const)[2]) a;
}
)";
static const char QualAddArrPtrConstData[] = R"(
void f() {
  double (*a)[2] {};
  (const double(*)[2]) a;
}
)";
/// Removing const MIGHT require const_cast
static const char QualRemoveConst[] = R"(
void f() {
  const int x = 0;
  (int) x;
}
)";
static const char QualRemovePtrToConst[] = R"(
void f() {
  const int* x = nullptr;
  int* y = (int*) x;
}
)";
static const char QualRemoveConstPtr[] = R"(
void f() {
  int* const x = nullptr;
  int* y = (int*) x;
}
)";
static const char QualRemoveConstDoublePtr[] = R"(
void f() {
  int* const * const x = nullptr;
  int** y = (int**) x;
}
)";
static const char QualRemoveConstRef[] = R"(
void f() {
  int x = 1;
  const int& y = x;
  int& z = (int&) y;
}
)";
static const char QualRemoveConstArr[] = R"(
void f() {
  const double a[2] {1, 2};
  double* ca = (double*) a;
}
)";
static const char QualRemoveConstPtrToArr[] = R"(
void f() {
  double (* const a)[2] {};
  (double(*)[2]) a;
}
)";
static const char QualRemoveConstPtrToArrOfConstPtrs[] = R"(
void f() {
  double* const (* const a)[2] {};
  (double* (*)[2]) a;
}
)";
static const char QualRemoveArrPtrConstData[] = R"(
void f() {
  const double (*a)[2] {};
  (double(*)[2]) a;
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
static const char QualAddVolatileArr[] = R"(
void f() {
  double a[2] {1, 2};
  volatile double* ca = (volatile double*) a;
}
)";
static const char QualAddVolatileArrPtr[] = R"(
void f() {
  double a[2] {1, 2};
  (volatile double(*)[2]) &a;
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
static const char QualAddRestrictedArr[] = R"(
void f() {
  double a[2] {1, 2};
  double* __restrict ca = (double* __restrict) a;
}
)";
static const char QualAddRestrictedArrPtr[] = R"(
void f() {
  double a[2] {1, 2};
  (double(* __restrict)[2]) &a;
}
)";

} // namespace testcases

#endif // LLVM_PROJECT_CLANGQUALIFIERTESTCASES_H
