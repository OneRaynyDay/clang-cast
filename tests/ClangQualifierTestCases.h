#ifndef LLVM_CLANG_TOOLS_EXTRA_UNITTESTS_CLANG_CAST_CLANGQUALIFIERTESTCASES_H
#define LLVM_CLANG_TOOLS_EXTRA_UNITTESTS_CLANG_CAST_CLANGQUALIFIERTESTCASES_H

namespace testcases {

namespace modify {
/// TODO ADD TESTS

} // namespace modify

namespace constcheck {
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
static const char QualAddConstDiffLevelPtr[] = R"(
void f() {
  int*** x = nullptr;
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
static const char QualAddDiffLevelArrPtrConstData[] = R"(
void f() {
  double (*a)[2] {};
  (const double* (*)[2]) a;
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
static const char QualRemoveConstDiffLevelPtr[] = R"(
void f() {
  const int*** x = nullptr;
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
static const char QualRemoveDiffLevelArrPtrConstData[] = R"(
void f() {
  const double* (*a)[2] {};
  (double (*)[2]) a;
}
)";
static const char QualRemoveSimilarPtrsBeyondArrConstData[] = R"(
void f() {
  const double* const (* const a)[2] {};
  (double* const (* const)[2])(a);
}
)";

/// Volatile
/// add
static const char QualAddVolatile[] = R"(
void f() {
  int x = 0;
  (volatile int) x;
}
)";
static const char QualAddPtrToVolatile[] = R"(
void f() {
  int* x = nullptr;
  volatile int* y = (volatile int*) x;
}
)";
static const char QualAddVolatilePtr[] = R"(
void f() {
  int* x = nullptr;
  int* volatile y = (int* volatile) x;
}
)";
static const char QualAddVolatileDoublePtr[] = R"(
void f() {
  int** x = nullptr;
  int* volatile * volatile y = (int* volatile * volatile) x;
}
)";
static const char QualAddVolatileDiffLevelPtr[] = R"(
void f() {
  int*** x = nullptr;
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
static const char QualAddVolatilePtrToArr[] = R"(
void f() {
  double (*a)[2] {};
  (double(* volatile)[2]) a;
}
)";
static const char QualAddVolatilePtrToArrOfVolatilePtrs[] = R"(
void f() {
  double* (*a)[2] {};
  (double * volatile (* volatile)[2]) a;
}
)";
static const char QualAddArrPtrVolatileData[] = R"(
void f() {
  double (*a)[2] {};
  (volatile double(*)[2]) a;
}
)";
static const char QualAddDiffLevelArrPtrVolatileData[] = R"(
void f() {
  double (*a)[2] {};
  (volatile double* (*)[2]) a;
}
)";
static const char QualRemoveSimilarPtrsBeyondArrVolatileData[] = R"(
void f() {
  volatile double* volatile (* volatile a)[2] {};
  (double* volatile (* volatile)[2])(a);
}
)";
/// remove
static const char QualRemoveVolatile[] = R"(
void f() {
  volatile int x = 0;
  (int) x;
}
)";
static const char QualRemovePtrToVolatile[] = R"(
void f() {
  volatile int* x = nullptr;
  int* y = (int*) x;
}
)";
static const char QualRemoveVolatilePtr[] = R"(
void f() {
  int* volatile x = nullptr;
  int* y = (int*) x;
}
)";
static const char QualRemoveVolatileDoublePtr[] = R"(
void f() {
  int* volatile * volatile x = nullptr;
  int** y = (int**) x;
}
)";
static const char QualRemoveVolatileDiffLevelPtr[] = R"(
void f() {
  volatile int*** x = nullptr;
  int** y = (int**) x;
}
)";
static const char QualRemoveVolatileRef[] = R"(
void f() {
  int x = 1;
  volatile int& y = x;
  int& z = (int&) y;
}
)";
static const char QualRemoveVolatileArr[] = R"(
void f() {
  volatile double a[2] {1, 2};
  double* ca = (double*) a;
}
)";
static const char QualRemoveVolatilePtrToArr[] = R"(
void f() {
  double (* volatile a)[2] {};
  (double(*)[2]) a;
}
)";
static const char QualRemoveVolatilePtrToArrOfVolatilePtrs[] = R"(
void f() {
  double* volatile (* volatile a)[2] {};
  (double* (*)[2]) a;
}
)";
static const char QualRemoveArrPtrVolatileData[] = R"(
void f() {
  volatile double (*a)[2] {};
  (double(*)[2]) a;
}
)";
static const char QualRemoveDiffLevelArrPtrVolatileData[] = R"(
void f() {
  volatile double* (*a)[2] {};
  (double (*)[2]) a;
}
)";

/// Restricted
/// add
static const char QualAddRestrictPtr[] = R"(
void f() {
  int* x = nullptr;
  int* __restrict y = (int* __restrict) x;
}
)";
static const char QualAddRestrictDoublePtr[] = R"(
void f() {
  int** x = nullptr;
  int* __restrict * __restrict y = (int* __restrict * __restrict) x;
}
)";
// Add another layer of pointers to decorate __restrict on
static const char QualAddRestrictDiffLevelPtr[] = R"(
void f() {
  int** x = nullptr;
  int* __restrict *** y = (int* __restrict ***) x;
}
)";
// Add another layers of pointers to decorate __restrict on
static const char QualAddRestrictArr[] = R"(
void f() {
  double* a[2] {};
  double* __restrict * ca = (double* __restrict *) a;
}
)";
static const char QualAddRestrictPtrToArr[] = R"(
void f() {
  double (*a)[2] {};
  (double(* __restrict)[2]) a;
}
)";
static const char QualAddRestrictPtrToArrOfRestrictPtrs[] = R"(
void f() {
  double* (*a)[2] {};
  (double* __restrict (* __restrict)[2]) a;
}
)";
// Add another layer of pointers to decorate __restrict on
static const char QualAddArrPtrRestrictData[] = R"(
void f() {
  double* (*a)[2] {};
  (double* __restrict (*)[2]) a;
}
)";
// Add another layer of pointers to decorate __restrict on
static const char QualAddDiffLevelArrPtrRestrictData[] = R"(
void f() {
  double (*a)[2] {};
  (double* __restrict *(*)[2]) a;
}
)";
/// remove
static const char QualRemoveRestrictPtr[] = R"(
void f() {
  int* __restrict x = nullptr;
  int* y = (int*) x;
}
)";
static const char QualRemoveRestrictDoublePtr[] = R"(
void f() {
  int* __restrict * __restrict x = nullptr;
  int** y = (int**) x;
}
)";
static const char QualRemoveRestrictDiffLevelPtr[] = R"(
void f() {
  int* __restrict *** x = nullptr;
  int** y = (int**) x;
}
)";
static const char QualRemoveRestrictArr[] = R"(
void f() {
  double* __restrict a[2] {};
  double** ca = (double**) a;
}
)";
static const char QualRemoveRestrictPtrToArr[] = R"(
void f() {
  double (* __restrict a)[2] {};
  (double(*)[2]) a;
}
)";
static const char QualRemoveRestrictPtrToArrOfRestrictPtrs[] = R"(
void f() {
  double* __restrict (* __restrict a)[2] {};
  (double* (*)[2]) a;
}
)";
static const char QualRemoveArrPtrRestrictData[] = R"(
void f() {
  double* __restrict (*a)[2] {};
  (double* (*)[2]) a;
}
)";
static const char QualRemoveDiffLevelArrPtrRestrictData[] = R"(
void f() {
  double* __restrict *(*a)[2] {};
  (double (*)[2]) a;
}
)";
static const char QualRemoveSimilarPtrsBeyondArrRestrictData[] = R"(
void f() {
  double* __restrict * __restrict (* __restrict a)[2] {};
  (double* * __restrict (* __restrict)[2])(a);
}
)";
} // namespace constcheck

} // namespace testcases

#endif // LLVM_PROJECT_CLANGQUALIFIERTESTCASES_H
