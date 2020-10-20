//===-- ClangQualifierTestCases.h - clang-cast ------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
///
/// \file
/// This file contains test cases for
/// CStyleCastOperation::requireConstCast (defined in Cast.h)
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_TOOLS_EXTRA_UNITTESTS_CLANG_CAST_CLANGQUALIFIERTESTCASES_H
#define LLVM_CLANG_TOOLS_EXTRA_UNITTESTS_CLANG_CAST_CLANGQUALIFIERTESTCASES_H

namespace testcases {

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
static const char QualAddMemberPtrToConst[] = R"(
struct t{};
void f() {
  int t::* x = nullptr;
  const int t::* y = (const int t::*) x;
}
)";
static const char QualAddConstMemberPtr[] = R"(
struct t{};
void f() {
  int t::* x = nullptr;
  int t::* const y = (int t::* const) x;
}
)";
static const char QualAddConstDoubleMemberPtr[] = R"(
struct t{};
void f() {
  int t::* t::* x = nullptr;
  int t::* const t::* const y = (int t::* const t::* const) x;
}
)";
static const char QualAddConstDiffLevelMemberPtr[] = R"(
struct t{};
void f() {
  int t::* t::* t::* x = nullptr;
  const int t::* t::* y = (const int t::* t::*) x;
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
static const char QualAddConstMixedPtrTypes[] = R"(
struct t {};
void f() {
  double * t::* (t::* *a) [2];
  (const double * const t::* const (t::* const * const) [2]) a;
}
)";
static const char QualAddConstUnknownArrPtr[] = R"(
void f() {
  int* (*x) [] {};
  (const int* const (*)[]) x;
}
)";
static const char QualAddConstUnknownArrPtrToKnownArrPtr[] = R"(
void f() {
  int* (*x) [] {};
  (const int* const (*)[2]) x;
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
static const char QualRemoveMemberPtrToConst[] = R"(
struct t{};
void f() {
  const int t::* x = nullptr;
  int t::* y = (int t::*) x;
}
)";
static const char QualRemoveConstMemberPtr[] = R"(
struct t{};
void f() {
  int t::* const x = nullptr;
  int t::* y = (int t::*) x;
}
)";
static const char QualRemoveConstDoubleMemberPtr[] = R"(
struct t{};
void f() {
  int t::* const  t::* const x = nullptr;
  int t::* t::* y = (int t::* t::*) x;
}
)";
static const char QualRemoveConstDiffLevelMemberPtr[] = R"(
struct t{};
void f() {
  const int t::* t::* t::* x = nullptr;
  int t::* t::* y = (int t::* t::*) x;
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
  (double* const (* const)[2]) a;
}
)";
static const char QualRemoveConstMixedPtrTypes[] = R"(
struct t {};
void f() {
  const double * const t::* const (t::* const * const a) [2] {};
  (double * t::* (t::* *) [2]) a;
}
)";
static const char QualRemoveConstUnknownArrPtr[] = R"(
void f() {
  const int* const (*x) [] {};
  (int* (*)[]) x;
}
)";
static const char QualRemoveConstUnknownArrPtrToKnownArrPtr[] = R"(
void f() {
  const int* const (*x) [] {};
  (int* (*)[2]) x;
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
  (double* volatile (* volatile)[2]) a;
}
)";
static const char QualAddVolatileMixedPtrTypes[] = R"(
struct t {};
void f() {
  double * t::* (t::* *a) [2];
  (volatile double * volatile t::* volatile (t::* volatile * volatile) [2]) a;
}
)";
static const char QualAddVolatileUnknownArrPtr[] = R"(
void f() {
  int* (*x) [] {};
  (volatile int* volatile (*)[]) x;
}
)";
static const char QualAddVolatileUnknownArrPtrToKnownArrPtr[] = R"(
void f() {
  int* (*x) [] {};
  (volatile int* volatile (*)[2]) x;
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
static const char QualRemoveVolatileMixedPtrTypes[] = R"(
struct t {};
void f() {
  volatile double * volatile t::* volatile (t::* volatile * volatile a) [2] {};
  (double * t::* (t::* *) [2]) a;
}
)";
static const char QualRemoveVolatileUnknownArrPtr[] = R"(
void f() {
  volatile int* volatile (*x) [] {};
  (int* (*)[]) x;
}
)";
static const char QualRemoveVolatileUnknownArrPtrToKnownArrPtr[] = R"(
void f() {
  volatile int* volatile (*x) [] {};
  (int* (*)[2]) x;
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
static const char QualAddRestrictMixedPtrTypes[] = R"(
struct t {};
void f() {
  double * t::* (t::* *a) [2];
  (double * __restrict t::* __restrict (t::* __restrict * __restrict) [2]) a;
}
)";
static const char QualAddRestrictUnknownArrPtr[] = R"(
void f() {
  int* (*x) [] {};
  (int* __restrict (*)[]) x;
}
)";
static const char QualAddRestrictUnknownArrPtrToKnownArrPtr[] = R"(
void f() {
  int* (*x) [] {};
  (int* __restrict (*)[2]) x;
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
  (double* * __restrict (* __restrict)[2]) a;
}
)";
static const char QualRemoveRestrictMixedPtrTypes[] = R"(
struct t {};
void f() {
  double * __restrict t::* __restrict (t::* __restrict * __restrict a) [2] {};
  (double * t::* (t::* *) [2]) a;
}
)";
static const char QualRemoveRestrictUnknownArrPtr[] = R"(
void f() {
  int* __restrict (*x) [] {};
  (int* (*)[]) x;
}
)";
static const char QualRemoveRestrictUnknownArrPtrToKnownArrPtr[] = R"(
void f() {
  int* __restrict (*x) [] {};
  (int* (*)[2]) x;
}
)";

} // namespace constcheck

} // namespace testcases

#endif // LLVM_PROJECT_CLANGQUALIFIERTESTCASES_H
