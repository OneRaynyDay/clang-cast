//===-- ClangChangeQualifierTestCases.h - clang-cast ------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
///
/// \file
/// This file contains test cases for
/// CStyleCast::changeQualifiers (defined in Cast.h)
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_PROJECT_CLANGCHANGEQUALIFIERTESTCASES_H
#define LLVM_PROJECT_CLANGCHANGEQUALIFIERTESTCASES_H

/// NOTE: We are not performing an implicit cast conversion, so the types
/// are exactly decltype(p) when we pass it into changeQualifiers().
namespace testcases {
namespace changequal {
namespace extension {
static const char NoQualifierChange[] = R"(
void f() {
  const int * const p {};
  (const int * const) p;
  // Expected type
  const int * const x {};
}
)";
static const char NoQualifierChangeReinterpret[] = R"(
void f() {
  const int * const p {};
  (const double * const) p;
  // Expected type
  const double * const x {};
}
)";

// Change all of these pointer qualifiers down
static const char ChangeNestedPointers[] = R"(
void f() {
  const int * const * volatile * __restrict p {};
  (int***) p;
  // Expected type
  const int* const * volatile * __restrict x {};
}
)";
static const char ChangeNestedPointersReinterpret[] = R"(
void f() {
  const int * const * volatile * __restrict p {};
  (double****) p;
  // Expected type (note how we have 1 more layer of ptr)
  double* const * const * volatile * __restrict x {};
}
)";

// Stop the const cast up to an array type
static const char ChangeNestedPointersUntilArray[] = R"(
void f() {
  int * const * volatile * __restrict (* const * volatile * __restrict p) [2] {};
  (int*** (***)[2]) p;
  // Expected type
  int * const * volatile * __restrict (* const * volatile * __restrict x) [2] {};
}
)";
static const char ChangeNestedPointersUntilArrayReinterpret[] = R"(
void f() {
  int * const * volatile * __restrict (* const * volatile * __restrict p) [2] {};
  (double**** (***)[2]) p;
  // Expected type
  double ** const * volatile * __restrict (* const * volatile * __restrict x) [2] {};
}
)";
static const char NoModificationToMixedPtrTypes[] = R"(
struct t{};
void f() {
  double * __restrict t::* __restrict (t::* __restrict * __restrict a) [2];
  (double * t::* (t::* *) [2]) a;
  // Expected type
  double * __restrict t::* __restrict (t::* __restrict * __restrict x) [2];
}
)";

// The member function dropped const, but const_cast can't perform this
// operation. It's up to reinterpret_cast to perform this.
static const char DontChangeMemberFuncPtr[] = R"(
struct t{};
void f() {
  void (t::* p)(void) const {};
  (void (t::*)(void)) p;
  // Expected type
  void (t::* x)(void) {};
}
)";

static const char ChangeNestedPointersUntilMemberVsNot[] = R"(
struct t{};
void f() {
    const int* const t::* const t::* const p {};
    (int** t::*) p;
    // Expected type
    int** const t::* const x {};
}
)";
} // namespace extension

namespace pedantic {

static const char NoQualifierChange[] = R"(
void f() {
  const int * const p {};
  (const int * const) p;
  // Expected type
  const int * const x {};
}
)";
static const char NoQualifierChangeReinterpret[] = R"(
void f() {
  const int * const p {};
  (const double * const) p;
  // Expected type
  const double * const x {};
}
)";

// Change all of these pointer qualifiers down
static const char ChangeNestedPointers[] = R"(
void f() {
  const int * const * volatile * __restrict p {};
  (int***) p;
  // Expected type
  const int* const * volatile * __restrict x {};
}
)";
static const char ChangeNestedPointersReinterpret[] = R"(
void f() {
  const int * const * volatile * __restrict p {};
  (double****) p;
  // Expected type (note how we have 1 more layer of ptr)
  double* const * const * volatile * __restrict x {};
}
)";

// Stop the const cast up to an array type
static const char ChangeNestedPointersUntilArray[] = R"(
void f() {
  int * const * volatile * __restrict (* const * volatile * __restrict p) [2] {};
  (int*** (***)[2]) p;
  // Expected type
  int * const * volatile * __restrict (* const * volatile * __restrict x) [2] {};
}
)";
static const char ChangeNestedPointersUntilArrayReinterpret[] = R"(
void f() {
  int * const * volatile * __restrict (* const * volatile * __restrict p) [2] {};
  (double**** (***)[2]) p;
  // Expected type
  double ** const * volatile * __restrict (* const * volatile * __restrict x) [2] {};
}
)";
static const char NoModificationToMixedPtrTypes[] = R"(
struct t{};
void f() {
  double * __restrict t::* __restrict (t::* __restrict * __restrict a) [2];
  (double * t::* (t::* *) [2]) a;
  // Expected type
  double * __restrict t::* __restrict (t::* __restrict * __restrict x) [2];
}
)";

// The member function dropped const, but const_cast can't perform this
// operation. It's up to reinterpret_cast to perform this.
static const char DontChangeMemberFuncPtr[] = R"(
struct t{};
void f() {
  void (t::* p)(void) const {};
  (void (t::*)(void)) p;
  // Expected type
  void (t::* x)(void) {};
}
)";

static const char ChangeNestedPointersUntilMemberVsNot[] = R"(
struct t{};
void f() {
    const int* const t::* const t::* const p {};
    (int** t::*) p;
    // Expected type
    const int* const* const t::* const x {};
}
)";

} // namespace pedantic

} // namespace changequal
} // namespace testcases

#endif // LLVM_PROJECT_CLANGCHANGEQUALIFIERTESTCASES_H
