#ifndef LLVM_PROJECT_CLANGCHANGEQUALIFIERTESTCASES_H
#define LLVM_PROJECT_CLANGCHANGEQUALIFIERTESTCASES_H

namespace testcases {
namespace changequal {

// all of these are going to be static casts/reinterpret casts + const cast if
// necessary.
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
  int *** __restrict (* const * volatile * __restrict x) [2] {};
}
)";
static const char ChangeNestedPointersUntilArrayReinterpret[] = R"(
void f() {
  int * const * volatile * __restrict (* const * volatile * __restrict p) [2] {};
  (double**** (***)[2]) p;
  // Expected type
  double **** __restrict (* const * volatile * __restrict x) [2] {};
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

} // namespace changequal
} // namespace testcases

#endif // LLVM_PROJECT_CLANGCHANGEQUALIFIERTESTCASES_H
