#ifndef LLVM_CLANG_TOOLS_EXTRA_UNITTESTS_CLANG_CAST_CLANGCXXCASTTESTCASES_H
#define LLVM_CLANG_TOOLS_EXTRA_UNITTESTS_CLANG_CAST_CLANGCXXCASTTESTCASES_H

namespace testcases {

/// Const cast types
static const char NoOp[] = R"(
void f() {
  (int&&) 0;
}
)";
static const char ArrayToPointerDecay[] = R"(
void f() {
  char x[] = "";
  (char*) x;
}
)";
// NOTE: Unused, as C style casts cannot
//       perform this. It must be done implicitly.
//       (int&&) x is a NoOp, and std::move(x) is
//       FunctionToPointerDecay.
static const char LValueToRValue[] = R"(
void f() {
  int x;
  int y = x;
}
)";

/// Static cast types
static const char BaseToDerived[] = R"(
class A {};
class B: public A {};
class C: public B {};

void f() {
  A* a = nullptr;
  (C*) a;
}
)";
static const char DerivedToBase[] = R"(
class A {};
class B: public A {};
class C: public B {};

void f() {
  C* c = nullptr;
  (A*) c;
}
)";
// NOTE: Unused, as C style casts cannot
//       perform this. It must be done implicitly.
static const char UncheckedDerivedToBase[] = R"(
class A { public: void a(){} };
class B : public A {};

void f() {
    B *b;
    b->a();
}
)";
static const char FunctionToPointerDecay[] = R"(
void g() {}

void f() {
  (void (*)()) g;
}
)";
static const char NullToPointer[] = R"(
void f() {
  (void*) 0;
}
)";
static const char NullToMemberPointer[] = R"(
struct A {};
void f() {
  (int A::*) 0;
}
)";
static const char BaseToDerivedMemberPointer[] = R"(
struct A { int m; };
struct B : A {};
void f() {
  (int B::*) &A::m;
}
)";
static const char DerivedToBaseMemberPointer[] = R"(
struct A {};
struct B : A { int m; };
void f() {
  (int A::*) &B::m;
}
)";
static const char MemberPointerToBoolean[] = R"(
struct A { int m; };
void f() {
  (bool) &A::m;
}
)";
static const char UserDefinedConversion[] = R"(
struct A { operator int(); };

void f() {
  (int) A();
}
)";
static const char ConstructorConversion[] = R"(
struct A { A(int); };

void f() {
  (A) 10;
}
)";
static const char PointerToBoolean[] = R"(
void f() {
  (bool) nullptr;
}
)";
static const char ToVoid[] = R"(
void f() {
  (void) 0;
}
)";
static const char VectorSplat[] = R"(
void f() {
  typedef float float4 __attribute__((ext_vector_type(4)));
  using type = float4;
  (type) 0.0f;
}
)";
static const char IntegralCast[] = R"(
void f() {
  (long long int) 0u;
}
)";
static const char IntegralToBoolean[] = R"(
void f() {
  (bool) 10l;
}
)";
static const char IntegralToFloating[] = R"(
void f() {
  (float) 10l;
}
)";

// NOTE: Unused, as fixed points are not yet introduced into C++ standard.
//       nor the clang extensions.
static const char FixedPointCast[] = R"()";
// NOTE: Unused, as fixed points are not yet introduced into C++ standard.
//       nor the clang extensions.
static const char FixedPointToIntegral[] = R"()";
// NOTE: Unused, as fixed points are not yet introduced into C++ standard.
//       nor the clang extensions.
static const char IntegralToFixedPoint[] = R"()";
// NOTE: Unused, as fixed points are not yet introduced into C++ standard.
//       nor the clang extensions.
static const char FixedPointToBoolean[] = R"()";

static const char FloatingToIntegral[] = R"(
void f() {
  (int) 0.0f;
}
)";
static const char FloatingToBoolean[] = R"(
void f() {
  (bool) 0.0f;
}
)";
// TODO: Ask question
// NOTE: Unused, because AFAIK this is not possible, according to
//       the comments it will cast to -1/0 for true/false.
static const char BooleanToSignedIntegral[] = R"(
void f() {
  (int) true;
}
)";
static const char FloatingCast[] = R"(
void f() {
  (double) 0.0f;
}
)";
static const char FloatingRealToComplex[] = R"(
void f() {
  (_Complex long double) 1.0;
}
)";
static const char FloatingComplexToReal[] = R"(
void f() {
  _Complex long double c;
  (long double) c;
}
)";
static const char FloatingComplexToBoolean[] = R"(
void f() {
  _Complex long double c;
  (bool) c;
}
)";
static const char FloatingComplexCast[] = R"(
void f() {
  _Complex long double c;
  (_Complex float) c;
}
)";
static const char FloatingComplexToIntegralComplex[] = R"(
void f() {
  _Complex long double c;
  (_Complex int) c;
}
)";
static const char IntegralRealToComplex[] = R"(
void f() {
  (_Complex long long) 10l;
}
)";
static const char IntegralComplexToReal[] = R"(
void f() {
  _Complex long long c;
  (int) c;
}
)";
static const char IntegralComplexToBoolean[] = R"(
void f() {
  _Complex long long c;
  (bool) c;
}
)";
static const char IntegralComplexCast[] = R"(
void f() {
  _Complex long long c;
  (_Complex int) c;
}
)";
static const char IntegralComplexToFloatingComplex[] = R"(
void f() {
  _Complex long long c;
  (_Complex float) c;
}
)";
static const char AtomicToNonAtomic[] = R"(
void f() {
  _Atomic(int) c;
  (int) c;
}
)";
static const char NonAtomicToAtomic[] = R"(
void f() {
  int c;
  (_Atomic(int)) c;
}
)";

/// Reinterpret cast types
const char BitCast[] = R"(
void f() {
  char* x;
  (int *) x;
}
)";
const char LValueBitCast[] = R"(
void f() {
  char c;
  (bool&) c;
}
)";
static const char IntegralToPointer[] = R"(
void f() {
  (int*) 10l;
}
)";
// NOTE: Unused, as C style casts cannot
//       perform this. It must be done by bit_cast.
const char LValueToRValueBitCast[] = R"(
void f() {
  int i;
  std::bit_cast<float>(i);
}
)";
static const char ReinterpretMemberPointer[] = R"(
struct A { int val; };

void f() {
  int A::* ptr = &A::val;
  (bool A::*) ptr;
}
)";
static const char PointerToIntegral[] = R"(
#include <stdint.h>
void f() {
  (intptr_t) nullptr;
}
)";

/// C-style cast types
static const char Dependent[] = R"(
template <typename T>
void foo() {
    (T) 0;
}
)";

namespace edgecases {

static const char BaseToDerivedPrivateSpecifier[] = R"(
struct A { int i; };
struct Pad { int i; };
class B: Pad, A {};

B* foo(A *a) { return (B*)(a); }
)";

static const char DerivedToBasePrivateSpecifier[] = R"(
struct A { int i; };
struct Pad { int i; };
class B: Pad, A {};

A* foo(B *b) { return (A*)(b); }
)";

} // namespace edgecases

} // namespace testcases

#endif // LLVM_CLANG_TOOLS_EXTRA_UNITTESTS_CLANG_CAST_CLANGCXXCASTTESTCASES_H
