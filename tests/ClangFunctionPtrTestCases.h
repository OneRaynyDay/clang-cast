#ifndef LLVM_PROJECT_CLANGFUNCTIONPTRTESTCASES_H
#define LLVM_PROJECT_CLANGFUNCTIONPTRTESTCASES_H

namespace testcases {
namespace funcptr {

// Out of all of these tests, we should ideally only identify the cases of
// FreeFunction and MemberFunction.

static const char Scalar[] = R"(
void f() {
  bool a {};
}
)";

static const char ArrOfFreeFunctionPtr[] = R"(
void f() {
  void (*a[2])(void){};
}
)";

static const char NestedFreeFunctionPtr[] = R"(
void f() {
  void (**a)(void) {};
}
)";

static const char FreeFunction[] = R"(
void f() {
  void (*a)(void) {};
}
)";

static const char ArrOfMemberFunction[] = R"(
struct t{};
void f() {
  void (t::* a[2])(void) const {};
}
)";

static const char NestedMemberFunction[] = R"(
struct t{};
void f() {
  void (t::** a)(void) const {};
}
)";

static const char MemberFunction[] = R"(
struct t{};
void f() {
  void (t::* a)(void) const {};
}
)";
} // namespace funcptr
} // namespace testcases

#endif // LLVM_PROJECT_CLANGFUNCTIONPTRTESTCASES_H
