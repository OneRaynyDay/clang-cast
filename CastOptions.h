//===--- CastOptions.h - clang-cast -----------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANG_CAST_CAST_OPTIONS_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANG_CAST_CAST_OPTIONS_H

#include "clang/Rewrite/Frontend/FixItRewriter.h"
#include <cstdint>
#include <string>

namespace clang {
namespace cppcast {

/// Enumerations for cast types
/// The ordering of these enums is important.
///
/// C style casts in clang are performed incrementally:
/// - CStyleCastExpr
///   - ImplicitCastExpr
///     - ImplicitCastExpr
///     ...
///       - DeclRefExpr (for example)
///
/// Each one of the cast exprs may require a more "powerful" level of
/// casting. With the exception of dynamic cast, the rest are ordered
/// accordingly.
///
/// CC_DynamicCast
/// --------------
/// dynamic_cast<Base*>(derived_ptr);
/// A conversion from Base to Derived or vice versa that is
/// performed at RUNTIME. This is not possible to be expressed
/// in terms of C style casts.
///
/// CC_NoOpCast
/// -----------
/// This is either a cast to itself or an implicit conversion that
/// can be done without casting.
///
/// CC_ConstCast
/// ------------
/// int x = 1;
/// const int& y = x;
/// const_cast<int&>(y);
/// A conversion from the same type but with different qualifiers on the
/// multilevel pointer-array structure.
///
/// CC_StaticCast
/// -------------
/// static_cast<int>(true);
/// Static cast can perform logical conversions between types,
/// call explicitly defined conversion functions such as operator(),
/// and cast up and down an inheritance hierarchy (given access),
/// and more.
///
/// CC_ReinterpretCast
/// ------------------
/// int* x;
/// (bool*) x;
/// The above is a bitcast, and is generally the theme of reinterpret cast.
/// We reinterpret the bits of the data type into something else. This cast
/// will only cast A to B if sizeof(A) <= sizeof(B). Out of all the C++ casts,
/// this is the most "rule-breaking" and dangerous, and should be used
/// very sparingly.
///
/// CC_CStyleCast
/// -------------
/// template <typename T>
/// void foo() {
///     (T) 0;
/// }
/// There are some cases where none of the above casts are possible,
/// or suitable for replacement for C style casts, such as when
/// static_cast cannot cast DerivedToBase due to insufficient access,
/// or C style casting dependent (template) types (which can be any type
/// enumerated above, including the DerivedToBase case). It is generally
/// good to convert all C style casts to something of lower power, but
/// sometimes it's not possible without losing power.
///
/// CC_InvalidCast
/// --------------
/// This maps to the set of CastKind::CK_* that are not possible to
/// generate in C++. If this enum is encountered, something is wrong.
///
/// Please refer to getCastType and requireConstCast for more information.
///
/// NOTE: We can't make these enum-classes if we want to use the
/// llvm CommandLine.h macros to define lists.
/// we also make these masks so we can construct a simple bitmask for testing
/// inclusion.
enum CXXCast {
  CC_DynamicCast = 0b1,
  CC_NoOpCast = 0b10,
  CC_ConstCast = 0b100,
  CC_StaticCast = 0b1000,
  CC_ReinterpretCast = 0b10000,
  CC_CStyleCast = 0b100000,
  CC_InvalidCast = 0b1000000,
};

} // namespace cppcast

namespace cli {

using clang::cppcast::CXXCast;

enum ErrorOpts {
  EO_StaticCast = CXXCast::CC_StaticCast,
  EO_ReinterpretCast = CXXCast::CC_ReinterpretCast,
  EO_ConstCast = CXXCast::CC_ConstCast,
  EO_CStyleCast = CXXCast::CC_CStyleCast,
  EO_NoOpCast = CXXCast::CC_NoOpCast,
  EO_All = 0xffffffff,
};

// NOTE: There is no "fix_cstyle" because we can't fix them.
enum FixOpts {
  FO_StaticCast = CXXCast::CC_StaticCast,
  FO_ReinterpretCast = CXXCast::CC_ReinterpretCast,
  FO_ConstCast = CXXCast::CC_ConstCast,
  FO_NoOpCast = CXXCast::CC_NoOpCast,
  FO_All = 0xffffffff,
};

} // namespace cli

namespace rewriter {

class FixItRewriterOptions : public clang::FixItOptions {
public:
  FixItRewriterOptions(const std::string &RewriteSuffix)
      : RewriteSuffix(RewriteSuffix) {
    if (RewriteSuffix.empty()) {
      InPlace = true;
    } else {
      InPlace = false;
    }
    FixWhatYouCan = true;
  }

  std::string RewriteFilename(const std::string &Filename, int &fd) override {
    // Set fd to -1 to mean that the file descriptor is not yet opened.
    fd = -1;
    const auto NewFilename = Filename + RewriteSuffix;
    return NewFilename;
  }

private:
  std::string RewriteSuffix;
};

} // namespace rewriter

} // namespace clang

#endif
