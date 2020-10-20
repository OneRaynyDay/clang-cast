//===--- CastOptions.h - clang-cast -----------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the enumerations and options that dictate behavior of
// the Matcher object defined in Matcher.h.
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANG_CAST_CAST_OPTIONS_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANG_CAST_CAST_OPTIONS_H

#include "clang/Rewrite/Frontend/FixItRewriter.h"
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
/// \code
/// dynamic_cast<Base*>(derived_ptr);
/// \endcode
///
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
/// \code
/// int x = 1;
/// const int& y = x;
/// const_cast<int&>(y);
/// \endcode
///
/// A conversion from the same type but with different qualifiers on the
/// multilevel pointer-array structure.
///
/// CC_StaticCast
/// -------------
/// \code
/// static_cast<int>(true);
/// \endcode
///
/// Static cast can perform logical conversions between types,
/// call explicitly defined conversion functions such as operator(),
/// and cast up and down an inheritance hierarchy (given access),
/// and more.
///
/// CC_ReinterpretCast
/// ------------------
/// \code
/// int* x;
/// (bool*) x;
/// \endcode
///
/// The above is a bitcast, and is generally the theme of reinterpret cast.
/// We reinterpret the bits of the data type into something else. This cast
/// will only cast A to B if sizeof(A) <= sizeof(B). Out of all the C++ casts,
/// this is the most "rule-breaking" and dangerous, and should be used
/// very sparingly.
///
/// CC_CStyleCast
/// -------------
/// \code
/// template <typename T>
/// void foo() {
///     (T) 0;
/// }
/// \endcode
///
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
/// NOTE: We are using enums instead of enum-classes for the following reasons:
/// - We can't use convenience functions from llvm CommandLine.h to define lists.
/// - we want to make these these values bitmasks for inclusivity testing, and
///   there is no implicit conversion from enum-class values to integral types.
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

/// Options for CLI to specify which of the following should raise an error
/// upon encountering CStyleCast with equivalent power.
///
/// NOTE: If a C style cast requires both const and static, having EO_StaticCast
/// is sufficient to trigger an error.
enum ErrorOpts {
  EO_StaticCast = CXXCast::CC_StaticCast,
  EO_ReinterpretCast = CXXCast::CC_ReinterpretCast,
  EO_ConstCast = CXXCast::CC_ConstCast,
  EO_CStyleCast = CXXCast::CC_CStyleCast,
  EO_NoOpCast = CXXCast::CC_NoOpCast,
  EO_All = 0xffffffff,
};

/// Options for CLI to specify which of C style casts should be fixed with
/// FixItWriters.
///
/// NOTE: If a C style cast requires both const and static, it is required to
/// have the bits of 'FO_StaticCast | FO_ConstCast' in the mask to apply a fix.
enum FixOpts {
  FO_StaticCast = CXXCast::CC_StaticCast,
  FO_ReinterpretCast = CXXCast::CC_ReinterpretCast,
  FO_ConstCast = CXXCast::CC_ConstCast,
  // NOTE: There is no "fix_cstyle" because we can't fix them.
  FO_NoOpCast = CXXCast::CC_NoOpCast,
  FO_All = 0xffffffff,
};

} // namespace cli

namespace rewriter {

/// Custom FixItOptions to allow users to emit to files with added suffix.
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
