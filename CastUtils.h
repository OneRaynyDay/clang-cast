//===--- CastUtils.h - clang-cast ------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANG_CAST_CAST_UTILS_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANG_CAST_CAST_UTILS_H

#include "clang/AST/DeclCXX.h"
#include "clang/AST/ASTContext.h"
#include "CastOptions.h"

namespace clang {
namespace cppcast {

template <unsigned N, typename... Args>
DiagnosticBuilder reportWithLoc(DiagnosticsEngine &Engine,
                                const DiagnosticsEngine::Level &Level,
                                const char (&FormatString)[N], const SourceLocation &Loc,
                                Args &&... args) {
  unsigned ID = Engine.getCustomDiagID(Level, FormatString);
  // Binary left fold
  return (Engine.Report(Loc, ID) << ... << std::forward<Args>(args));
}

template <unsigned N, typename... Args>
DiagnosticBuilder report(DiagnosticsEngine &Engine, DiagnosticsEngine::Level Level,
                         const char (&FormatString)[N], Args &&... args) {
  unsigned ID = Engine.getCustomDiagID(Level, FormatString);
  // Binary left fold
  return (Engine.Report(ID) << ... << std::forward<Args &&>(args));
}

namespace details {

/// Determines whether Base is accessible from Derived class.
///
/// \returns true if Base is accessible from Derived or are the same class, and
///          false if Base is not accessible from Derived or are
///          unrelated classes
bool isAccessible(const CXXRecordDecl *Base, const CXXRecordDecl *Derived) {
  if (!Base || !Derived)
    return false;

  if (clang::declaresSameEntity(Derived, Base)) {
    // The class's contents is always accessible to itself.
    return true;
  }

  for (const CXXBaseSpecifier &Specifier : Derived->bases()) {
    // This should already be canonical
    const QualType &BaseType = Specifier.getType();
    CXXRecordDecl *BaseClass = (*BaseType).getAsCXXRecordDecl();

    if (Specifier.getAccessSpecifier() == clang::AccessSpecifier::AS_public &&
        isAccessible(Base, BaseClass))
      return true;
  }

  // These two are unrelated classes.
  return false;
}

/// Determines the proper cast type for a Base to/from Derived conversion
/// based off of accessbility.
///
/// \return CXXCast enum corresponding to the lowest power cast required.
CXXCast getBaseDerivedCast(const CXXRecordDecl *Base,
                           const CXXRecordDecl *Derived) {
  assert(Base && Derived);
  if (!details::isAccessible(Base, Derived))
    return CXXCast::CC_CStyleCast;
  else
    return CXXCast::CC_StaticCast;
}

QualType stripLayer(const QualType &T, const ASTContext &Context) {
  if (T->isPointerType()) {
    const PointerType *PT = dyn_cast<PointerType>(T);
    return PT->getPointeeType();
  }
  if (T->isArrayType()) {
    const ArrayType *AT = Context.getAsArrayType(T);
    return AT->getElementType();
  }
  if (T->isMemberPointerType()) {
    const MemberPointerType *MPT = dyn_cast<MemberPointerType>(T);
    return MPT->getPointeeType();
  }
  llvm_unreachable("The type is not a pointer/array/member to pointer type.");
  return T;
}

bool isFunctionPtr(const QualType &T) {
  return T->isMemberFunctionPointerType() || T->isFunctionPointerType();
}

/// The types A and B are locally similar if
/// - pointer, i.e. `int*` is a pointer to an `int`.
/// - member pointer, i.e. given `struct t{};`, `int t::* const ptr` is a
/// pointer to an `int` member of struct `t`.
/// - array / array of unknown bound, i.e. `int a[2]` and `int a[]`, where the
/// latter is likely a partial `extern` type.
/// - both are of same terminal type.
bool isLocallySimilar(const QualType &A, const QualType &B) {
  bool AIsPtr = A->isPointerType();
  bool BIsPtr = B->isPointerType();
  bool AIsArr = A->isArrayType();
  bool BIsArr = B->isArrayType();
  bool AIsMemberPtr = A->isMemberPointerType();
  bool BIsMemberPtr = B->isMemberPointerType();

  bool LocallySimilar = (AIsMemberPtr && BIsMemberPtr) ||
                        (AIsPtr && BIsPtr && !AIsMemberPtr && !BIsMemberPtr) ||
                        (AIsArr && BIsArr);

  return LocallySimilar;
}

/// Either types are terminal if either one are not pointer-like types that
/// can be traversed.
bool isTerminal(const QualType &A, const QualType &B) {
  bool AIsPtr = A->isPointerType();
  bool BIsPtr = B->isPointerType();
  bool AIsArr = A->isArrayType();
  bool BIsArr = B->isArrayType();
  bool AIsMemberPtr = A->isMemberPointerType();
  bool BIsMemberPtr = B->isMemberPointerType();

  bool IsTerminal = !(AIsPtr || AIsArr || AIsMemberPtr) ||
                    !(BIsPtr || BIsArr || BIsMemberPtr);

  return IsTerminal;
}

} // namespace details
} // namespace cppcast
} // namespace clang

#endif
