//===--- CastUtils.h - clang-cast -------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
///
/// \file
/// This file contains utility functions for semantics and diagnostics.
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANG_CAST_CASTUTILS_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANG_CAST_CASTUTILS_H

#include "CastOptions.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/DeclCXX.h"

namespace clang {
namespace cppcast {

/// Given a cast type enum of the form CXXCasts::CC_{type}, return the
/// string representation of that respective type.
inline std::string cppCastToString(const CXXCast &Cast) {
  switch (Cast) {
  case CXXCast::CC_ConstCast:
    return "const_cast";
  case CXXCast::CC_StaticCast:
    return "static_cast";
  case CXXCast::CC_ReinterpretCast:
    return "reinterpret_cast";
    // Below are only used for summary diagnostics
  case CXXCast::CC_CStyleCast:
    return "C style cast";
  case CXXCast::CC_NoOpCast:
    return "No-op cast";
  default:
    llvm_unreachable("The cast should never occur.");
    return {};
  }
}

namespace {

template <typename Arg>
DiagnosticBuilder reportHelper(DiagnosticBuilder &Builder, Arg &&A) {
  return (Builder << std::forward<Arg>(A));
}

template <typename Arg, typename... Args>
DiagnosticBuilder reportHelper(DiagnosticBuilder &Builder, Arg &&A,
                               Args &&... AS) {
  Builder << std::forward<Arg>(A);
  return reportHelper(Builder, std::forward<Args>(AS)...);
}

} // namespace

/// Reports messages with a source location, typically used to address
/// specific code segments.
///
/// \tparam N length of string
/// \tparam Args variadic types to be accepted by DiagnosticBuilder
/// \param Engine the diagnostic engine to report with
/// \param Level diagnostic level
/// \param FormatString A C string with \p N characters with potential clang
/// format strings
/// \param Loc The starting location in the translation unit to
/// address
/// \param args data to be formatted into FormatString \return resulting
/// message object to be emitted.
template <unsigned N, typename... Args>
DiagnosticBuilder reportWithLoc(DiagnosticsEngine &Engine,
                                const DiagnosticsEngine::Level &Level,
                                const char (&FormatString)[N],
                                const SourceLocation &Loc, Args &&... AS) {
  unsigned ID = Engine.getCustomDiagID(Level, FormatString);
  // Binary left fold in C++14
  auto Builder = Engine.Report(Loc, ID);
  return reportHelper(Builder, std::forward<Args>(AS)...);
}

/// Reports messages, typically used to address a translation-unit/file wide
/// diagnostic. Refer to reportWithLoc for more information.
template <unsigned N, typename... Args>
DiagnosticBuilder report(DiagnosticsEngine &Engine,
                         DiagnosticsEngine::Level Level,
                         const char (&FormatString)[N], Args &&... AS) {
  unsigned ID = Engine.getCustomDiagID(Level, FormatString);
  auto Builder = Engine.Report(ID);
  return reportHelper(Builder, std::forward<Args>(AS)...);
}

namespace details {

/// Determines whether Base is accessible from Derived class.
///
/// \param Base the base class declaration
/// \param Derived the derived class declaration
/// \returns true if \p Base is accessible from \p Derived or are the same
/// class, and false if \p Base is not accessible from \p Derived or are
/// unrelated classes
inline bool isAccessible(const CXXRecordDecl *Base,
                         const CXXRecordDecl *Derived) {
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
/// \param Base the base class declaration
/// \param Derived the derived class declaration
/// \return CXXCast enum corresponding to the lowest power cast required.
inline CXXCast getBaseDerivedCast(const CXXRecordDecl *Base,
                                  const CXXRecordDecl *Derived) {
  assert(Base && Derived && "Base and Derived decls cannot be null.");
  if (!details::isAccessible(Base, Derived))
    return CXXCast::CC_CStyleCast;
  else
    return CXXCast::CC_StaticCast;
}

/// Removes a layer of pointers, member pointers, arrays.
///
/// \param T type to strip, assumed to be one of the above.
/// \param Context, the ASTContext to create the array type edge case.
/// \return type corresponding to \p T stripped of one indirection layer.
inline QualType stripLayer(const QualType &T, const ASTContext &Context) {
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

/// \param T some qualified type
/// \return true if T is a function pointer
inline bool isFunctionPtr(const QualType &T) {
  return T->isMemberFunctionPointerType() || T->isFunctionPointerType();
}

/// We define the types A and B to be locally similar if they are both
/// - pointer, i.e. int* is a pointer to an int
/// - member pointer, i.e. given struct t, int t::* const ptr is a
/// pointer to an int member of struct t.
/// - array / array of unknown bound, i.e. int a[2] and int a[], where the
/// latter is likely a partial 'extern' type.
inline bool isLocallySimilar(const QualType &A, const QualType &B) {
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
inline bool isTerminal(const QualType &A, const QualType &B) {
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

/// Some conversions have implicit conversions that aren't actually of no-op
/// power. An example is:
///
/// CStyleCastExpr 'void *' <NoOp>
/// `-ImplicitCastExpr 'void *' <BitCast> ...
///  `-ImplicitCastExpr 'const int *' <LValueToRValue>
///    `-DeclRefExpr 'const int *' lvalue 'const int *'
///
/// which is a BitCast conversion which is same power as reinterpret_cast.
/// When we use the intermediate implicit converted type for testing for
/// cast-away-constness, we don't want to include any non-implicit convertible
/// things like BitCast.
///
/// \param Expression Expr type of the subexpression.
/// \return QualType of the most implicit converted type
inline QualType getImplicitConvertibleType(const Expr *Expression) {
  const ImplicitCastExpr *ImplicitCastExpression =
      dyn_cast<ImplicitCastExpr>(Expression);

  while (ImplicitCastExpression &&
         ImplicitCastExpression->isPartOfExplicitCast()) {
    const auto &ImCastKind = ImplicitCastExpression->getCastKind();
    if (ImCastKind == CastKind::CK_NoOp ||
        ImCastKind == CastKind::CK_ArrayToPointerDecay ||
        ImCastKind == CastKind::CK_LValueToRValue)
      break;
    Expression = ImplicitCastExpression->getSubExpr();
    ImplicitCastExpression = dyn_cast<ImplicitCastExpr>(Expression);
  }
  return Expression->getType().getCanonicalType();
}

} // namespace details
} // namespace cppcast
} // namespace clang

#endif
