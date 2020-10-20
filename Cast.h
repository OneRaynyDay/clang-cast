//===--- Cast.h - clang-cast ------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
///
/// \file
/// This file contains classes that manage semantics of C style casts.
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANG_CAST_CAST_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANG_CAST_CAST_H

#include "CastOptions.h"
#include "CastUtils.h"
#include "clang/AST/OperationKinds.h"
#include <exception>

//===----------------------------------------------------------------------===//
// CStyleCastOperation
//===----------------------------------------------------------------------===//

namespace clang {
namespace cppcast {

/// CStyleCastOperation is responsible for capturing a CStyleCastExpr AST node
/// and perform some basic semantic analysis on the C style cast's equivalent in
/// C++ explicit cast expressions.
///
/// This class does not have any ownership semantics for the CStyleCastExpr
/// itself, nor does it have ownership semantics for the underlying Context that
/// the CStyleCastExpr is from.
///
/// Note that although some functions are similar to the Sema library, such as
/// CastsAwayConstness vs. requireConstCast, it is a much simpler version as we
/// assume compilation is successful and we are restricted to C++. The reason
/// Sema was not used here is because the anonymous namespaces and static
/// visibility of the original functions require leaking existing abstractions
/// and a large refactoring in the fundamental Clang codebase.
class CStyleCastOperation {
  /// The main expression captured by a matcher
  const CStyleCastExpr &MainExpr;

  /// The subexpression type in the C style cast.
  /// For example:
  /// \code
  /// (int) 3.2f;
  /// \endcode
  ///
  /// the subexpression is 3.2f, and its type is float.
  const QualType SubExprType;

  /// The cast type in the C style cast.
  /// For example:
  /// \code
  /// (int) 3.2f;
  /// \endcode
  ///
  /// the cast type is int.
  const QualType CastType;

  /// The context that the CStyleCastExpr belongs to.
  const ASTContext &Context;

  /// The engine in the context responsible for printing diagnostics
  const DiagnosticsEngine &DiagEngine;

  /// Whether or not the generated code should comply with -pedantic
  const bool Pedantic;

public:
  /// Initializes a new CStyleCastOperation
  /// \param CastExpr node to perform semantic analysis on
  /// \param Context the context that CastExpr belongs to
  /// \param Pedantic whether we should generate code that complies with
  /// -pedantic and -pedantic-errors
  ///
  /// Note that we are canonicalizing the subexpression and cast types. We don't
  /// yet provide typedef-preserving code generation.
  CStyleCastOperation(const CStyleCastExpr &CastExpr, const ASTContext &Context,
                      const bool Pedantic)
      : MainExpr(CastExpr),
        SubExprType(
            CastExpr.getSubExprAsWritten()->getType().getCanonicalType()),
        CastType(CastExpr.getTypeAsWritten().getCanonicalType()),
        Context(Context), DiagEngine(Context.getDiagnostics()),
        Pedantic(Pedantic) {}

  CStyleCastOperation() = delete;
  CStyleCastOperation(const CStyleCastOperation &) = delete;
  CStyleCastOperation(CStyleCastOperation &&) = delete;
  CStyleCastOperation &operator=(const CStyleCastOperation &) = delete;
  CStyleCastOperation &operator=(CStyleCastOperation &&) = delete;
  virtual ~CStyleCastOperation() = default;

  /// public accessor methods, some of which return reference handles.
  QualType getSubExprType() const { return SubExprType; }
  QualType getCastType() const { return CastType; }
  const CStyleCastExpr &getCStyleCastExpr() const { return MainExpr; }
  const Expr &getSubExprAsWritten() const {
    return *MainExpr.getSubExprAsWritten();
  }
  const ASTContext &getContext() const { return Context; }

  /// This method tests to see whether the conversion from SubExprType to
  /// CastType is "casting away constness", as the standard describes.
  ///
  /// The standard states that a conversion is casting away constness when there
  /// exists a cv-decomposition such that there exists no implicit qualification
  /// conversion from SubExprType to CastType.
  ///
  /// Clang, without -pedantic or -pedantic-error, allows a few exceptional
  /// cases, such as when two nested pointers diverge in type (pointer vs.
  /// array, for example), and the rest of the qualifiers are ignored in the
  /// cast-away-constness consideration. (exception: two member-pointers that
  /// are pointers to different classes are considered the same "type").
  ///
  /// Some other notable exceptions include variable-length arrays (VLA) being
  /// used in non-pedantic codebases, which we also allow.
  bool requireConstCast() const;

  /// This converts From(the cast type) into To(subexpression type)'s qualifiers
  /// to prepare for const_cast.
  /// \return QualType corresponding to CastType but with minimal qualifiers to
  /// satisfy for a non-pedantic conversion.
  ///
  /// For example:
  /// \code
  /// const int* const (* const x) [2];
  /// (int***) x;
  /// \endcode
  ///
  /// will yield (int* const* const* const) for typical, non-pedantic usage
  /// because const_cast will only modify the qualifiers where they are
  /// both locally similar (they stop being similar at array vs. pointer).
  ///
  /// We need this to first perform static/reinterpret casts and then const
  /// cast. In order to do this, we must take the cast type and change its
  /// qualifiers so that it can be performed by static/reinterpret cast first.
  ///
  /// NOTE: There is only one case where we'd need to modify qualifiers and that
  /// is for function pointers. Const cast cannot change qualifiers on function
  /// pointers.
  QualType changeQualifiers() const {
    return changeQualifierHelper(CastType, SubExprType);
  }

  /// Given the CStyleCastExpr, determine from its CastKind and other metadata
  /// to decide what kind of C++ style cast is appropriate, if any. This does
  /// not take into consideration const_cast and qualifiers. Use
  /// requireConstCast() to determine whether const_cast should be added.
  ///
  /// \return CXXCast corresponding to the type of conversion.
  CXXCast getCastKindFromCStyleCast() const { return castHelper(&MainExpr); }

private:
  /// Auxilliary diagnostic methods
  void warnMemberPointerClass(const QualType &SEType,
                              const QualType &CType) const;
  void errorPedanticVLA(const QualType &T) const;

  /// \param SEType, a copy of QualType subexpression
  /// \param CType, a copy of QualType cast type
  /// \return true if the const was casted away, false otherwise.
  ///
  /// IMPORTANT: We are assuming that reinterpret_cast will have already taken
  /// care of the downcasting of nested function pointers, and if we have nested
  /// function pointers, they have the same qualifiers.
  bool castAwayConst(const QualType &SEType, const QualType &CType) const;

  /// \param From, the CastType, which needs to be modified to not require const
  /// cast
  /// \param To, the SubExpression, which has specific qualifiers on it.
  /// \return QualType mirroring From but with qualifiers on To.
  QualType changeQualifierHelper(QualType From, const QualType &To) const;

  /// Recurse CastExpr AST nodes until a non-cast expression has been reached.
  /// \return CXXCast enum corresponding to the lowest power cast required.
  CXXCast castHelper(const Expr *Expression) const;

  /// Given a CastExpr, determine from its CastKind and other metadata
  /// the corresponding CXXCast to use (NOTE: this does not include
  ///     the additional const cast for qualifiers if it is
  ///     static/interpret. Use isQualifierModified for that.)
  /// Note that it's a CastExpr, which can be either CStyleCastExpr
  /// or ImplicitCastExpr or any of its children.
  ///
  /// \return CXXCast corresponding to the type of conversion.
  CXXCast getCastType(const CastExpr *CastExpression) const;
};

bool CStyleCastOperation::requireConstCast() const {
  // Case 0 - We just cannot cast function pointers at the very beginning,
  // regardless of whether it's being downcasted or not.
  if (details::isFunctionPtr(CastType) || details::isFunctionPtr(SubExprType)) {
    return false;
  }

  // We modify the types for references
  // Note that for our subexpr type, we use the type post-implicit conv.
  QualType ModifiedImpliedSubExprType =
      MainExpr.getSubExpr()->getType().getCanonicalType();
  QualType ModifiedCastType = CastType;

  // Case 1 - reference type:
  // remove the reference from both the subexpr and cast and add a pointer
  // level.
  if (ModifiedCastType->isReferenceType()) {
    ModifiedCastType = ModifiedCastType.getNonReferenceType();
    if (ModifiedImpliedSubExprType->isReferenceType()) {
      ModifiedImpliedSubExprType =
          ModifiedImpliedSubExprType.getNonReferenceType();
    }
    ModifiedCastType = Context.getPointerType(ModifiedCastType);
    ModifiedImpliedSubExprType =
        Context.getPointerType(ModifiedImpliedSubExprType);
  }

  // Case 2, 3 - pointer type & POD type
  // if the pointer qualifiers are downcasted at any level, then fail.
  // if the POD qualifiers are downcasted, then fail.
  return castAwayConst(ModifiedImpliedSubExprType, ModifiedCastType);
}

void CStyleCastOperation::warnMemberPointerClass(const QualType &SEType,
                                                 const QualType &CType) const {
  // Auxilliary: If the member pointers classes are
  // not the same, issue a warning.
  if (SEType->isMemberPointerType() && CType->isMemberPointerType()) {
    const MemberPointerType *MPSEType = dyn_cast<MemberPointerType>(SEType);
    const Type *SEClass = MPSEType->getClass();

    const MemberPointerType *MPCType = dyn_cast<MemberPointerType>(CType);
    const Type *CClass = MPCType->getClass();

    if (SEClass->getCanonicalTypeUnqualified() !=
        CClass->getCanonicalTypeUnqualified()) {
      reportWithLoc(
          Context.getDiagnostics(), DiagnosticsEngine::Warning,
          "C style cast performs a member-to-pointer cast from class %0 to "
          "%1, which are not equal",
          MainExpr.getExprLoc(), QualType(SEClass, /*Quals=*/0),
          QualType(CClass, /*Quals=*/0));
    }
  }
}

void CStyleCastOperation::errorPedanticVLA(const QualType &T) const {
  if (!Pedantic)
    return;
  // Auxilliary: If the type is variable length arrays (VLA)s, it should raise
  // warnings under --pedantic
  if (T->isVariableArrayType()) {
    reportWithLoc(Context.getDiagnostics(), DiagnosticsEngine::Error,
                  "detected variable length array %0 with --pedantic enabled",
                  MainExpr.getExprLoc(), T);
  }
}

bool CStyleCastOperation::castAwayConst(const QualType &SEType,
                                        const QualType &CType) const {
  if (SEType.isMoreQualifiedThan(CType)) {
    return true;
  }

  // If we follow clang's extensions, then the moment something is not locally
  // similar, we consider the source and destination types not equal and so we
  // can return false for any nested levels.
  if (!details::isLocallySimilar(SEType, CType) && !Pedantic)
    return false;

  // Auxiliary warnings during parsing
  warnMemberPointerClass(SEType, CType);
  errorPedanticVLA(SEType);
  errorPedanticVLA(CType);

  if (details::isTerminal(SEType, CType))
    return false;

  QualType SEStrippedType = details::stripLayer(SEType, Context);
  QualType CStrippedType = details::stripLayer(CType, Context);

  // Continue recursing for pointer types
  return castAwayConst(SEStrippedType, CStrippedType);
}

QualType CStyleCastOperation::changeQualifierHelper(QualType From,
                                                    const QualType &To) const {
  // If it's a function pointer, then we don't change the qualifier and we've
  // reached the end.
  if (details::isFunctionPtr(From))
    return From;

  // We're changing qualifiers because it'd be casting away constness.
  // If we follow the standard, we could be casting away constness down to the
  // terminal level.
  // If we follow clang's extensions, we could be casting away constness until
  // we've reached a non-similar stage.
  if ((!details::isLocallySimilar(From, To) && !Pedantic) ||
      details::isTerminal(From, To)) {
    From.setLocalFastQualifiers(To.getLocalFastQualifiers());
    return From;
  }

  auto StrippedTo = details::stripLayer(To, Context);
  auto StrippedFrom = details::stripLayer(From, Context);

  auto Temp = changeQualifierHelper(StrippedFrom, StrippedTo);
  // If they are locally similar and non-terminal, we can keep going down
  if (From->isPointerType()) {
    // modify the nested types
    From = Context.getPointerType(Temp);
  } else if (From->isMemberPointerType()) {
    const MemberPointerType *MPT = dyn_cast<MemberPointerType>(From);
    const Type *FromClass = MPT->getClass();
    // modify the nested types
    From = Context.getMemberPointerType(Temp, FromClass);
  } else if (From->isConstantArrayType()) {
    const ConstantArrayType *AT = dyn_cast<ConstantArrayType>(From);
    // Don't assign yet because we need to change the qualifiers
    From = Context.getConstantArrayType(Temp, AT->getSize(), AT->getSizeExpr(),
                                        AT->getSizeModifier(),
                                        AT->getIndexTypeCVRQualifiers());
  } else if (From->isIncompleteArrayType()) {
    const IncompleteArrayType *IAT = dyn_cast<IncompleteArrayType>(From);
    From = Context.getIncompleteArrayType(Temp, IAT->getSizeModifier(),
                                          IAT->getIndexTypeCVRQualifiers());
  } else if (From->isVariableArrayType()) {
    // The following can only work if we're not in --pedantic
    const VariableArrayType *VAT = dyn_cast<VariableArrayType>(From);
    Context.getVariableArrayType(
        Temp, VAT->getSizeExpr(), VAT->getSizeModifier(),
        VAT->getIndexTypeCVRQualifiers(), VAT->getBracketsRange());
  }
  // Unwrap the references and reconstruct them
  // but we don't need to strip To here (lvalue-to-rvalue would've already
  // happened)
  else if (From->isLValueReferenceType()) {
    From = Context.getLValueReferenceType(Temp);
  } else if (From->isRValueReferenceType()) {
    From = Context.getRValueReferenceType(Temp);
  }

  From.setLocalFastQualifiers(To.getLocalFastQualifiers());
  return From;
}

CXXCast CStyleCastOperation::castHelper(const Expr *Expression) const {
  const auto *CastExpression = dyn_cast<CastExpr>(Expression);

  // Base case - we have reached an expression that's not a CastExpr
  if (!CastExpression) {
    return CXXCast::CC_NoOpCast;
  }

  // If it's a cast expression but is not a part of the explicit c-style cast,
  // we've also gone too far.
  const auto *ImplicitCastExpression = dyn_cast<ImplicitCastExpr>(Expression);

  if (ImplicitCastExpression &&
      !ImplicitCastExpression->isPartOfExplicitCast()) {
    return CXXCast::CC_NoOpCast;
  }

  return std::max(getCastType(CastExpression),
                  castHelper(CastExpression->getSubExpr()));
}

CXXCast CStyleCastOperation::getCastType(const CastExpr *CastExpression) const {
  switch (CastExpression->getCastKind()) {
  /// No-op cast type
  case CastKind::CK_NoOp:
  case CastKind::CK_ArrayToPointerDecay:
  case CastKind::CK_LValueToRValue:
    return CXXCast::CC_NoOpCast;

  // Static cast (with extension) types
  case CastKind::CK_UncheckedDerivedToBase:
  case CastKind::CK_DerivedToBase: {
    /// Special case:
    /// The base class A is inaccessible (private)
    /// so we can't static_cast. We can't reinterpret_cast
    /// either because reinterpret casting to A* would point
    /// to the data segment owned by Pad. We can't convert to C style
    /// in this case.
    ///
    /// \code
    /// struct A { int i; };
    /// struct Pad { int i; };
    /// class B: Pad, A {};
    ///
    /// A *f(B *b) { return (A*)(b); }
    /// \endcode
    ///
    /// We assume that the base class is unambiguous.
    const CXXRecordDecl *Base = CastType->getPointeeCXXRecordDecl();
    const CXXRecordDecl *Derived = SubExprType->getPointeeCXXRecordDecl();
    return details::getBaseDerivedCast(Base, Derived);
  }
  case CastKind::CK_BaseToDerived: {
    const CXXRecordDecl *Base = SubExprType->getPointeeCXXRecordDecl();
    const CXXRecordDecl *Derived = CastType->getPointeeCXXRecordDecl();
    return details::getBaseDerivedCast(Base, Derived);
  }
  case CastKind::CK_FunctionToPointerDecay:
  case CastKind::CK_NullToPointer:
  case CastKind::CK_NullToMemberPointer:
  case CastKind::CK_BaseToDerivedMemberPointer:
  case CastKind::CK_DerivedToBaseMemberPointer:
  case CastKind::CK_MemberPointerToBoolean:
  case CastKind::CK_UserDefinedConversion:
  case CastKind::CK_ConstructorConversion:
  case CastKind::CK_PointerToBoolean:
  case CastKind::CK_ToVoid:
  // vector splats are constant size vectors that can be
  // broadcast assigned a single value.
  case CastKind::CK_VectorSplat:
  // Common integral/float cast types
  case CastKind::CK_IntegralCast:
  case CastKind::CK_IntegralToBoolean:
  case CastKind::CK_IntegralToFloating:
  case CastKind::CK_FixedPointCast:
  case CastKind::CK_FixedPointToIntegral:
  case CastKind::CK_IntegralToFixedPoint:
  case CastKind::CK_FixedPointToBoolean:
  case CastKind::CK_FloatingToIntegral:
  case CastKind::CK_FloatingToBoolean:
  case CastKind::CK_BooleanToSignedIntegral:
  case CastKind::CK_FloatingCast:
  // Floating complex cast types
  case CastKind::CK_FloatingRealToComplex:
  case CastKind::CK_FloatingComplexToReal:
  case CastKind::CK_FloatingComplexToBoolean:
  case CastKind::CK_FloatingComplexCast:
  case CastKind::CK_FloatingComplexToIntegralComplex:
  // Integral complex cast types
  case CastKind::CK_IntegralRealToComplex:
  case CastKind::CK_IntegralComplexToReal:
  case CastKind::CK_IntegralComplexToBoolean:
  case CastKind::CK_IntegralComplexCast:
  case CastKind::CK_IntegralComplexToFloatingComplex:
  // Atomic to non-atomic casts
  case CastKind::CK_AtomicToNonAtomic:
  case CastKind::CK_NonAtomicToAtomic:
  // OpenCL casts
  // https://godbolt.org/z/DEz8Rs
  case CastKind::CK_ZeroToOCLOpaqueType:
  case CastKind::CK_AddressSpaceConversion:
  case CastKind::CK_IntToOCLSampler:
    return CXXCast::CC_StaticCast;

  // Reinterpret cast types
  case CastKind::CK_BitCast:
  case CastKind::CK_LValueBitCast:
  case CastKind::CK_IntegralToPointer:
  case CastKind::CK_LValueToRValueBitCast:
  case CastKind::CK_ReinterpretMemberPointer:
  case CastKind::CK_PointerToIntegral:
    return CXXCast::CC_ReinterpretCast;

  // C style cast types
  // Dependent types are left as they are.
  case CastKind::CK_Dependent:
    return CXXCast::CC_CStyleCast;

  // Invalid cast types for C++
  // Union casts is not available in C++.
  case CastKind::CK_ToUnion:
  // Built-in functions must be directly called and don't have
  // address. This is impossible for C style casts.
  case CastKind::CK_BuiltinFnToFnPtr:
  // C++ does not officially support the Objective C extensions.
  // We mark these as invalid.
  // - Objective C pointer types &
  // - Objective C automatic reference counting (ARC)
  // - Objective C blocks
  // - etc
  case CastKind::CK_CPointerToObjCPointerCast:
  case CastKind::CK_BlockPointerToObjCPointerCast:
  case CastKind::CK_AnyPointerToBlockPointerCast:
  case CastKind::CK_ObjCObjectLValueCast:
  case CastKind::CK_ARCProduceObject:
  case CastKind::CK_ARCConsumeObject:
  case CastKind::CK_ARCReclaimReturnedObject:
  case CastKind::CK_ARCExtendBlockObject:
  case CastKind::CK_CopyAndAutoreleaseBlockObject:
  default:
    return CXXCast::CC_InvalidCast;
  }
}

} // namespace cppcast
} // namespace clang
#endif
