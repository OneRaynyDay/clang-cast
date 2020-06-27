//===--- ClangCast.h - clang-cast -------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANG_QUERY_QUERY_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANG_QUERY_QUERY_H

#include <exception>
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/OperationKinds.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"

namespace clang {
namespace cppcast {

/// Enumerations for cast types
/// The ordering of these enums is important.
///
/// C-style casts in clang are performed incrementally:
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
/// in terms of C-style casts.
///
/// CC_ConstCast
/// ------------
/// int x = 1;
/// const int& y = x;
/// const_cast<int&>(y);
/// A conversion from the same time but with different qualifiers.
///
/// CC_StaticCast
/// -------------
/// static_cast<int>(true);
/// Static cast can perform implicit conversions between types,
/// call explicitly defined conversion functions such as operator(),
/// and cast up and down an inheritance hierarchy (given access),
/// and more.
///
/// CC_CStyleCast
/// -------------
/// (bool) 0;
/// There are some cases where none of the above casts are possible,
/// or suitable for replacement for C-style casts, such as when
/// static_cast cannot cast DerivedToBase due to insufficient access,
/// or C-style casting templated types (which can be any of the casts
/// enumerated above, including the DerivedToBase case). It is generally
/// good to convert all C-style casts to something of lower power, but
/// sometimes it's not possible.
///
/// CC_InvalidCast
/// --------------
/// This maps to the set of CastKind::CK_* that are not possible to
/// generate in C++. If this enum is encountered, something is wrong.
///
/// Please refer to getCastType and castHelper for more information.
enum CXXCast : std::uint8_t {
  CC_DynamicCast,
  CC_ConstCast,
  CC_StaticCast,
  CC_ReinterpretCast,
  CC_CStyleCast,
  CC_InvalidCast
};

// forward declare for helper
CXXCast getCastType(const CastExpr* CastExpression,
                    const QualType& CanonicalSubExprType,
                    const QualType& CanonicalCastType);

namespace details {

/// Determines whether Base is accessible from Derived class.
///
/// \returns true if Base is accessible from Derived or are the same class, and
///          false if Base is not accessible from Derived or are
///          unrelated classes
bool isAccessible(const CXXRecordDecl* Base,
                  const CXXRecordDecl* Derived) {
  if (!Base || !Derived)
    return false;

  if(clang::declaresSameEntity(Derived, Base)) {
    // The class's contents is always accessible to itself.
    return true;
  }

  for (const CXXBaseSpecifier &Specifier : Derived->bases()) {
    // This should already be canonical
    const QualType& BaseType = Specifier.getType();
    CXXRecordDecl* BaseClass = BaseType.getTypePtrOrNull()->getAsCXXRecordDecl();

    if(Specifier.getAccessSpecifier() == clang::AccessSpecifier::AS_public &&
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
CXXCast getBaseDerivedCast(const CXXRecordDecl* Base, const CXXRecordDecl* Derived) {
  if (!Base || !Derived) {
    return CXXCast::CC_CStyleCast;
  }
  if (!details::isAccessible(Base, Derived))
    return CXXCast::CC_CStyleCast;
  else
    return CXXCast::CC_StaticCast;
}


/// A helper function for getCastKindFromCStyleCast, which
/// determines the least power of cast required by recursing
/// CastExpr AST nodes until a non-cast expression has been reached.
///
/// \return CXXCast enum corresponding to the lowest power cast required.
CXXCast castHelper(const Expr* Expression,
                   CXXCast Cast,
                   const QualType& CanonicalSubExprType,
                   const QualType& CanonicalCastType) {
  const auto* CastExpression = dyn_cast<CastExpr>(Expression);

  // If it's not a cast expression, we've gone too far.
  if (!CastExpression)
    return Cast;
  // If it's a cast expression but is not a part of the explicit c-style cast,
  // we've also gone too far.
  const auto* ImplicitCastExpression = dyn_cast<ImplicitCastExpr>(Expression);
  if (ImplicitCastExpression && !ImplicitCastExpression->isPartOfExplicitCast())
    return Cast;

  Cast = std::max(Cast, cppcast::getCastType(CastExpression,
                                             CanonicalSubExprType,
                                             CanonicalCastType));
  return castHelper(CastExpression->getSubExpr(),
                    Cast,
                    CanonicalSubExprType,
                    CanonicalCastType);
}

} // namespace details

/// Main function for determining CXX cast type.
/// Recursively demote from const cast level.
CXXCast getCastKindFromCStyleCast(const CStyleCastExpr* CastExpression) {
  if (!CastExpression)
    return CXXCast::CC_InvalidCast;

  const Expr* SubExpression = CastExpression->getSubExprAsWritten();
  if (!SubExpression)
    return CXXCast::CC_InvalidCast;

  QualType CanonicalSubExpressionType = SubExpression->getType().getCanonicalType();
  QualType CanonicalCastType = CastExpression->getTypeAsWritten().getCanonicalType();

  return details::castHelper(CastExpression,
                             CXXCast::CC_ConstCast,
                             CanonicalSubExpressionType,
                             CanonicalCastType);
}

/// Given a CastExpr, determine from its CastKind and other metadata
/// the corresponding CXXCast to use.
/// Note that it's a CastExpr, which can be either CStyleCastExpr
/// or ImplicitCastExpr or any of its children.
///
/// \return CXXCast corresponding to the type of conversion.
CXXCast getCastType(const CastExpr* CastExpression,
                    const QualType& CanonicalSubExprType,
                    const QualType& CanonicalCastType) {
  const CastKind CastType = CastExpression->getCastKind();
  switch(CastType) {
    /// Reinterpret cast types
    case CastKind::CK_BitCast:
    case CastKind::CK_LValueBitCast:
    case CastKind::CK_LValueToRValueBitCast:
    case CastKind::CK_ReinterpretMemberPointer:
    case CastKind::CK_PointerToIntegral:
      return CXXCast::CC_ReinterpretCast;

    /// Static cast types
    // This cannot be expressed in the form of a C-style cast.
    case CastKind::CK_UncheckedDerivedToBase:
    case CastKind::CK_DerivedToBase: {
      // Special case:
      // The base class A is inaccessible (private)
      // so we can't static_cast. We can't reinterpret_cast
      // either because reinterpret casting to A* would point
      // to the data segment owned by Pad. We can't convert to C-style
      // in this case.
      //
      // struct A { int i; };
      // struct Pad { int i; };
      // class B: Pad, A {};
      //
      // A *f(B *b) { return (A*)(b); }
      //
      // We assume that the base class is unambiguous.
      const CXXRecordDecl* Base = CanonicalCastType.getTypePtr()->getPointeeCXXRecordDecl();
      const CXXRecordDecl* Derived = CanonicalSubExprType.getTypePtr()->getPointeeCXXRecordDecl();
      return details::getBaseDerivedCast(Base, Derived);
    }
    case CastKind::CK_BaseToDerived: {
      const CXXRecordDecl* Base = CanonicalSubExprType.getTypePtr()->getPointeeCXXRecordDecl();
      const CXXRecordDecl* Derived = CanonicalCastType.getTypePtr()->getPointeeCXXRecordDecl();
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
    case CastKind::CK_IntegralToPointer:
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

    /// const cast type
    case CastKind::CK_NoOp:
    case CastKind::CK_ArrayToPointerDecay:
    case CastKind::CK_LValueToRValue:
      return CXXCast::CC_ConstCast;

    /// dynamic cast type
    case CastKind::CK_Dynamic:
      return CXXCast::CC_DynamicCast;

    // Dependent types are left as they are.
    // TODO: Provide warning for dependent types encountered.
    case CastKind::CK_Dependent:
    // Built-in functions must be directly called and don't have
    // address. This is impossible for C-style casts.
    case CastKind::CK_BuiltinFnToFnPtr:
    // Union casts is not available in C++.
      return CXXCast::CC_CStyleCast;

    case CastKind::CK_ToUnion:
    // C++ does not officially support the Objective C extensions.
    // We mark these as invalid.
    // Objective C pointer types &
    // Objective C automatic reference counting (ARC) &
    // Objective C blocks
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

} // namespace cast
} // namespace clang
#endif