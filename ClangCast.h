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
/// CC_NoOpCast
/// -----------
/// This is a cast from a type to itself. The cast can be omitted.
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
  CC_NoOpCast,
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
    CXXRecordDecl* BaseClass = (*BaseType).getAsCXXRecordDecl();

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

/// Given a cast expression, determine whether the cast affects
/// modifiers. (This information cannot be found through CastKinds)
///
/// \return true if the qualifier is modified from the cast expression,
///         false otherwise.
//bool isQualifierModified(const QualType& CanonicalSubExprType,
//                         const QualType& CanonicalCastType) {
//  llvm::outs() << "The type: " << CanonicalSubExprType.getAsString() << " with cvr mask: " << CanonicalSubExprType.getLocalFastQualifiers() << "\n";
//  // Whenever we encounter an array, it doesn't matter if the qualifier is
//  // const or not. All of the below works:
//  //
//  //  double m[2];
//  //  reinterpret_cast<double*>(m);
//  //  reinterpret_cast<const double*>(m);
//  //  reinterpret_cast<const double* const>(m);
//  bool CurrentEquals = CanonicalSubExprType->isArrayType() || CanonicalSubExprType.getLocalFastQualifiers() ==
//                         CanonicalCastType.getLocalFastQualifiers();
//
//  if (!CurrentEquals) {
//    return true;
//  }
//
//  auto StripPtrLayer = [](const QualType& QualifiedType) -> QualType {
//    const PointerType *PtrType = dyn_cast<PointerType>(QualifiedType);
//    return PtrType->getPointeeType();
//  };
//
//  auto StripRefLayer = [](const QualType& QualifiedType) -> QualType {
//    return QualifiedType.getNonReferenceType();
//  };
//
//  auto StripArrayLayer = [](const QualType& QualifiedType) -> QualType {
//    const ArrayType *ArrType = dyn_cast<ArrayType>(QualifiedType);
//    return ArrType->getElementType();
//  };
//
//  // Case 1 - multilevel pointers/arrays
//  // According to the standards:
//  // "Two possibly multilevel pointers to the same type may be
//  // converted between each other, regardless of cv-qualifiers at each level."
//  //
//  // One can only cast arrays to pointer types and not vice versa, i.e.:
//  // int arr[] {1,2};
//  // (const int*) arr;
//  //
//  // We must also take care of the case of nested pointers to array.
//  // (const int(*)[2]) &arr;
//  // for example:
//  //
//  // COMPILES:
//  // (pointer to array of triple const pointers to const pointers to const doubles
//  // is OK because the base layer is double compared with pointer of const things
//  // so since the pointer itself is not const, we're fine)
//  // const double * const * (*a) [2];
//  // reinterpret_cast<double**>(a);
//  //
//  // FAILS(Warning):
//  // (pointer of array of const doubles fails because the base layer is double
//  // compared to const double)
//  // const double (*a) [2];
//  // reinterpret_cast<double**>(a);
//  //
//  // Clang warns with the following:
//  // warning: ISO C++ does not allow reinterpret_cast from
//  // 'const double (*)[2]' to 'double **' because it casts away qualifiers,
//  // even though the source and destination types are unrelated
//  // [-Wcast-qual-unrelated]
//  //
//  // Therefore if we see an array in the middle of the pointer chain, we stop
//  // checking beyond the type underneath it.
//  if (CanonicalCastType->isPointerType()) {
//    QualType StrippedCastType = StripPtrLayer(CanonicalCastType);
//    if (CanonicalSubExprType->isPointerType()) {
//      QualType StrippedSubExprType = StripPtrLayer(CanonicalSubExprType);
//      return isQualifierModified(StrippedSubExprType, StrippedCastType);
//    }
//    // Go one layer below array to deal with the ISO warning, and don't go
//    // any further.
//    if (CanonicalSubExprType->isArrayType()) {
//      QualType StrippedSubExprType = StripArrayLayer(CanonicalSubExprType);
//      return StrippedSubExprType.getLocalFastQualifiers() ==
//             StrippedCastType.getLocalFastQualifiers();
//    }
//  }
//
//  // Case 2 (fallthrough) - lvalue reference cast to r/lvalue reference
//  // It's the case that the SubExpr, even if it is a reference, it's not
//  // reflected in value categories in the AST. So we only remove ref
//  // on the cast type.
//  // Refer to requireConstCast comments for more information.
//  if(CanonicalCastType->isReferenceType()) {
//    return isQualifierModified(CanonicalSubExprType,
//                               StripRefLayer(CanonicalCastType));
//  }
//  // Case 1 - Root case: There are no more layers of pointers.
//  return false;
//}

QualType stripPtrLayer(const QualType &QualifiedType) {
  const PointerType *PtrType = dyn_cast<PointerType>(QualifiedType);
  return PtrType->getPointeeType();
}


QualType stripArrLayer(const QualType &QualifiedType, const ASTContext* Context) {
  const ArrayType *ArrType = Context->getAsArrayType(QualifiedType);
  return ArrType->getElementType();
}

bool qualifierDowncasted(const QualType &SubExpr, const QualType &CastType) {
  // const -> non-const downcast
  if (SubExpr.isConstQualified() && !CastType.isConstQualified())
    return true;
  // volatile -> non-volatile downcast
  if (SubExpr.isVolatileQualified() && !CastType.isVolatileQualified())
    return true;
  // restrict -> non-restrict downcast
  if (SubExpr.isRestrictQualified() && !CastType.isRestrictQualified())
    return true;
  return false;
}

/// \param SubExpr, a copy of QualType subexpression
/// \param CastType, a copy of QualType cast type
/// \param Context, the ASTContext pointer used for auxilliary functions
/// \param Skip, whether or not to skip a downcast
/// \return true if the qualifier is downcasted from the possibly nested ptr or
///         pod/array type, false otherwise.
bool recurseDowncastCheck(const QualType& SubExpr,
                          const QualType& CastType,
                          const ASTContext* Context,
                          bool& Skip) {
  if (Skip) {
    Skip = false;
  }
  else if (details::qualifierDowncasted(SubExpr, CastType)) {
    return true;
  }

  bool SubExprPtr = SubExpr->isPointerType();
  bool CastTypePtr = CastType->isPointerType();
  bool SubExprArr = SubExpr->isArrayType();
  bool CastTypeArr = CastType->isArrayType();

  llvm::outs() << "ehm..." << SubExpr.getAsString() << " and " << CastType.getAsString() << "..." << SubExprPtr << " " << CastTypePtr << " " << SubExprArr << " " << CastTypeArr << "\n\n\n";
  llvm::outs() << "qualifiers? : " << SubExpr.getLocalFastQualifiers() << " vs. " << CastType.getLocalFastQualifiers() << "\n";

  // Special edge case: clang treats arrays as a layer over the original type.
  // we simply peel over the array layer and return whatever's underneath.
  // NOTE: this disregards Skip, which is ok as well (since it would skip the array layer which can't have qualifiers)
  if(SubExprArr || CastTypeArr) {
    // if either can't be descended further (is not array or pointer), then false for no downcast occurred.
    if((!SubExprPtr && !SubExprArr) || (!CastTypePtr && !CastTypeArr))
      return false;
    // if they both can be descended, then cast them down 1 level and do a comparison.
    QualType SubExprStripped = SubExprPtr ? details::stripPtrLayer(SubExpr) : details::stripArrLayer(SubExpr, Context);
    QualType CastTypeStripped = CastTypePtr ? details::stripPtrLayer(CastType) : details::stripArrLayer(CastType, Context);
    llvm::outs() << "hmm... " << SubExprStripped.getAsString() << " vs. " << CastTypeStripped.getAsString() << "\n\n";
    llvm::outs() << "qualifiers? : " << SubExprStripped.getLocalFastQualifiers() << " vs. " << CastTypeStripped.getLocalFastQualifiers() << "\n";
    return details::qualifierDowncasted(SubExprStripped, CastTypeStripped);
  }

  // Continue recursing for pointer types
  if(SubExprPtr && CastTypePtr) {
    return recurseDowncastCheck(details::stripPtrLayer(SubExpr), details::stripPtrLayer(CastType), Context, Skip);
  }
  return false;
};


} // namespace details

// TODO: Add tests for templates - how do we tell if templates are pointer types/ref types?
bool requireConstCast(QualType CanonicalSubExprType,
                      QualType CanonicalCastType,
                      const ASTContext* Context) {
  // Implicit conversion can perform the first qualifier cast without
  // a const_cast.
  bool SkipFirstQualifiers = true;

  // Case 1 - reference type:
  // remove the reference from both the subexpr and cast and add a pointer level.
  if (CanonicalCastType->isReferenceType()) {
    CanonicalCastType = CanonicalCastType.getNonReferenceType();
    if (CanonicalSubExprType->isReferenceType()) {
      CanonicalSubExprType = CanonicalSubExprType.getNonReferenceType();
    }
    CanonicalCastType = Context->getPointerType(CanonicalCastType);
    CanonicalSubExprType = Context->getPointerType(CanonicalSubExprType);
  }

  // Case 2, 3 - pointer type & POD type
  // if the pointer qualifiers are downcasted at any level, then fail.
  // if the POD qualifiers are downcasted, then fail.
  return details::recurseDowncastCheck(CanonicalSubExprType, CanonicalCastType, Context, SkipFirstQualifiers);
}

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
                             // Start with NoOpCast(so we'll never hit dynamic)
                             CXXCast::CC_NoOpCast,
                             CanonicalSubExpressionType,
                             CanonicalCastType);
}

/// TODO: Test this with pointers, arrays, and references.
/// TODO: Test this with multi-level pointers like:
///       (const int***) (int*) doesn't need to change qualifiers
///       (const int*) (int***) doesn't need to change qualifiers
///       (const int**) (int**) DOES need to change qualifiers.
///       This just means the constness is only up to the least level of the
///       cast or subexpression type.
/// Given a QualType From with a set of qualifiers, return a copy of From
/// with the same underlying type but with the qualifiers modified to be To.
/// We require From and To to be canonical, otherwise it is undefined behavior.
///     (To be precise, we don't get rid of qualifiers from typedefs)
///
/// \param From, a copy of QualType cast expression
/// \param To, a copy of QualType subexpression
/// \return Res, a copy of From with To's (possibly nested) qualifiers
QualType changeQualifiers(QualType From, const QualType To, const ASTContext* Context) {
  // TODO: Remove this code duplication BS
  auto StripPtrLayer = [](const QualType& QualifiedType) -> QualType {
    const PointerType *PtrType = dyn_cast<PointerType>(QualifiedType);
    return PtrType->getPointeeType();
  };
  auto StripArrayLayer = [](const QualType& QualifiedType) -> QualType {
    const ArrayType *ArrType = dyn_cast<ArrayType>(QualifiedType);
    return ArrType->getElementType();
  };

  if (From->isPointerType()) {
    QualType StrippedFrom = StripPtrLayer(From);
    if (To->isPointerType()) {
      QualType StrippedTo = StripPtrLayer(To);
      From = Context->getPointerType(changeQualifiers(StrippedFrom, StrippedTo, Context));
    }
    else if (To->isArrayType()) {
      QualType StrippedTo = StripArrayLayer(To);
      From = Context->getPointerType(changeQualifiers(StrippedFrom, StrippedTo, Context));
    }
    // We've reached a terminal non-pointer type
    else {

    }
  }
  // We don't need to check if it's a reference type.

  QualType Res = From.getUnqualifiedType();
  Res.setLocalFastQualifiers(To.getLocalFastQualifiers());
  return Res;
}

/// Given a CastExpr, determine from its CastKind and other metadata
/// the corresponding CXXCast to use (NOTE: this does not include
///     the additional const cast for qualifiers if it is
///     static/interpret. Use isQualifierModified for that.)
/// Note that it's a CastExpr, which can be either CStyleCastExpr
/// or ImplicitCastExpr or any of its children.
///
/// \return CXXCast corresponding to the type of conversion.
CXXCast getCastType(const CastExpr* CastExpression,
                    const QualType& CanonicalSubExprType,
                    const QualType& CanonicalCastType) {
  const CastKind CastType = CastExpression->getCastKind();
  switch(CastType) {

    /// No-op cast type
    case CastKind::CK_NoOp:
    case CastKind::CK_ArrayToPointerDecay:
    case CastKind::CK_LValueToRValue:
      return CXXCast::CC_NoOpCast;

    /// dynamic cast type
    case CastKind::CK_Dynamic:
      return CXXCast::CC_DynamicCast;

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
      const CXXRecordDecl* Base = (*CanonicalCastType).getPointeeCXXRecordDecl();
      const CXXRecordDecl* Derived = (*CanonicalSubExprType).getPointeeCXXRecordDecl();
      return details::getBaseDerivedCast(Base, Derived);
    }
    case CastKind::CK_BaseToDerived: {
      const CXXRecordDecl* Base = (*CanonicalSubExprType).getPointeeCXXRecordDecl();
      const CXXRecordDecl* Derived = (*CanonicalCastType).getPointeeCXXRecordDecl();
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

    /// Reinterpret cast types
    case CastKind::CK_BitCast:
    case CastKind::CK_LValueBitCast:
    case CastKind::CK_IntegralToPointer:
    case CastKind::CK_LValueToRValueBitCast:
    case CastKind::CK_ReinterpretMemberPointer:
    case CastKind::CK_PointerToIntegral:
      return CXXCast::CC_ReinterpretCast;

    /// C-style cast types
    // Dependent types are left as they are.
    // TODO: Provide warning for dependent types encountered.
    case CastKind::CK_Dependent:
      return CXXCast::CC_CStyleCast;

    // Union casts is not available in C++.
    case CastKind::CK_ToUnion:
    // Built-in functions must be directly called and don't have
    // address. This is impossible for C-style casts.
    case CastKind::CK_BuiltinFnToFnPtr:
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
