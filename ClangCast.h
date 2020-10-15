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
/// or suitable for replacement for C-style casts, such as when
/// static_cast cannot cast DerivedToBase due to insufficient access,
/// or C-style casting dependent (template) types (which can be any type
/// enumerated above, including the DerivedToBase case). It is generally
/// good to convert all C-style casts to something of lower power, but
/// sometimes it's not possible without losing power.
///
/// CC_InvalidCast
/// --------------
/// This maps to the set of CastKind::CK_* that are not possible to
/// generate in C++. If this enum is encountered, something is wrong.
///
/// Please refer to getCastType and requireConstCast for more information.
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

  if (ImplicitCastExpression && !ImplicitCastExpression->isPartOfExplicitCast()) {
    return Cast;
  }

  Cast = std::max(Cast, cppcast::getCastType(CastExpression,
                                             CanonicalSubExprType,
                                             CanonicalCastType));
  return castHelper(CastExpression->getSubExpr(),
                    Cast,
                    CanonicalSubExprType,
                    CanonicalCastType);
}

/// NOTE: This does not strip the member pointer layers. For that,
/// please use stripMemberPtrLayer
QualType stripPtrLayer(const QualType &T) {
  const PointerType *PT = dyn_cast<PointerType>(T);
  return PT->getPointeeType();
}

QualType stripMemberPtrLayer(const QualType &T) {
  const MemberPointerType *MPT = dyn_cast<MemberPointerType>(T);
  return MPT->getPointeeType();
}

const Type* getMemberPtrClass(const QualType& T) {
  const MemberPointerType *MPT = dyn_cast<MemberPointerType>(T);
  return MPT->getClass();
}

/// NOTE: If we don't use ASTContext.getAsArrayType(), we will lose the
/// qualifiers on the element type.
QualType stripArrLayer(const QualType &T, const ASTContext* Context) {
  const ArrayType *AT = Context->getAsArrayType(T);
  return AT->getElementType();
}

QualType stripLayer (const QualType& T, const ASTContext* Context){
  if(T->isPointerType())
    return details::stripPtrLayer(T);
  if(T->isArrayType())
    return details::stripArrLayer(T, Context);
  if(T->isMemberPointerType())
    return details::stripMemberPtrLayer(T);
  // llvm_unreachable
  return T;
}

bool isFunctionPtr(const QualType& T) {
  return T->isMemberFunctionPointerType() || T->isFunctionPointerType();
}

/// The types A and B are locally similar if
/// - pointer, i.e. `int*` is a pointer to an `int`.
/// - member pointer, i.e. given `struct t{};`, `int t::* const ptr` is a pointer to an `int` member of struct `t`.
/// - array / array of unknown bound, i.e. `int a[2]` and `int a[]`, where the latter is likely a partial `extern` type.
/// - both are of same terminal type.
bool isLocallySimilar(const QualType& A, const QualType& B) {
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
bool isTerminal(const QualType& A, const QualType& B) {
  bool AIsPtr = A->isPointerType();
  bool BIsPtr = B->isPointerType();
  bool AIsArr = A->isArrayType();
  bool BIsArr = B->isArrayType();
  bool AIsMemberPtr = A->isMemberPointerType();
  bool BIsMemberPtr = B->isMemberPointerType();

  bool IsTerminal = !(AIsPtr || AIsArr || AIsMemberPtr) || !(BIsPtr || BIsArr || BIsMemberPtr);

  return IsTerminal;
}

/// \param SubExpr, a copy of QualType subexpression
/// \param CastType, a copy of QualType cast type
/// \param Context, the ASTContext pointer used for auxilliary functions
/// \param Pedantic, if false, we should follow clang's extensions,
///                  otherwise follow the standard
/// \return true if the qualifier is downcasted from the possibly nested ptr or
///         pod/array type, false otherwise.
///
/// NOTE: We are assuming that reinterpret_cast will have already taken care
/// of the downcasting of nested function pointers, and if we have
/// nested function pointers, they have the same qualifiers.
bool recurseDowncastCheck(const QualType& SubExpr,
                          const QualType& CastType,
                          const ASTContext* Context,
                          const bool Pedantic) {
  if (SubExpr.isMoreQualifiedThan(CastType)) {
    return true;
  }

  // If we follow clang's extensions, then the moment something is not locally similar,
  // we consider the source and destination types not equal and so we can return
  // false for any nested levels.
  if(!details::isLocallySimilar(SubExpr, CastType) && !Pedantic)
    return false;

  if(details::isTerminal(SubExpr, CastType))
    return false;


  QualType SubExprStripped = stripLayer(SubExpr, Context);
  QualType CastTypeStripped = stripLayer(CastType, Context);

  // Continue recursing for pointer types
  return recurseDowncastCheck(SubExprStripped, CastTypeStripped, Context, Pedantic);
}

} // namespace details

// TODO: Add tests for templates - how do we tell if templates are pointer types/ref types?
bool requireConstCast(const CStyleCastExpr* CastExpression,
                      const ASTContext* Context,
                      const bool Pedantic) {
  // We use the implicitly convertible type if possible
  QualType CanonicalSubExprType = CastExpression->getSubExpr()->getType().getCanonicalType();
  QualType CanonicalCastType = CastExpression->getTypeAsWritten().getCanonicalType();

  // Case 0 - We just cannot cast function pointers at the very beginning, regardless of whether it's being downcasted or not.
  if(details::isFunctionPtr(CanonicalCastType) || details::isFunctionPtr(CanonicalSubExprType)) {
    return false;
  }

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
  return details::recurseDowncastCheck(CanonicalSubExprType, CanonicalCastType, Context, Pedantic);
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

/// This converts From(the cast type) into To(subexpression type)'s qualifiers
/// to prepare for const_cast.
///
/// For example:
/// const int* const (* const x) [2];
/// (int***) x;
///
/// will yield (int* const* const* const) because const_cast will only modify the
/// qualifiers where they are both locally similar
/// (they stop becoming similar at array vs. pointer)
///
/// We need this to first perform static/reinterpret casts and then const cast.
/// In order to do this, we must take the cast type and change its qualifiers
/// so that it can be performed by static/reinterpret cast first.
///
/// NOTE: There is only one case where we'd need to modify qualifiers and that is for
/// function pointers. Const cast cannot change qualifiers on function pointers.
///
/// \param From, the CastType, which needs to be modified to not require const cast
/// \param To, the SubExpression, which has specific qualifiers on it.
/// \param Context, ASTContext for helper
/// \return QualType mirroring From but with qualifiers on To.
QualType changeQualifiers(QualType From, const QualType& To, const ASTContext* Context, const bool Pedantic) {
  // If it's a function pointer, then we don't change the qualifier and we've
  // reached the end.
  if(details::isFunctionPtr(From))
    return From;

  // We're changing qualifiers because it'd be casting away constness.
  // If we follow the standard, we could be casting away constness down to the
  // terminal level.
  // If we follow clang's extensions, we could be casting away constness until
  // we've reached a non-similar stage.
  if ((!details::isLocallySimilar(From, To) && !Pedantic) || details::isTerminal(From, To)) {
    From.setLocalFastQualifiers(To.getLocalFastQualifiers());
    return From;
  }

  // TODO: Clang-cast does not support VLA's yet
  assert (!From->isVariableArrayType());
  auto StrippedTo = details::stripLayer(To, Context);
  auto StrippedFrom = details::stripLayer(From, Context);

  auto Temp = changeQualifiers(StrippedFrom, StrippedTo, Context, Pedantic);
  // If they are locally similar and non-terminal, we can keep going down
  if (From->isPointerType()) {
    // modify the nested types
    From = Context->getPointerType(Temp);
  }
  else if (From->isMemberPointerType()) {
    const Type* FromClass = details::getMemberPtrClass(From);
    // modify the nested types
    From = Context->getMemberPointerType(Temp, FromClass);
  }
  else if (From->isConstantArrayType()) {
    const ConstantArrayType* AT = dyn_cast<ConstantArrayType>(From);
    // Don't assign yet because we need to change the qualifiers
    From = Context->getConstantArrayType(Temp,
                                         AT->getSize(),
                                         AT->getSizeExpr(),
                                         AT->getSizeModifier(),
                                         AT->getIndexTypeCVRQualifiers());
  }
  else if (From->isIncompleteArrayType()) {
    const IncompleteArrayType* IAT = dyn_cast<IncompleteArrayType>(From);
    From = Context->getIncompleteArrayType(Temp,
                                           IAT->getSizeModifier(),
                                           IAT->getIndexTypeCVRQualifiers());
  }
  // Unwrap the references and reconstruct them
  // but we don't need to strip To here (lvalue-to-rvalue would've already happened)
  else if (From->isLValueReferenceType()) {
    From = Context->getLValueReferenceType(Temp);
  }
  else if (From->isRValueReferenceType()) {
    From = Context->getRValueReferenceType(Temp);
  }

  From.setLocalFastQualifiers(To.getLocalFastQualifiers());
  return From;
}

/// Given a cast type enum of the form CXXCasts::CC_{type}, return the
/// string representation of that respective type.
std::string cppCastToString(const CXXCast& Cast){
  switch (Cast){
    case CXXCast::CC_ConstCast : return "const_cast";
    case CXXCast::CC_StaticCast: return "static_cast";
    case CXXCast::CC_ReinterpretCast: return "reinterpret_cast";
    case CXXCast::CC_DynamicCast: return "dynamic_cast";
    default:
      // we're passing in a non-cpp cast type.
      // TODO llvm_unreachable
      return {};
  }
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
