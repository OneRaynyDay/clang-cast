//===--- ClangCast.h - clang-cast -------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANG_QUERY_QUERY_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANG_QUERY_QUERY_H

#include "clang/AST/ASTConsumer.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/OperationKinds.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include <exception>

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
enum class CXXCast : std::uint8_t {
  CC_DynamicCast,
  CC_NoOpCast,
  CC_ConstCast,
  CC_StaticCast,
  CC_ReinterpretCast,
  CC_CStyleCast,
  CC_InvalidCast
};

// forward declare for helper
CXXCast getCastType(const CastExpr *CastExpression,
                    const QualType &CanonicalSubExprType,
                    const QualType &CanonicalCastType);

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

// This class only exists while the Context is still alive
class CStyleCastOperation {
  const CStyleCastExpr &MainExpr;
  const QualType SubExprType;
  const QualType CastType;

  const ASTContext &Context;
  const DiagnosticsEngine &DiagEngine;
  const bool Pedantic;

public:
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

  // Public access methods
  QualType getSubExprType() const { return SubExprType; }

  QualType getCastType() const { return CastType; }

  const CStyleCastExpr &getCStyleCastExpr() const { return MainExpr; }

  const Expr &getSubExprAsWritten() const {
    return *MainExpr.getSubExprAsWritten();
  }

  const ASTContext &getContext() const { return Context; }

  bool requireConstCast() const {
    // Case 0 - We just cannot cast function pointers at the very beginning,
    // regardless of whether it's being downcasted or not.
    if (details::isFunctionPtr(CastType) ||
        details::isFunctionPtr(SubExprType)) {
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
    return recurseDowncastCheck(ModifiedImpliedSubExprType, ModifiedCastType);
  }

  /// This converts From(the cast type) into To(subexpression type)'s qualifiers
  /// to prepare for const_cast.
  ///
  /// For example:
  /// const int* const (* const x) [2];
  /// (int***) x;
  ///
  /// will yield (int* const* const* const) for typical, non-pedantic usage
  /// because const_cast will only modify the qualifiers where they are
  /// both locally similar (they stop being similar at array vs. pointer)
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

  /// Main function for determining CXX cast type.
  /// Recursively demote from const cast level.
  CXXCast getCastKindFromCStyleCast() const { return castHelper(&MainExpr); }

private:
  void WarnMemberPointerClass(const QualType &SEType,
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
        auto &DiagEngine = Context.getDiagnostics();
        const auto &LangOpts = Context.getLangOpts();
        unsigned ID = DiagEngine.getCustomDiagID(
            DiagnosticsEngine::Warning,
            "C style cast performs a member-to-pointer cast from class %0 to "
            "%1, which are not equal");
        DiagEngine.Report(MainExpr.getExprLoc(), ID)
            << QualType(SEClass, 0) << QualType(CClass, 0);
      }
    }
  }

  void ErrorPedanticVLA(const QualType &T) const {
    if (!Pedantic)
      return;
    // Auxilliary: If the type is variable length arrays (VLA)s, it should raise
    // warnings under --pedantic
    if (T->isVariableArrayType()) {
      auto &DiagEngine = Context.getDiagnostics();
      const auto &LangOpts = Context.getLangOpts();
      unsigned ID = DiagEngine.getCustomDiagID(
          DiagnosticsEngine::Error,
          "detected variable length array %0 with --pedantic enabled");
      DiagEngine.Report(MainExpr.getExprLoc(), ID) << T;
    }
  }

  /// \param SEType, a copy of QualType subexpression
  /// \param CType, a copy of QualType cast type
  /// \param Context, the ASTContext pointer used for auxilliary functions
  /// \param Pedantic, if false, we should follow clang's extensions,
  ///                  otherwise follow the standard
  /// \return true if the qualifier is downcasted from the possibly nested ptr
  /// or
  ///         pod/array type, false otherwise.
  ///
  /// NOTE: We are assuming that reinterpret_cast will have already taken care
  /// of the downcasting of nested function pointers, and if we have
  /// nested function pointers, they have the same qualifiers.
  bool recurseDowncastCheck(const QualType &SEType,
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
    WarnMemberPointerClass(SEType, CType);
    ErrorPedanticVLA(SEType);
    ErrorPedanticVLA(CType);

    if (details::isTerminal(SEType, CType))
      return false;

    QualType SEStrippedType = details::stripLayer(SEType, Context);
    QualType CStrippedType = details::stripLayer(CType, Context);

    // Continue recursing for pointer types
    return recurseDowncastCheck(SEStrippedType, CStrippedType);
  }

  /// \param From, the CastType, which needs to be modified to not require const
  /// cast
  /// \param To, the SubExpression, which has specific qualifiers on it.
  /// \param Context, ASTContext for helper
  /// \return QualType mirroring From but with qualifiers on To.
  QualType changeQualifierHelper(QualType From, const QualType &To) const {
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
      From = Context.getConstantArrayType(
          Temp, AT->getSize(), AT->getSizeExpr(), AT->getSizeModifier(),
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

  /// A helper function for getCastKindFromCStyleCast, which
  /// determines the least power of cast required by recursing
  /// CastExpr AST nodes until a non-cast expression has been reached.
  ///
  /// \return CXXCast enum corresponding to the lowest power cast required.
  CXXCast castHelper(const Expr *Expression) const {
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

  /// Given a CastExpr, determine from its CastKind and other metadata
  /// the corresponding CXXCast to use (NOTE: this does not include
  ///     the additional const cast for qualifiers if it is
  ///     static/interpret. Use isQualifierModified for that.)
  /// Note that it's a CastExpr, which can be either CStyleCastExpr
  /// or ImplicitCastExpr or any of its children.
  ///
  /// \return CXXCast corresponding to the type of conversion.
  CXXCast getCastType(const CastExpr *CastExpression) const {
    switch (CastExpression->getCastKind()) {
    /// No-op cast type
    case CastKind::CK_NoOp:
    case CastKind::CK_ArrayToPointerDecay:
    case CastKind::CK_LValueToRValue:
      return CXXCast::CC_NoOpCast;

    /// dynamic cast type
    case CastKind::CK_Dynamic:
      return CXXCast::CC_DynamicCast;

    /// Static cast types
    // This cannot be expressed in the form of a C style cast.
    case CastKind::CK_UncheckedDerivedToBase:
    case CastKind::CK_DerivedToBase: {
      // Special case:
      // The base class A is inaccessible (private)
      // so we can't static_cast. We can't reinterpret_cast
      // either because reinterpret casting to A* would point
      // to the data segment owned by Pad. We can't convert to C style
      // in this case.
      //
      // struct A { int i; };
      // struct Pad { int i; };
      // class B: Pad, A {};
      //
      // A *f(B *b) { return (A*)(b); }
      //
      // We assume that the base class is unambiguous.
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

    /// Reinterpret cast types
    case CastKind::CK_BitCast:
    case CastKind::CK_LValueBitCast:
    case CastKind::CK_IntegralToPointer:
    case CastKind::CK_LValueToRValueBitCast:
    case CastKind::CK_ReinterpretMemberPointer:
    case CastKind::CK_PointerToIntegral:
      return CXXCast::CC_ReinterpretCast;

    /// C style cast types
    // Dependent types are left as they are.
    case CastKind::CK_Dependent:
      return CXXCast::CC_CStyleCast;

    // Union casts is not available in C++.
    case CastKind::CK_ToUnion:
    // Built-in functions must be directly called and don't have
    // address. This is impossible for C style casts.
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
};

/// Given a cast type enum of the form CXXCasts::CC_{type}, return the
/// string representation of that respective type.
std::string cppCastToString(const CXXCast &Cast) {
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

} // namespace cppcast
} // namespace clang
#endif
