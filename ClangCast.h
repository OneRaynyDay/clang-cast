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
#include "clang/AST/OperationKinds.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"

namespace clang {
namespace cppcast {

enum CXXCast : std::uint8_t {
  // We put DynamicCast at the beginning for now to catch errors
  CC_DynamicCast,
  // TODO comment
  CC_ConstCast,
  CC_StaticCast,
  CC_ReinterpretCast,
  CC_InvalidCast
};

// forward declare for helper
CXXCast getCastType(const CastKind);
namespace details {

CXXCast castHelper(const Expr* Expression, CXXCast Cast) {
  const auto* CastExpression = dyn_cast<CastExpr>(Expression);

  // If it's not a cast expression, we've gone too far.
  if (!CastExpression)
    return Cast;

  Cast = std::max(Cast, cppcast::getCastType(CastExpression->getCastKind()));
  return castHelper(CastExpression->getSubExpr(), Cast);
}

} // namespace details

// Recursively demote from const cast level.
CXXCast getCastKindFromCStyleCast(const CStyleCastExpr* CastExpression) {
  return details::castHelper(CastExpression, CXXCast::CC_ConstCast);
}

CXXCast getCastType(const CastKind CastType) {
  switch(CastType) {
    /// Reinterpret cast types
    case CastKind::CK_BitCast:
      llvm::outs() << "Type: bitcast\n";
    case CastKind::CK_LValueBitCast:
      llvm::outs() << "Type: bitcast\n";
    case CastKind::CK_LValueToRValueBitCast:
      llvm::outs() << "Type: bitcast\n";
      // https://godbolt.org/z/46gxUf
    case CastKind::CK_ReinterpretMemberPointer:
      // https://godbolt.org/z/Ra8pbF
    case CastKind::CK_PointerToIntegral:
      return CXXCast::CC_ReinterpretCast;

      /// Static cast types
    case CastKind::CK_LValueToRValue:
    case CastKind::CK_BaseToDerived:
    case CastKind::CK_DerivedToBase:
      // TODO: Understand what this means
    case CastKind::CK_UncheckedDerivedToBase:
      // https://godbolt.org/z/3p2vFW
    case CastKind::CK_FunctionToPointerDecay:
      // https://godbolt.org/z/AMpyLr
    case CastKind::CK_NullToPointer:
      // https://godbolt.org/z/Kx0JbH
    case CastKind::CK_NullToMemberPointer:
      // For the 3 below: https://godbolt.org/z/46gxUf
      // For reference: https://en.cppreference.com/w/cpp/language/pointer#Pointers_to_data_members
    case CastKind::CK_BaseToDerivedMemberPointer:
    case CastKind::CK_DerivedToBaseMemberPointer:
    case CastKind::CK_MemberPointerToBoolean:
      // For the 2 below
      // https://godbolt.org/z/eLdthQ
    case CastKind::CK_UserDefinedConversion:
    case CastKind::CK_ConstructorConversion:
      // For the 2 below
      // https://godbolt.org/z/Ra8pbF
    case CastKind::CK_IntegralToPointer:
      // NOTE: It's interesting how pointer->bool is static while
      //    pointer->integral is reinterpret.
    case CastKind::CK_PointerToBoolean:
      // https://godbolt.org/z/c9s-ws
    case CastKind::CK_ToVoid:
      // https://godbolt.org/z/W-an5j
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
      // https://godbolt.org/z/cZ9yBp
    case CastKind::CK_FloatingRealToComplex:
    case CastKind::CK_FloatingComplexToReal:
    case CastKind::CK_FloatingComplexToBoolean:
    case CastKind::CK_FloatingComplexCast:
    case CastKind::CK_FloatingComplexToIntegralComplex:
      // Integral complex cast types
      // TODO: There is a bug. The last 3 examples
      //  should only be static_cast'able.
      // https://godbolt.org/z/ny-9jc
    case CastKind::CK_IntegralRealToComplex:
    case CastKind::CK_IntegralComplexToReal:
    case CastKind::CK_IntegralComplexToBoolean:
    case CastKind::CK_IntegralComplexCast:
    case CastKind::CK_IntegralComplexToFloatingComplex:
      // Atomic to non-atomic casts
      // https://godbolt.org/z/6ayZ2V
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
      llvm::outs() << "No op cast.\n";
    // https://godbolt.org/z/d-s9hg
    case CastKind::CK_ArrayToPointerDecay:
      return CXXCast::CC_ConstCast;

      /// dynamic cast type
    case CastKind::CK_Dynamic:
      return CXXCast::CC_DynamicCast;

      /// Invalid cast types for C-style casts
      // TODO: It seems like the gcc extension doesn't work on neither
      // clang nor gcc: https://godbolt.org/z/NtDrA7.
      // link to the extension: https://gcc.gnu.org/onlinedocs/gcc/Cast-to-Union.html
    case CastKind::CK_ToUnion: {
      llvm::outs() << "Union casts aren't working.";
      return CXXCast::CC_InvalidCast;
    }
      // Objective C pointer types &
      // Objective C automatic reference counting (ARC) &
      // Objective C blocks (AFAIK C++ blocks were never implemented and it's
      //    a C++ extension and thus we don't support it)
    case CastKind::CK_CPointerToObjCPointerCast:
    case CastKind::CK_BlockPointerToObjCPointerCast:
    case CastKind::CK_AnyPointerToBlockPointerCast:
    case CastKind::CK_ObjCObjectLValueCast:
    case CastKind::CK_ARCProduceObject:
    case CastKind::CK_ARCConsumeObject:
    case CastKind::CK_ARCReclaimReturnedObject:
    case CastKind::CK_ARCExtendBlockObject:
    case CastKind::CK_CopyAndAutoreleaseBlockObject: {
      llvm::outs() << "These are Objective-C casts and should not be encountered in C++.";
      return CXXCast::CC_InvalidCast;
    }
    // Built-in functions must be directly called and don't have
    // address. This is impossible for C-style casts.
    case CastKind::CK_BuiltinFnToFnPtr: {
      llvm::outs() << "Built-in functions cannot be c-style casted.";
      return CXXCast::CC_InvalidCast;
    }
      // TODO
    case CastKind::CK_Dependent: {
      llvm::outs() << "Dependent types are not yet implemented.";
      return CXXCast::CC_InvalidCast;
    }
    default: {
      llvm::outs() << "These are some messed up casts.";
      return CXXCast::CC_InvalidCast;
    }
  }
}

} // namespace cast
} // namespace clang


#endif
