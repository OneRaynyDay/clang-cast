//===-- ClangCastTests.cpp - clang-cast -------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "Cast.h"
#include "ClangCXXCastTestCases.h"
#include "ClangChangeQualifierTestCases.h"
#include "ClangFunctionPtrTestCases.h"
#include "ClangQualifierTestCases.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "gtest/gtest.h"
#include <iostream>
#include <set>
#include <vector>

#define CLANG_CXX_CAST_CHECK(cast_kind, cxx_cast)                              \
  {                                                                            \
    auto res = parse(cast_kind);                                               \
    ASSERT_GE(res.first.size(), 1ul);                                          \
    ASSERT_EQ(res.second.size(), 1ul);                                         \
    ASSERT_TRUE(res.first.find(CastKind::CK_##cast_kind) != res.first.end());  \
    ASSERT_EQ(res.second[0], CXXCast::CC_##cxx_cast);                          \
  }

#define CLANG_QUAL_CHECK(test_case, req_const, pedantic)                       \
  {                                                                            \
    auto res = parse(test_case, pedantic);                                     \
    ASSERT_EQ(res, req_const);                                                 \
  }

#define CLANG_FUNC_PTR_CHECK(test_case, detected)                              \
  {                                                                            \
    auto res = parse(test_case);                                               \
    ASSERT_EQ(res, detected);                                                  \
  }

using namespace testcases;
using namespace testcases::constcheck;
using namespace testcases::funcptr;
using namespace testcases::changequal;
using namespace clang;
using namespace clang::tooling;
using namespace clang::ast_matchers;
using namespace clang::cppcast;

static constexpr auto CastVar = "cast";
static constexpr auto DeclVar = "varDecl";

/// Uses CStyleCastCollector to collect all CXXCast enums obtained
/// and CastKinds encountered.
class ClangCXXCastTest : public ::testing::Test {
  using CastKindSet = std::set<CastKind>;
  using CXXCastVector = std::vector<CXXCast>;
  StatementMatcher CStyleCastMatcher;

  struct CStyleCastCollector : MatchFinder::MatchCallback {
    std::vector<CXXCast> Casts;
    std::set<CastKind> CastKinds;
    CStyleCastCollector() = default;

    virtual void run(const MatchFinder::MatchResult &Result) override {
      ASTContext *Context = Result.Context;
      const CStyleCastExpr *Expr =
          Result.Nodes.getNodeAs<CStyleCastExpr>(CastVar);
      assert(Expr && Context);
      CStyleCastOperation Op(*Expr, *Context, /*Pedantic*/ false);

      const CastExpr *GenericCastExpr = dyn_cast<CastExpr>(Expr);
      // traverse the expr tree and set current expr
      // node to GenericCastExpr.
      while (GenericCastExpr) {
        CastKinds.insert(GenericCastExpr->getCastKind());
        GenericCastExpr = dyn_cast<CastExpr>(GenericCastExpr->getSubExpr());
      }

      Casts.push_back(Op.getCastKindFromCStyleCast());
    }
  };

protected:
  ClangCXXCastTest() : CStyleCastMatcher(cStyleCastExpr().bind(CastVar)) {}

  std::pair<CastKindSet, CXXCastVector> parse(const StringRef Code) {
    // Parses a single translation unit (from text)
    // and returns the CXXCasts in order of traversed.
    std::unique_ptr<clang::ASTUnit> ast(clang::tooling::buildASTFromCode(Code));
    CStyleCastCollector Collector;
    MatchFinder Finder;
    Finder.addMatcher(CStyleCastMatcher, &Collector);
    Finder.matchAST(ast->getASTContext());
    return {Collector.CastKinds, Collector.Casts};
  }
};

class ClangQualifierModificationTest : public ::testing::Test {
  StatementMatcher CStyleCastMatcher;

  struct QualifierChecker : MatchFinder::MatchCallback {
    bool RequireConstCast;
    bool Pedantic;

    QualifierChecker(const bool Pedantic) : Pedantic(Pedantic){};

    virtual void run(const MatchFinder::MatchResult &Result) override {
      ASTContext *Context = Result.Context;
      const CStyleCastExpr *CastExpression =
          Result.Nodes.getNodeAs<CStyleCastExpr>(CastVar);
      assert(CastExpression && Context);
      CStyleCastOperation Op(*CastExpression, *Context, Pedantic);

      RequireConstCast = Op.requireConstCast();
    }
  };

protected:
  ClangQualifierModificationTest()
      : CStyleCastMatcher(cStyleCastExpr().bind(CastVar)) {}

  bool parse(const StringRef Code, bool Pedantic) {
    std::unique_ptr<clang::ASTUnit> ast(clang::tooling::buildASTFromCode(Code));
    QualifierChecker Checker(Pedantic);
    MatchFinder Finder;
    Finder.addMatcher(CStyleCastMatcher, &Checker);
    Finder.matchAST(ast->getASTContext());
    return Checker.RequireConstCast;
  }
};

class ClangFunctionPtrDetectionTest : public ::testing::Test {
  DeclarationMatcher VarDeclMatcher;

  struct FunctionPtrDetector : MatchFinder::MatchCallback {
    bool FoundFunctionPtr;
    FunctionPtrDetector() = default;

    virtual void run(const MatchFinder::MatchResult &Result) override {
      const VarDecl *DeclExpr = Result.Nodes.getNodeAs<VarDecl>(DeclVar);
      assert(DeclExpr);
      QualType CanonicalDeclType = DeclExpr->getType().getCanonicalType();
      FoundFunctionPtr = details::isFunctionPtr(CanonicalDeclType);
    }
  };

protected:
  ClangFunctionPtrDetectionTest() : VarDeclMatcher(varDecl().bind(DeclVar)) {}

  bool parse(const StringRef Code) {
    std::unique_ptr<clang::ASTUnit> ast(clang::tooling::buildASTFromCode(Code));
    FunctionPtrDetector Detector;
    MatchFinder Finder;
    Finder.addMatcher(VarDeclMatcher, &Detector);
    Finder.matchAST(ast->getASTContext());
    return Detector.FoundFunctionPtr;
  }
};

class ChangeQualifierTest : public ::testing::Test {
  StatementMatcher CStyleCastMatcher;
  DeclarationMatcher DeclMatcher;

  struct QualifierChanger : MatchFinder::MatchCallback {
    QualType ChangedCanonicalType;
    bool Pedantic;
    QualifierChanger(const bool Pedantic) : Pedantic(Pedantic) {}

    virtual void run(const MatchFinder::MatchResult &Result) override {
      ASTContext *Context = Result.Context;
      const CStyleCastExpr *CastExpression =
          Result.Nodes.getNodeAs<CStyleCastExpr>(CastVar);
      assert(CastExpression && Context);
      CStyleCastOperation Op(*CastExpression, *Context, Pedantic);

      ChangedCanonicalType = Op.changeQualifiers().getCanonicalType();
    }
  };

  struct DeclTypeMatcher : MatchFinder::MatchCallback {
    QualType FoundCanonicalType;
    DeclTypeMatcher() = default;

    virtual void run(const MatchFinder::MatchResult &Result) override {
      const VarDecl *DeclExpr = Result.Nodes.getNodeAs<VarDecl>(DeclVar);
      assert(DeclExpr);

      FoundCanonicalType = DeclExpr->getType().getCanonicalType();
    }
  };

protected:
  ChangeQualifierTest()
      : CStyleCastMatcher(cStyleCastExpr().bind(CastVar)),
        DeclMatcher(varDecl().bind(DeclVar)) {}

  bool parse(const StringRef CastCode, bool Pedantic) {
    std::unique_ptr<clang::ASTUnit> CastAst(
        clang::tooling::buildASTFromCode(CastCode));
    std::unique_ptr<clang::ASTUnit> TypeAst(
        clang::tooling::buildASTFromCode(CastCode));
    QualifierChanger Changer(Pedantic);
    DeclTypeMatcher TypeMatcher;
    {
      MatchFinder Finder;
      Finder.addMatcher(CStyleCastMatcher, &Changer);
      Finder.matchAST(CastAst->getASTContext());
    }
    {
      MatchFinder Finder;
      Finder.addMatcher(DeclMatcher, &TypeMatcher);
      Finder.matchAST(TypeAst->getASTContext());
    }
    return Changer.ChangedCanonicalType.getAsString() ==
           TypeMatcher.FoundCanonicalType.getAsString();
  }
};

TEST_F(ClangCXXCastTest, TestNoOpCastTypes) {
  CLANG_CXX_CAST_CHECK(NoOp, NoOpCast);
  CLANG_CXX_CAST_CHECK(ArrayToPointerDecay, NoOpCast);
  // Unchecked: CLANG_CXX_CAST_CHECK(LValueToRValue, ConstCast);
}

TEST_F(ClangCXXCastTest, TestReinterpretCastTypes) {
  CLANG_CXX_CAST_CHECK(BitCast, ReinterpretCast);
  CLANG_CXX_CAST_CHECK(LValueBitCast, ReinterpretCast);
  CLANG_CXX_CAST_CHECK(IntegralToPointer, ReinterpretCast);
  CLANG_CXX_CAST_CHECK(ReinterpretMemberPointer, ReinterpretCast);
  CLANG_CXX_CAST_CHECK(PointerToIntegral, ReinterpretCast);
}

TEST_F(ClangCXXCastTest, TestStaticCastTypes) {
  CLANG_CXX_CAST_CHECK(BaseToDerived, StaticCast);
  CLANG_CXX_CAST_CHECK(DerivedToBase, StaticCast);
  // Unchecked: CLANG_CXX_CAST_CHECK(UncheckedDerivedToBase, StaticCast);
  CLANG_CXX_CAST_CHECK(FunctionToPointerDecay, StaticCast);
  CLANG_CXX_CAST_CHECK(NullToPointer, StaticCast);
  CLANG_CXX_CAST_CHECK(NullToMemberPointer, StaticCast);
  CLANG_CXX_CAST_CHECK(BaseToDerivedMemberPointer, StaticCast);
  CLANG_CXX_CAST_CHECK(DerivedToBaseMemberPointer, StaticCast);
  CLANG_CXX_CAST_CHECK(MemberPointerToBoolean, StaticCast);
  CLANG_CXX_CAST_CHECK(UserDefinedConversion, StaticCast);
  CLANG_CXX_CAST_CHECK(ConstructorConversion, StaticCast);
  CLANG_CXX_CAST_CHECK(PointerToBoolean, StaticCast);
  CLANG_CXX_CAST_CHECK(ToVoid, StaticCast);
  CLANG_CXX_CAST_CHECK(VectorSplat, StaticCast);
  CLANG_CXX_CAST_CHECK(IntegralCast, StaticCast);
  CLANG_CXX_CAST_CHECK(IntegralToBoolean, StaticCast);
  CLANG_CXX_CAST_CHECK(IntegralToFloating, StaticCast);
  CLANG_CXX_CAST_CHECK(FloatingToIntegral, StaticCast);
  CLANG_CXX_CAST_CHECK(FloatingToBoolean, StaticCast);
  CLANG_CXX_CAST_CHECK(FloatingCast, StaticCast);
  CLANG_CXX_CAST_CHECK(FloatingRealToComplex, StaticCast);
  CLANG_CXX_CAST_CHECK(FloatingComplexToReal, StaticCast);
  CLANG_CXX_CAST_CHECK(FloatingComplexToBoolean, StaticCast);
  CLANG_CXX_CAST_CHECK(FloatingComplexCast, StaticCast);
  CLANG_CXX_CAST_CHECK(FloatingComplexToIntegralComplex, StaticCast);
  CLANG_CXX_CAST_CHECK(IntegralRealToComplex, StaticCast);
  CLANG_CXX_CAST_CHECK(IntegralComplexToReal, StaticCast);
  CLANG_CXX_CAST_CHECK(IntegralComplexToBoolean, StaticCast);
  CLANG_CXX_CAST_CHECK(IntegralComplexCast, StaticCast);
  CLANG_CXX_CAST_CHECK(IntegralComplexToFloatingComplex, StaticCast);
  CLANG_CXX_CAST_CHECK(AtomicToNonAtomic, StaticCast);
  CLANG_CXX_CAST_CHECK(NonAtomicToAtomic, StaticCast);
}

TEST_F(ClangCXXCastTest, TestCStyleCastTypes) {
  CLANG_CXX_CAST_CHECK(Dependent, CStyleCast);
}

TEST_F(ClangCXXCastTest, TestEdgeCases) {
  using namespace edgecases;
  {
    auto res = parse(DerivedToBasePrivateSpecifier);
    ASSERT_GE(res.first.size(), 1ul);
    ASSERT_GE(res.second.size(), 1ul);
    ASSERT_TRUE(res.first.find(CastKind::CK_DerivedToBase) != res.first.end());
    ASSERT_EQ(res.second[0], CXXCast::CC_CStyleCast);
  }
  {
    auto res = parse(BaseToDerivedPrivateSpecifier);
    ASSERT_GE(res.first.size(), 1ul);
    ASSERT_GE(res.second.size(), 1ul);
    ASSERT_TRUE(res.first.find(CastKind::CK_BaseToDerived) != res.first.end());
    ASSERT_EQ(res.second[0], CXXCast::CC_CStyleCast);
  }
  CLANG_CXX_CAST_CHECK(Dependent, CStyleCast);
}

///// These tests mean:
///// Does the C-style cast in <test case> require a const_cast?
TEST_F(ClangQualifierModificationTest, TestConstCases) {
  CLANG_QUAL_CHECK(QualNoOp, false, false);
  // add
  // we perform these operations in order to first do a sanity check that
  // 1. const cast isn't needed for upcasting
  // 2. there will be no segmentation faults before we run the removal tests
  CLANG_QUAL_CHECK(QualAddConst, false, false);
  CLANG_QUAL_CHECK(QualAddPtrToConst, false, false);
  CLANG_QUAL_CHECK(QualAddConstPtr, false, false);
  CLANG_QUAL_CHECK(QualAddConstDoublePtr, false, false);
  CLANG_QUAL_CHECK(QualAddConstDiffLevelPtr, false, false);
  CLANG_QUAL_CHECK(QualAddMemberPtrToConst, false, false);
  CLANG_QUAL_CHECK(QualAddConstMemberPtr, false, false);
  CLANG_QUAL_CHECK(QualAddConstDoubleMemberPtr, false, false);
  CLANG_QUAL_CHECK(QualAddConstDiffLevelMemberPtr, false, false);
  CLANG_QUAL_CHECK(QualAddConstRef, false, false);
  CLANG_QUAL_CHECK(QualAddConstArr, false, false);
  CLANG_QUAL_CHECK(QualAddConstPtrToArr, false, false);
  CLANG_QUAL_CHECK(QualAddConstPtrToArrOfConstPtrs, false, false);
  CLANG_QUAL_CHECK(QualAddArrPtrConstData, false, false);
  CLANG_QUAL_CHECK(QualAddDiffLevelArrPtrConstData, false, false);
  CLANG_QUAL_CHECK(QualAddConstMixedPtrTypes, false, false);
  CLANG_QUAL_CHECK(QualAddConstUnknownArrPtr, false, false);
  CLANG_QUAL_CHECK(QualAddConstUnknownArrPtrToKnownArrPtr, false, false);

  // remove
  // we perform these operations in order to check the positive cases, along
  // with negative edge cases.
  // does not require const cast - implicit
  CLANG_QUAL_CHECK(QualRemoveConst, false, false);
  // does require const cast, base type downcast
  CLANG_QUAL_CHECK(QualRemovePtrToConst, true, false);
  // does not - implicit
  CLANG_QUAL_CHECK(QualRemoveConstPtr, false, false);
  // does - downcast
  CLANG_QUAL_CHECK(QualRemoveConstDoublePtr, true, false);
  // does not - level truncated
  CLANG_QUAL_CHECK(QualRemoveConstDiffLevelPtr, false, false);

  // Same as the above 4
  CLANG_QUAL_CHECK(QualRemoveMemberPtrToConst, true, false);
  CLANG_QUAL_CHECK(QualRemoveConstMemberPtr, false, false);
  CLANG_QUAL_CHECK(QualRemoveConstDoubleMemberPtr, true, false);
  CLANG_QUAL_CHECK(QualRemoveConstDiffLevelMemberPtr, false, false);

  // does - downcast
  CLANG_QUAL_CHECK(QualRemoveConstRef, true, false);
  // does - downcast
  CLANG_QUAL_CHECK(QualRemoveConstArr, true, false);
  // does not - implicit
  CLANG_QUAL_CHECK(QualRemoveConstPtrToArr, false, false);
  // does - downcast
  CLANG_QUAL_CHECK(QualRemoveConstPtrToArrOfConstPtrs, true, false);
  // does - downcast
  CLANG_QUAL_CHECK(QualRemoveArrPtrConstData, true, false);
  // does not - level truncated
  CLANG_QUAL_CHECK(QualRemoveDiffLevelArrPtrConstData, false, false);
  // does - similar types going down
  CLANG_QUAL_CHECK(QualRemoveSimilarPtrsBeyondArrConstData, true, false);
  // does - All pointer-like types are downcasted
  CLANG_QUAL_CHECK(QualRemoveConstMixedPtrTypes, true, false);
  // does - Unknown size array is similar to unknown size array
  CLANG_QUAL_CHECK(QualRemoveConstUnknownArrPtr, true, false);
  // does - Unknown size array is similar to known size array
  CLANG_QUAL_CHECK(QualRemoveConstUnknownArrPtrToKnownArrPtr, true, false);

  // Checking for pedantic changes
//  CLANG_QUAL_CHECK(QualNoOp, false, false);
//  CLANG_QUAL_CHECK(QualAddConst, false, false);
//  CLANG_QUAL_CHECK(QualAddPtrToConst, false, false);
//  CLANG_QUAL_CHECK(QualAddConstPtr, false, false);
//  CLANG_QUAL_CHECK(QualAddConstDoublePtr, false, false);
//  CLANG_QUAL_CHECK(QualAddConstDiffLevelPtr, false, false);
//  CLANG_QUAL_CHECK(QualAddMemberPtrToConst, false, false);
//  CLANG_QUAL_CHECK(QualAddConstMemberPtr, false, false);
//  CLANG_QUAL_CHECK(QualAddConstDoubleMemberPtr, false, false);
//  CLANG_QUAL_CHECK(QualAddConstDiffLevelMemberPtr, false, false);
//  CLANG_QUAL_CHECK(QualAddConstRef, false, false);
//  CLANG_QUAL_CHECK(QualAddConstArr, false, false);
//  CLANG_QUAL_CHECK(QualAddConstPtrToArr, false, false);
//  CLANG_QUAL_CHECK(QualAddConstPtrToArrOfConstPtrs, false, false);
//  CLANG_QUAL_CHECK(QualAddArrPtrConstData, false, false);
//  CLANG_QUAL_CHECK(QualAddDiffLevelArrPtrConstData, false, false);
//  CLANG_QUAL_CHECK(QualAddConstMixedPtrTypes, false, false);
//  CLANG_QUAL_CHECK(QualAddConstUnknownArrPtr, false, false);
//  CLANG_QUAL_CHECK(QualAddConstUnknownArrPtrToKnownArrPtr, false, false);
//
//  CLANG_QUAL_CHECK(QualRemoveConst, false, false);
//  CLANG_QUAL_CHECK(QualRemovePtrToConst, true, false);
//  CLANG_QUAL_CHECK(QualRemoveConstPtr, false, false);
//  CLANG_QUAL_CHECK(QualRemoveConstDoublePtr, true, false);
//  CLANG_QUAL_CHECK(QualRemoveConstDiffLevelPtr, false, false);
//  CLANG_QUAL_CHECK(QualRemoveMemberPtrToConst, true, false);
//  CLANG_QUAL_CHECK(QualRemoveConstMemberPtr, false, false);
//  CLANG_QUAL_CHECK(QualRemoveConstDoubleMemberPtr, true, false);
//  CLANG_QUAL_CHECK(QualRemoveConstDiffLevelMemberPtr, false, false);
//  CLANG_QUAL_CHECK(QualRemoveConstRef, true, false);
//  CLANG_QUAL_CHECK(QualRemoveConstArr, true, false);
//  CLANG_QUAL_CHECK(QualRemoveConstPtrToArr, false, false);
//  CLANG_QUAL_CHECK(QualRemoveConstPtrToArrOfConstPtrs, true, false);
//  CLANG_QUAL_CHECK(QualRemoveArrPtrConstData, true, false);
//  CLANG_QUAL_CHECK(QualRemoveDiffLevelArrPtrConstData, false, false);
//  CLANG_QUAL_CHECK(QualRemoveSimilarPtrsBeyondArrConstData, true, false);
//  CLANG_QUAL_CHECK(QualRemoveConstMixedPtrTypes, true, false);
//  CLANG_QUAL_CHECK(QualRemoveConstUnknownArrPtr, true, false);
//  CLANG_QUAL_CHECK(QualRemoveConstUnknownArrPtrToKnownArrPtr, true, false);
}

TEST_F(ClangQualifierModificationTest, TestVolatileCases) {
  // add
  CLANG_QUAL_CHECK(QualAddVolatile, false, false);
  CLANG_QUAL_CHECK(QualAddPtrToVolatile, false, false);
  CLANG_QUAL_CHECK(QualAddVolatilePtr, false, false);
  CLANG_QUAL_CHECK(QualAddVolatileDoublePtr, false, false);
  CLANG_QUAL_CHECK(QualAddVolatileDiffLevelPtr, false, false);
  CLANG_QUAL_CHECK(QualAddVolatileRef, false, false);
  CLANG_QUAL_CHECK(QualAddVolatileArr, false, false);
  CLANG_QUAL_CHECK(QualAddVolatilePtrToArr, false, false);
  CLANG_QUAL_CHECK(QualAddVolatilePtrToArrOfVolatilePtrs, false, false);
  CLANG_QUAL_CHECK(QualAddArrPtrVolatileData, false, false);
  CLANG_QUAL_CHECK(QualAddDiffLevelArrPtrVolatileData, false, false);
  CLANG_QUAL_CHECK(QualAddVolatileMixedPtrTypes, false, false);
  CLANG_QUAL_CHECK(QualAddVolatileUnknownArrPtr, false, false);
  CLANG_QUAL_CHECK(QualAddVolatileUnknownArrPtrToKnownArrPtr, false, false);

  // remove
  CLANG_QUAL_CHECK(QualRemoveVolatile, false, false);
  CLANG_QUAL_CHECK(QualRemovePtrToVolatile, true, false);
  CLANG_QUAL_CHECK(QualRemoveVolatilePtr, false, false);
  CLANG_QUAL_CHECK(QualRemoveVolatileDoublePtr, true, false);
  CLANG_QUAL_CHECK(QualRemoveVolatileDiffLevelPtr, false, false);
  CLANG_QUAL_CHECK(QualRemoveVolatileRef, true, false);
  CLANG_QUAL_CHECK(QualRemoveVolatileArr, true, false);
  CLANG_QUAL_CHECK(QualRemoveVolatilePtrToArr, false, false);
  CLANG_QUAL_CHECK(QualRemoveVolatilePtrToArrOfVolatilePtrs, true, false);
  CLANG_QUAL_CHECK(QualRemoveArrPtrVolatileData, true, false);
  CLANG_QUAL_CHECK(QualRemoveDiffLevelArrPtrVolatileData, false, false);
  CLANG_QUAL_CHECK(QualRemoveSimilarPtrsBeyondArrVolatileData, true, false);
  CLANG_QUAL_CHECK(QualRemoveVolatileMixedPtrTypes, true, false);
  CLANG_QUAL_CHECK(QualRemoveVolatileUnknownArrPtr, true, false);
  CLANG_QUAL_CHECK(QualRemoveVolatileUnknownArrPtrToKnownArrPtr, true, false);
}

TEST_F(ClangQualifierModificationTest, TestRestrictCases) {
  // add
  CLANG_QUAL_CHECK(QualAddRestrictPtr, false, false);
  CLANG_QUAL_CHECK(QualAddRestrictDoublePtr, false, false);
  CLANG_QUAL_CHECK(QualAddRestrictDiffLevelPtr, false, false);
  CLANG_QUAL_CHECK(QualAddRestrictArr, false, false);
  CLANG_QUAL_CHECK(QualAddRestrictPtrToArr, false, false);
  CLANG_QUAL_CHECK(QualAddRestrictPtrToArrOfRestrictPtrs, false, false);
  CLANG_QUAL_CHECK(QualAddArrPtrRestrictData, false, false);
  CLANG_QUAL_CHECK(QualAddDiffLevelArrPtrRestrictData, false, false);
  CLANG_QUAL_CHECK(QualAddRestrictMixedPtrTypes, false, false);
  CLANG_QUAL_CHECK(QualAddRestrictUnknownArrPtr, false, false);
  CLANG_QUAL_CHECK(QualAddRestrictUnknownArrPtrToKnownArrPtr, false, false);

  // remove
  CLANG_QUAL_CHECK(QualRemoveRestrictPtr, false, false);
  CLANG_QUAL_CHECK(QualRemoveRestrictDoublePtr, true, false);
  CLANG_QUAL_CHECK(QualRemoveRestrictDiffLevelPtr, false, false);
  CLANG_QUAL_CHECK(QualRemoveRestrictArr, true, false);
  CLANG_QUAL_CHECK(QualRemoveRestrictPtrToArr, false, false);
  CLANG_QUAL_CHECK(QualRemoveRestrictPtrToArrOfRestrictPtrs, true, false);
  CLANG_QUAL_CHECK(QualRemoveArrPtrRestrictData, true, false);
  CLANG_QUAL_CHECK(QualRemoveDiffLevelArrPtrRestrictData, false, false);
  CLANG_QUAL_CHECK(QualRemoveSimilarPtrsBeyondArrRestrictData, true, false);
  CLANG_QUAL_CHECK(QualRemoveRestrictMixedPtrTypes, true, false);
  CLANG_QUAL_CHECK(QualRemoveRestrictUnknownArrPtr, true, false);
  CLANG_QUAL_CHECK(QualRemoveRestrictUnknownArrPtrToKnownArrPtr, true, false);
  // TODO: for member function pointers you can actually change the qualifier
  // for it and in order to do so you use reinterpret_cast WITHOUT
  // const_cast to remove the qualifiers... WTF?
  // https://godbolt.org/z/APnWdN
}

TEST_F(ClangFunctionPtrDetectionTest, TestFuncPtrs) {
  CLANG_FUNC_PTR_CHECK(Scalar, false);
  CLANG_FUNC_PTR_CHECK(ArrOfFreeFunctionPtr, false);
  CLANG_FUNC_PTR_CHECK(NestedFreeFunctionPtr, false);
  CLANG_FUNC_PTR_CHECK(FreeFunction, true);
  CLANG_FUNC_PTR_CHECK(ArrOfMemberFunction, false);
  CLANG_FUNC_PTR_CHECK(NestedMemberFunction, false);
  CLANG_FUNC_PTR_CHECK(MemberFunction, true);
}

TEST_F(ChangeQualifierTest, TestChangeQualifiers) {
  ASSERT_TRUE(parse(extension::NoQualifierChange, false));
  ASSERT_TRUE(parse(extension::NoQualifierChangeReinterpret, false));
  ASSERT_TRUE(parse(extension::ChangeNestedPointers, false));
  ASSERT_TRUE(parse(extension::ChangeNestedPointersReinterpret, false));
  ASSERT_TRUE(parse(extension::ChangeNestedPointersUntilArray, false));
  ASSERT_TRUE(
      parse(extension::ChangeNestedPointersUntilArrayReinterpret, false));
  ASSERT_TRUE(parse(extension::NoModificationToMixedPtrTypes, false));
  ASSERT_TRUE(parse(extension::DontChangeMemberFuncPtr, false));
  ASSERT_TRUE(parse(extension::ChangeNestedPointersUntilMemberVsNot, false));

  ASSERT_TRUE(parse(pedantic::NoQualifierChange, true));
  ASSERT_TRUE(parse(pedantic::NoQualifierChangeReinterpret, true));
  ASSERT_TRUE(parse(pedantic::ChangeNestedPointers, true));
  ASSERT_TRUE(parse(pedantic::ChangeNestedPointersReinterpret, true));
  ASSERT_TRUE(parse(pedantic::ChangeNestedPointersUntilArray, true));
  ASSERT_TRUE(parse(pedantic::ChangeNestedPointersUntilArrayReinterpret, true));
  ASSERT_TRUE(parse(pedantic::NoModificationToMixedPtrTypes, true));
  ASSERT_TRUE(parse(pedantic::DontChangeMemberFuncPtr, true));
  ASSERT_TRUE(parse(pedantic::ChangeNestedPointersUntilMemberVsNot, true));
}
