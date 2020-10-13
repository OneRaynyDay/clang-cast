#include "ClangCXXCastTestCases.h"
#include "ClangQualifierTestCases.h"
#include "ClangFunctionPtrTestCases.h"
#include "ClangChangeQualifierTestCases.h"
#include "ClangCast.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "gtest/gtest.h"
#include <iostream>
#include <set>
#include <vector>

#define CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(cast_kind, cxx_cast)            \
  {                                                                           \
  auto res = parse(cast_kind);                                                \
  ASSERT_GE(res.first.size(), 1ul);                                             \
  ASSERT_EQ(res.second.size(), 1ul);                                            \
  ASSERT_TRUE(res.first.find(CastKind::CK_##cast_kind) != res.first.end());   \
  ASSERT_EQ(res.second[0], CXXCast::CC_##cxx_cast);                           \
  }

#define CLANG_QUAL_CHECK_SINGLE_TEST_CASE(test_case, req_const)               \
  {                                                                           \
  auto res = parse(test_case);                                                \
  ASSERT_EQ(res, req_const);                                                  \
  }

#define CLANG_FUNC_PTR_CHECK_SINGLE_TEST_CASE(test_case, detected)            \
  {                                                                           \
  auto res = parse(test_case);                                                \
  ASSERT_EQ(res, detected);                                                   \
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
      const CStyleCastExpr* Expr = Result.Nodes.getNodeAs<CStyleCastExpr>(CastVar);
      if(!Expr) {
        llvm::errs() << "This should never happen.\n";
        return;
      }
      const CastExpr* GenericCastExpr = dyn_cast<CastExpr>(Expr);
      // traverse the expr tree and set current expr
      // node to GenericCastExpr.
      while(GenericCastExpr) {
        CastKinds.insert(GenericCastExpr->getCastKind());
        GenericCastExpr = dyn_cast<CastExpr>(GenericCastExpr->getSubExpr());
      }
      Casts.push_back(cppcast::getCastKindFromCStyleCast(Expr));
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
    QualifierChecker() = default;

    virtual void run(const MatchFinder::MatchResult &Result) override {
      ASTContext *Context = Result.Context;
      const CStyleCastExpr* CastExpression = Result.Nodes.getNodeAs<CStyleCastExpr>(CastVar);
      if(!CastExpression) {
        llvm::errs() << "This should never happen.\n";
        return;
      }
      RequireConstCast = requireConstCast(CastExpression, Context);
    }
  };

protected:
  ClangQualifierModificationTest() : CStyleCastMatcher(cStyleCastExpr().bind(CastVar)) {}

  bool parse(const StringRef Code) {
    std::unique_ptr<clang::ASTUnit> ast(clang::tooling::buildASTFromCode(Code));
    QualifierChecker Checker;
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
      const VarDecl* DeclExpr = Result.Nodes.getNodeAs<VarDecl>(DeclVar);
      if(!DeclExpr) {
        llvm::errs() << "This should never happen.\n";
        return;
      }
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
    QualifierChanger() = default;

    virtual void run(const MatchFinder::MatchResult &Result) override {
      ASTContext *Context = Result.Context;
      const CStyleCastExpr* CastExpression = Result.Nodes.getNodeAs<CStyleCastExpr>(CastVar);
      if(!CastExpression) {
        llvm::errs() << "This should never happen.\n";
        return;
      }
      const Expr* SubExpression = CastExpression->getSubExprAsWritten();
      QualType CanonicalSubExpressionType = SubExpression->getType().getCanonicalType();
      QualType CanonicalCastType = CastExpression->getTypeAsWritten().getCanonicalType();
      ChangedCanonicalType = changeQualifiers(CanonicalCastType, CanonicalSubExpressionType, Context).getCanonicalType();
    }
  };

  struct DeclTypeMatcher : MatchFinder::MatchCallback {
    QualType FoundCanonicalType;
    DeclTypeMatcher() = default;

    virtual void run(const MatchFinder::MatchResult &Result) override {
      const VarDecl* DeclExpr = Result.Nodes.getNodeAs<VarDecl>(DeclVar);
      if(!DeclExpr) {
        llvm::errs() << "This should never happen.\n";
        return;
      }
      FoundCanonicalType = DeclExpr->getType().getCanonicalType();
    }
  };

protected:
  ChangeQualifierTest() : CStyleCastMatcher(cStyleCastExpr().bind(CastVar)),
                                     DeclMatcher(varDecl().bind(DeclVar)) {}

  bool parse(const StringRef CastCode) {
    std::unique_ptr<clang::ASTUnit> CastAst(clang::tooling::buildASTFromCode(CastCode));
    std::unique_ptr<clang::ASTUnit> TypeAst(clang::tooling::buildASTFromCode(CastCode));
    QualifierChanger Changer;
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
    return Changer.ChangedCanonicalType.getAsString() == TypeMatcher.FoundCanonicalType.getAsString();
  }
};

TEST_F(ClangCXXCastTest, TestNoOpCastTypes) {
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(NoOp, NoOpCast);
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(ArrayToPointerDecay, NoOpCast);
  // Unchecked: CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(LValueToRValue, ConstCast);
}

TEST_F(ClangCXXCastTest, TestReinterpretCastTypes) {
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(BitCast, ReinterpretCast);
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(LValueBitCast, ReinterpretCast);
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(IntegralToPointer, ReinterpretCast);
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(ReinterpretMemberPointer, ReinterpretCast);
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(PointerToIntegral, ReinterpretCast);
}

TEST_F(ClangCXXCastTest, TestStaticCastTypes) {
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(BaseToDerived, StaticCast);
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(DerivedToBase, StaticCast);
  // Unchecked: CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(UncheckedDerivedToBase, StaticCast);
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(FunctionToPointerDecay, StaticCast);
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(NullToPointer, StaticCast);
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(NullToMemberPointer, StaticCast);
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(BaseToDerivedMemberPointer, StaticCast);
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(DerivedToBaseMemberPointer, StaticCast);
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(MemberPointerToBoolean, StaticCast);
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(UserDefinedConversion, StaticCast);
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(ConstructorConversion, StaticCast);
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(PointerToBoolean, StaticCast);
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(ToVoid, StaticCast);
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(VectorSplat, StaticCast);
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(IntegralCast, StaticCast);
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(IntegralToBoolean, StaticCast);
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(IntegralToFloating, StaticCast);
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(FloatingToIntegral, StaticCast);
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(FloatingToBoolean, StaticCast);
  // TODO: How is this possible? CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(BooleanToSignedIntegral, StaticCast);
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(FloatingCast, StaticCast);
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(FloatingRealToComplex, StaticCast);
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(FloatingComplexToReal, StaticCast);
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(FloatingComplexToBoolean, StaticCast);
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(FloatingComplexCast, StaticCast);
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(FloatingComplexToIntegralComplex, StaticCast);
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(IntegralRealToComplex, StaticCast);
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(IntegralComplexToReal, StaticCast);
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(IntegralComplexToBoolean, StaticCast);
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(IntegralComplexCast, StaticCast);
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(IntegralComplexToFloatingComplex, StaticCast);
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(AtomicToNonAtomic, StaticCast);
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(NonAtomicToAtomic, StaticCast);
}

TEST_F(ClangCXXCastTest, TestCStyleCastTypes) {
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(Dependent, CStyleCast);
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
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(Dependent, CStyleCast);
}

///// These tests mean:
///// Does the C-style cast in <test case> require a const_cast?
TEST_F(ClangQualifierModificationTest, TestConstCases) {
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualNoOp, false);
  // add
  // we perform these operations in order to first do a sanity check that
  // 1. const cast isn't needed for upcasting
  // 2. there will be no segmentation faults before we run the removal tests
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddConst, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddPtrToConst, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddConstPtr, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddConstDoublePtr, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddConstDiffLevelPtr, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddMemberPtrToConst, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddConstMemberPtr, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddConstDoubleMemberPtr, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddConstDiffLevelMemberPtr, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddConstRef, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddConstArr, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddConstPtrToArr, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddConstPtrToArrOfConstPtrs, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddArrPtrConstData, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddDiffLevelArrPtrConstData, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddConstMixedPtrTypes, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddConstUnknownArrPtr, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddConstUnknownArrPtrToKnownArrPtr, false);

  // remove
  // we perform these operations in order to check the positive cases, along
  // with negative edge cases.
  // does not require const cast - implicit
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveConst, false);
  // does require const cast, base type downcast
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemovePtrToConst, true);
  // does not - implicit
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveConstPtr, false);
  // does - downcast
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveConstDoublePtr, true);
  // does not - level truncated
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveConstDiffLevelPtr, false);

  // Same as the above 4
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveMemberPtrToConst, true);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveConstMemberPtr, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveConstDoubleMemberPtr, true);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveConstDiffLevelMemberPtr, false);

  // does - downcast
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveConstRef, true);
  // does - downcast
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveConstArr, true);
  // does not - implicit
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveConstPtrToArr, false);
  // does - downcast
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveConstPtrToArrOfConstPtrs, true);
  // does - downcast
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveArrPtrConstData, true);
  // does not - level truncated
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveDiffLevelArrPtrConstData, false);
  // does - similar types going down
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveSimilarPtrsBeyondArrConstData, true);
  // does - All pointer-like types are downcasted
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveConstMixedPtrTypes, true);
  // does - Unknown size array is similar to unknown size array
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveConstUnknownArrPtr, true);
  // does - Unknown size array is similar to known size array
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveConstUnknownArrPtrToKnownArrPtr, true);
}

TEST_F(ClangQualifierModificationTest, TestVolatileCases) {
  // add
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddVolatile, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddPtrToVolatile, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddVolatilePtr, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddVolatileDoublePtr, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddVolatileDiffLevelPtr, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddVolatileRef, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddVolatileArr, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddVolatilePtrToArr, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddVolatilePtrToArrOfVolatilePtrs, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddArrPtrVolatileData, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddDiffLevelArrPtrVolatileData, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddVolatileMixedPtrTypes, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddVolatileUnknownArrPtr, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddVolatileUnknownArrPtrToKnownArrPtr, false);

  // remove
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveVolatile, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemovePtrToVolatile, true);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveVolatilePtr, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveVolatileDoublePtr, true);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveVolatileDiffLevelPtr, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveVolatileRef, true);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveVolatileArr, true);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveVolatilePtrToArr, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveVolatilePtrToArrOfVolatilePtrs, true);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveArrPtrVolatileData, true);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveDiffLevelArrPtrVolatileData, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveSimilarPtrsBeyondArrVolatileData, true);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveVolatileMixedPtrTypes, true);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveVolatileUnknownArrPtr, true);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveVolatileUnknownArrPtrToKnownArrPtr, true);
}

TEST_F(ClangQualifierModificationTest, TestRestrictCases) {
  // add
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddRestrictPtr, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddRestrictDoublePtr, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddRestrictDiffLevelPtr, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddRestrictArr, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddRestrictPtrToArr, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddRestrictPtrToArrOfRestrictPtrs, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddArrPtrRestrictData, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddDiffLevelArrPtrRestrictData, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddRestrictMixedPtrTypes, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddRestrictUnknownArrPtr, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddRestrictUnknownArrPtrToKnownArrPtr, false);

  // remove
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveRestrictPtr, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveRestrictDoublePtr, true);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveRestrictDiffLevelPtr, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveRestrictArr, true);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveRestrictPtrToArr, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveRestrictPtrToArrOfRestrictPtrs, true);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveArrPtrRestrictData, true);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveDiffLevelArrPtrRestrictData, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveSimilarPtrsBeyondArrRestrictData, true);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveRestrictMixedPtrTypes, true);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveRestrictUnknownArrPtr, true);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveRestrictUnknownArrPtrToKnownArrPtr, true);
  // TODO: for member function pointers you can actually change the qualifier
  // for it and in order to do so you use reinterpret_cast WITHOUT
  // const_cast to remove the qualifiers... WTF?
  // https://godbolt.org/z/APnWdN
}

TEST_F(ClangFunctionPtrDetectionTest, TestFuncPtrs) {
  CLANG_FUNC_PTR_CHECK_SINGLE_TEST_CASE(Scalar, false);
  CLANG_FUNC_PTR_CHECK_SINGLE_TEST_CASE(ArrOfFreeFunctionPtr, false);
  CLANG_FUNC_PTR_CHECK_SINGLE_TEST_CASE(NestedFreeFunctionPtr, false);
  CLANG_FUNC_PTR_CHECK_SINGLE_TEST_CASE(FreeFunction, true);
  CLANG_FUNC_PTR_CHECK_SINGLE_TEST_CASE(ArrOfMemberFunction, false);
  CLANG_FUNC_PTR_CHECK_SINGLE_TEST_CASE(NestedMemberFunction, false);
  CLANG_FUNC_PTR_CHECK_SINGLE_TEST_CASE(MemberFunction, true);
}

TEST_F(ChangeQualifierTest, TestChangeQualifiers) {
  ASSERT_TRUE(parse(NoQualifierChange));
  ASSERT_TRUE(parse(NoQualifierChangeReinterpret));
  ASSERT_TRUE(parse(ChangeNestedPointers));
  ASSERT_TRUE(parse(ChangeNestedPointersReinterpret));
  ASSERT_TRUE(parse(ChangeNestedPointersUntilArray));
  ASSERT_TRUE(parse(ChangeNestedPointersUntilArrayReinterpret));
  ASSERT_TRUE(parse(DontChangeMemberFuncPtr));
}
