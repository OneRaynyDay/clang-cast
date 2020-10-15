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
  ASSERT_GE(res.first.size(), 1ul);                                           \
  ASSERT_EQ(res.second.size(), 1ul);                                          \
  ASSERT_TRUE(res.first.find(CastKind::CK_##cast_kind) != res.first.end());   \
  ASSERT_EQ(res.second[0], CXXCast::CC_##cxx_cast);                           \
  }

#define CLANG_QUAL_CHECK_SINGLE_TEST_CASE(test_case, req_const, pedantic)     \
  {                                                                           \
  auto res = parse(test_case, pedantic);                                      \
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
    bool Pedantic;

    QualifierChecker(const bool Pedantic) : Pedantic(Pedantic) {};

    virtual void run(const MatchFinder::MatchResult &Result) override {
      ASTContext *Context = Result.Context;
      const CStyleCastExpr* CastExpression = Result.Nodes.getNodeAs<CStyleCastExpr>(CastVar);
      if(!CastExpression) {
        llvm::errs() << "This should never happen.\n";
        return;
      }
      RequireConstCast = requireConstCast(CastExpression, Context, Pedantic);
    }
  };

protected:
  ClangQualifierModificationTest() : CStyleCastMatcher(cStyleCastExpr().bind(CastVar)) {}

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
    bool Pedantic;
    QualifierChanger(const bool Pedantic) : Pedantic(Pedantic) {}

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
      ChangedCanonicalType = changeQualifiers(CanonicalCastType, CanonicalSubExpressionType, Context, Pedantic).getCanonicalType();
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

  bool parse(const StringRef CastCode, bool Pedantic) {
    std::unique_ptr<clang::ASTUnit> CastAst(clang::tooling::buildASTFromCode(CastCode));
    std::unique_ptr<clang::ASTUnit> TypeAst(clang::tooling::buildASTFromCode(CastCode));
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
    llvm::outs() << "Changed canonical type: " << Changer.ChangedCanonicalType.getAsString() << "\n\n\n";
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
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualNoOp, false, false);
  // add
  // we perform these operations in order to first do a sanity check that
  // 1. const cast isn't needed for upcasting
  // 2. there will be no segmentation faults before we run the removal tests
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddConst, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddPtrToConst, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddConstPtr, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddConstDoublePtr, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddConstDiffLevelPtr, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddMemberPtrToConst, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddConstMemberPtr, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddConstDoubleMemberPtr, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddConstDiffLevelMemberPtr, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddConstRef, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddConstArr, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddConstPtrToArr, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddConstPtrToArrOfConstPtrs, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddArrPtrConstData, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddDiffLevelArrPtrConstData, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddConstMixedPtrTypes, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddConstUnknownArrPtr, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddConstUnknownArrPtrToKnownArrPtr, false, false);

  // remove
  // we perform these operations in order to check the positive cases, along
  // with negative edge cases.
  // does not require const cast - implicit
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveConst, false, false);
  // does require const cast, base type downcast
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemovePtrToConst, true, false);
  // does not - implicit
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveConstPtr, false, false);
  // does - downcast
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveConstDoublePtr, true, false);
  // does not - level truncated
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveConstDiffLevelPtr, false, false);

  // Same as the above 4
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveMemberPtrToConst, true, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveConstMemberPtr, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveConstDoubleMemberPtr, true, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveConstDiffLevelMemberPtr, false, false);

  // does - downcast
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveConstRef, true, false);
  // does - downcast
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveConstArr, true, false);
  // does not - implicit
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveConstPtrToArr, false, false);
  // does - downcast
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveConstPtrToArrOfConstPtrs, true, false);
  // does - downcast
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveArrPtrConstData, true, false);
  // does not - level truncated
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveDiffLevelArrPtrConstData, false, false);
  // does - similar types going down
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveSimilarPtrsBeyondArrConstData, true, false);
  // does - All pointer-like types are downcasted
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveConstMixedPtrTypes, true, false);
  // does - Unknown size array is similar to unknown size array
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveConstUnknownArrPtr, true, false);
  // does - Unknown size array is similar to known size array
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveConstUnknownArrPtrToKnownArrPtr, true, false);
}

TEST_F(ClangQualifierModificationTest, TestVolatileCases) {
  // add
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddVolatile, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddPtrToVolatile, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddVolatilePtr, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddVolatileDoublePtr, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddVolatileDiffLevelPtr, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddVolatileRef, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddVolatileArr, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddVolatilePtrToArr, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddVolatilePtrToArrOfVolatilePtrs, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddArrPtrVolatileData, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddDiffLevelArrPtrVolatileData, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddVolatileMixedPtrTypes, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddVolatileUnknownArrPtr, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddVolatileUnknownArrPtrToKnownArrPtr, false, false);

  // remove
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveVolatile, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemovePtrToVolatile, true, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveVolatilePtr, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveVolatileDoublePtr, true, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveVolatileDiffLevelPtr, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveVolatileRef, true, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveVolatileArr, true, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveVolatilePtrToArr, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveVolatilePtrToArrOfVolatilePtrs, true, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveArrPtrVolatileData, true, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveDiffLevelArrPtrVolatileData, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveSimilarPtrsBeyondArrVolatileData, true, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveVolatileMixedPtrTypes, true, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveVolatileUnknownArrPtr, true, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveVolatileUnknownArrPtrToKnownArrPtr, true, false);
}

TEST_F(ClangQualifierModificationTest, TestRestrictCases) {
  // add
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddRestrictPtr, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddRestrictDoublePtr, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddRestrictDiffLevelPtr, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddRestrictArr, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddRestrictPtrToArr, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddRestrictPtrToArrOfRestrictPtrs, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddArrPtrRestrictData, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddDiffLevelArrPtrRestrictData, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddRestrictMixedPtrTypes, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddRestrictUnknownArrPtr, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddRestrictUnknownArrPtrToKnownArrPtr, false, false);

  // remove
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveRestrictPtr, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveRestrictDoublePtr, true, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveRestrictDiffLevelPtr, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveRestrictArr, true, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveRestrictPtrToArr, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveRestrictPtrToArrOfRestrictPtrs, true, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveArrPtrRestrictData, true, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveDiffLevelArrPtrRestrictData, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveSimilarPtrsBeyondArrRestrictData, true, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveRestrictMixedPtrTypes, true, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveRestrictUnknownArrPtr, true, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualRemoveRestrictUnknownArrPtrToKnownArrPtr, true, false);
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
  ASSERT_TRUE(parse(extension::NoQualifierChange, false));
  ASSERT_TRUE(parse(extension::NoQualifierChangeReinterpret, false));
  ASSERT_TRUE(parse(extension::ChangeNestedPointers, false));
  ASSERT_TRUE(parse(extension::ChangeNestedPointersReinterpret, false));
  ASSERT_TRUE(parse(extension::ChangeNestedPointersUntilArray, false));
  ASSERT_TRUE(parse(extension::ChangeNestedPointersUntilArrayReinterpret, false));
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
