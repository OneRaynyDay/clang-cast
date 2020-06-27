#include <vector>
#include <set>
#include <iostream>
#include "ClangCast.h"
#include "ClangCastTestCases.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "gtest/gtest.h"

#define CLANG_CAST_CHECK_SINGLE_TEST_CASE(cast_kind, cxx_cast)                \
  {                                                                           \
  auto res = parse(cast_kind);                                                \
  ASSERT_GE(res.first.size(), 1);                                             \
  ASSERT_EQ(res.second.size(), 1);                                            \
  ASSERT_TRUE(res.first.find(CastKind::CK_##cast_kind) != res.first.end());   \
  ASSERT_EQ(res.second[0], CXXCast::CC_##cxx_cast);                           \
  }

using namespace testcases;
using namespace clang;
using namespace clang::tooling;
using namespace clang::ast_matchers;
using namespace clang::cppcast;

static constexpr auto CastVar = "cast";

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
    // TODO: remove after done testing
    Expr->dump();
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

class ClangCastTest : public ::testing::Test {
  using CastKindSet = std::set<CastKind>;
  using CXXCastVector = std::vector<CXXCast>;
  StatementMatcher CStyleCastMatcher;
protected:
  ClangCastTest() : CStyleCastMatcher(cStyleCastExpr().bind(CastVar)) {}

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

TEST_F(ClangCastTest, TestConstCastTypes) {
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(NoOp, ConstCast);
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(ArrayToPointerDecay, ConstCast);
  // Unchecked: CLANG_CAST_CHECK_SINGLE_TEST_CASE(LValueToRValue, ConstCast);
}

TEST_F(ClangCastTest, TestReinterpretCastTypes) {
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(BitCast, ReinterpretCast);
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(LValueBitCast, ReinterpretCast);
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(ReinterpretMemberPointer, ReinterpretCast);
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(PointerToIntegral, ReinterpretCast);
}

TEST_F(ClangCastTest, TestStaticCastTypes) {
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(BaseToDerived, StaticCast);
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(DerivedToBase, StaticCast);
  // Unchecked: CLANG_CAST_CHECK_SINGLE_TEST_CASE(UncheckedDerivedToBase, StaticCast);
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(FunctionToPointerDecay, StaticCast);
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(NullToPointer, StaticCast);
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(NullToMemberPointer, StaticCast);
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(BaseToDerivedMemberPointer, StaticCast);
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(DerivedToBaseMemberPointer, StaticCast);
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(MemberPointerToBoolean, StaticCast);
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(UserDefinedConversion, StaticCast);
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(ConstructorConversion, StaticCast);
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(IntegralToPointer, StaticCast);
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(PointerToBoolean, StaticCast);
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(ToVoid, StaticCast);
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(VectorSplat, StaticCast);
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(IntegralCast, StaticCast);
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(IntegralToBoolean, StaticCast);
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(IntegralToFloating, StaticCast);
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(FloatingToIntegral, StaticCast);
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(FloatingToBoolean, StaticCast);
  // TODO: How is this possible? CLANG_CAST_CHECK_SINGLE_TEST_CASE(BooleanToSignedIntegral, StaticCast);
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(FloatingCast, StaticCast);
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(FloatingRealToComplex, StaticCast);
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(FloatingComplexToReal, StaticCast);
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(FloatingComplexToBoolean, StaticCast);
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(FloatingComplexCast, StaticCast);
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(FloatingComplexToIntegralComplex, StaticCast);
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(IntegralRealToComplex, StaticCast);
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(IntegralComplexToReal, StaticCast);
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(IntegralComplexToBoolean, StaticCast);
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(IntegralComplexCast, StaticCast);
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(IntegralComplexToFloatingComplex, StaticCast);
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(AtomicToNonAtomic, StaticCast);
  CLANG_CAST_CHECK_SINGLE_TEST_CASE(NonAtomicToAtomic, StaticCast);
}

TEST_F(ClangCastTest, TestEdgeCases) {
  using namespace edgecases;
  {
    auto res = parse(DerivedToBasePrivateSpecifier);
    ASSERT_GE(res.first.size(), 1);
    ASSERT_GE(res.second.size(), 1);
    ASSERT_TRUE(res.first.find(CastKind::CK_DerivedToBase) != res.first.end());
    ASSERT_EQ(res.second[0], CXXCast::CC_CStyleCast);
  }
  {
    auto res = parse(BaseToDerivedPrivateSpecifier);
    ASSERT_GE(res.first.size(), 1);
    ASSERT_GE(res.second.size(), 1);
    ASSERT_TRUE(res.first.find(CastKind::CK_BaseToDerived) != res.first.end());
    ASSERT_EQ(res.second[0], CXXCast::CC_CStyleCast);
  }
}
