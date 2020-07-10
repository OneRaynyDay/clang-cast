#include "ClangCXXCastTestCases.h"
#include "ClangQualifierTestCases.h"
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
  ASSERT_GE(res.first.size(), 1);                                             \
  ASSERT_EQ(res.second.size(), 1);                                            \
  ASSERT_TRUE(res.first.find(CastKind::CK_##cast_kind) != res.first.end());   \
  ASSERT_EQ(res.second[0], CXXCast::CC_##cxx_cast);                           \
  }

#define CLANG_QUAL_CHECK_SINGLE_TEST_CASE(test_case, qual_mod, req_const)     \
  {                                                                           \
  auto res = parse(test_case);                                                \
  ASSERT_EQ(res.first, qual_mod);                                             \
  ASSERT_EQ(res.second, req_const);                                           \
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

struct QualifierChecker : MatchFinder::MatchCallback {
  bool QualModified;
  bool RequireConstCast;
  QualifierChecker() = default;

  virtual void run(const MatchFinder::MatchResult &Result) override {
    const CStyleCastExpr* CastExpression = Result.Nodes.getNodeAs<CStyleCastExpr>(CastVar);
    if(!CastExpression) {
      llvm::errs() << "This should never happen.\n";
      return;
    }
    // TODO: remove after done testing
    CastExpression->dump();
    const Expr* SubExpression = CastExpression->getSubExprAsWritten();
    QualType CanonicalSubExpressionType = SubExpression->getType().getCanonicalType();
    QualType CanonicalCastType = CastExpression->getTypeAsWritten().getCanonicalType();
    QualModified = details::isQualifierModified(CanonicalSubExpressionType, CanonicalCastType);
    RequireConstCast = requireConstCast(CanonicalSubExpressionType, CanonicalCastType);
  }
};

/// Uses CStyleCastCollector to collect all CXXCast enums obtained
/// and CastKinds encountered.
class ClangCXXCastTest : public ::testing::Test {
  using CastKindSet = std::set<CastKind>;
  using CXXCastVector = std::vector<CXXCast>;
  StatementMatcher CStyleCastMatcher;
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
protected:
  ClangQualifierModificationTest() : CStyleCastMatcher(cStyleCastExpr().bind(CastVar)) {}

  std::pair<bool, bool> parse(const StringRef Code) {
    std::unique_ptr<clang::ASTUnit> ast(clang::tooling::buildASTFromCode(Code));
    QualifierChecker Checker;
    MatchFinder Finder;
    Finder.addMatcher(CStyleCastMatcher, &Checker);
    Finder.matchAST(ast->getASTContext());
    return {Checker.QualModified, Checker.RequireConstCast};
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
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(IntegralToPointer, StaticCast);
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

TEST_F(ClangCXXCastTest, TestEdgeCases) {
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
  CLANG_CXX_CAST_CHECK_SINGLE_TEST_CASE(Dependent, CStyleCast);
}

TEST_F(ClangQualifierModificationTest, TestAllCases) {
  // These tests mean:
  // Is <test case> modifying any qualifiers?
  // Does the C-style cast in <test case> require a const_cast?
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualNoOp, false, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddConst, true, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddConstPtr, true, true);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddConstDoublePtr, true, true);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddConstRef, true, true);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddConstArr, true, true);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddConstArrPtr, true, true);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddVolatile, true, false);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddVolatilePtr, true, true);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddVolatileDoublePtr, true, true);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddVolatileRef, true, true);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddVolatileArr, true, true);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddVolatileArrPtr, true, true);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddRestrictedPtr, true, true);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddRestrictedDoublePtr, true, true);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddRestrictedRef, true, true);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddRestrictedArr, true, true);
  CLANG_QUAL_CHECK_SINGLE_TEST_CASE(QualAddRestrictedArrPtr, true, true);
// TODO: for member function pointers you can actually change the qualifier
// for it and in order to do so you use reinterpret_cast WITHOUT
// const_cast to remove the qualifiers... WTF?
// https://godbolt.org/z/APnWdN
}
