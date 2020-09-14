#include "ClangCast.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/Tooling/Core/Replacement.h"
#include "clang/Tooling/Refactoring.h"
#include "llvm/Support/Error.h"

using namespace clang::ast_matchers;
using namespace clang;
using namespace cppcast;

static llvm::cl::OptionCategory ClangCastCategory("clang-cast options");

StatementMatcher CStyleCastMatcher = cStyleCastExpr().bind("cast");

class CStyleCastReplacer : public MatchFinder::MatchCallback {
  using ReplacementsMap = std::map<std::string, tooling::Replacements>;
public:
  CStyleCastReplacer(ReplacementsMap& Replacements) : Replacements(Replacements) {}

  virtual void run(const MatchFinder::MatchResult& Result) {
    ASTContext *Context = Result.Context;
    const CStyleCastExpr* CastExpression = Result.Nodes.getNodeAs<CStyleCastExpr>("cast");

    if (!CastExpression)
      return;

    // Retrieving top level cast type
    const CXXCast CXXCastType = getCastKindFromCStyleCast(CastExpression);

    // Retrieving const cast requirements
    const Expr* SubExpression = CastExpression->getSubExprAsWritten();
    QualType CanonicalSubExpressionType = SubExpression->getType().getCanonicalType();
    QualType CanonicalCastType = CastExpression->getTypeAsWritten().getCanonicalType();
    const bool RequireConstCast = requireConstCast(CanonicalSubExpressionType, CanonicalCastType);
    const CharSourceRange CastRange = CharSourceRange::getTokenRange(CastExpression->getLParenLoc(), CastExpression->getRParenLoc());

    auto replaceWithCast = [&](const std::vector<CXXCast>& casts) {
      tooling::Replacement Rep(
          Context->getSourceManager(),
          CastRange,
          StringRef("(lmao)"),
          Context->getLangOpts());

      llvm::Error ErrorCheck = Replacements[std::string(Rep.getFilePath())].add(Rep);
      // TODO: Don't just consume it without checking.
      // move is required because copy constructor is deleted.
      llvm::consumeError(std::move(ErrorCheck));
    };

    std::vector<CXXCast> CastOrder;

    // If in the rare occasion, we really do require a full C-style power
    // cast, we will simply skip over this match.
    if(CXXCastType == CXXCast::CC_CStyleCast) {
      llvm::outs() << "Skipping over a truly C-style cast.\n";
      return;
    }

    if (CXXCastType != CXXCast::CC_NoOpCast) {
      CastOrder.push_back(CXXCastType);
    }
    if (RequireConstCast) {
      CastOrder.push_back(CXXCast::CC_ConstCast);
    }

    replaceWithCast(CastOrder);

    auto &SourceManager = Context->getSourceManager();
    SourceLocation Loc =
        SourceManager.getSpellingLoc(CastExpression->getBeginLoc());
    FullSourceLoc DiagnosticLocation = FullSourceLoc(Loc, SourceManager);
    if (Loc.isInvalid()) {
      llvm::outs() << "Loc invalid"
                   << "\n";
      return;
    }
    const FileEntry *FileEntry =
        SourceManager.getFileEntryForID(SourceManager.getFileID(Loc));
    if (!FileEntry) {
      llvm::outs() << "File entry invalid"
                   << "\n";
      return;
    }
    llvm::outs() << "Found c-style cast expression in file "
                 << FileEntry->getName() << " on line "
                 << DiagnosticLocation.getSpellingLineNumber()
                 << ".\n";
    return;
  }
private:
  ReplacementsMap& Replacements;
};

int main(int argc, const char **argv) {
  // parse the command-line args passed to your code
  tooling::CommonOptionsParser op(argc, argv, ClangCastCategory);
  // create a new Clang Tool instance (a LibTooling environment)
  tooling::RefactoringTool Tool(op.getCompilations(), op.getSourcePathList());

  /// ===
  // std::string code = "#include <stdint.h>\nvoid f(){\n(bool) 3.2f;\n(int) true;\nint x = 2;\nchar c = 'a';\nconst int& y = (const int&) x;\n(const float*) &x;}"; std::unique_ptr<clang::ASTUnit> ast(clang::tooling::buildASTFromCode(code));

  // now you have the AST for the code snippet
  //  clang::ASTContext * pctx = &(ast->getASTContext());
  //  clang::TranslationUnitDecl * decl = pctx->getTranslationUnitDecl();
  /// ===
  std::vector<std::unique_ptr<ASTUnit>> ASTs;

  int Status = Tool.buildASTs(ASTs);
  int ASTStatus = 0;
  if (Status == 1) {
    // Building ASTs failed.
    return 1;
  } else if (Status == 2) {
    ASTStatus |= 1;
    llvm::errs() << "Failed to build AST for some of the files, "
                 << "results may be incomplete."
                 << "\n";
  } else {
    assert(Status == 0 && "Unexpected status returned");
  }

  CStyleCastReplacer Replacer(Tool.getReplacements());
  MatchFinder Finder;
  Finder.addMatcher(CStyleCastMatcher, &Replacer);
//
//  for (const auto &ast : ASTs) {
//    Finder.matchAST(ast->getASTContext());
//  }
//
//  llvm::outs() << "Replacements collected by the tool:\n";
//  auto toString = [](const tooling::Replacements& Replaces) {
//    std::string Result;
//    llvm::raw_string_ostream Stream(Result);
//    for (const auto Replace : Replaces) {
//      Stream << Replace.getFilePath() << ": " << Replace.getOffset() << ":+"
//             << Replace.getLength() << ":\"" << Replace.getReplacementText()
//             << "\"\n";
//    }
//    return Stream.str();
//  };
//  for (auto &p : Tool.getReplacements()) {
//    llvm::outs() << p.first << ":" << toString(p.second) << "\n";
//  }

  auto ActionPtr = tooling::newFrontendActionFactory(&Finder);
  Tool.runAndSave(ActionPtr.get());

//  int result = Tool.run(tooling::newFrontendActionFactory(&Finder).get());
  /// === begin random snippet
//  std::string code = "struct A{public: int i;}; void f(A & a}{}";
//  std::unique_ptr<clang::ASTUnit> ast(clang::tooling::buildASTFromCode(code));
//
//  // now you have the AST for the code snippet
//  clang::ASTContext * pctx = &(ast->getASTContext());
//  clang::TranslationUnitDecl * decl = pctx->getTranslationUnitDecl();
  /// === end
//  // run the Clang Tool, creating a new FrontendAction (explained below)
  /// ===

}
