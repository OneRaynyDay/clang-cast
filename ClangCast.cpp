#include "ClangCast.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"

using namespace clang::ast_matchers;
using namespace clang;
using namespace cppcast;

static llvm::cl::OptionCategory ClangCastCategory("clang-cast options");

StatementMatcher CStyleCastMatcher = cStyleCastExpr().bind("cast");

class CStyleCastPrinter : public MatchFinder::MatchCallback {
  virtual void run(const MatchFinder::MatchResult& Result) {
    ASTContext *Context = Result.Context;
    const CStyleCastExpr* CastExpression = Result.Nodes.getNodeAs<CStyleCastExpr>("cast");

    getCastKindFromCStyleCast(CastExpression);

    if (!CastExpression)
      return;

    const CXXCast CXXCastType = getCastKindFromCStyleCast(CastExpression);

    if (CXXCastType == CXXCast::CC_ConstCast)
      llvm::outs() << "cast type: const\n";
    else if (CXXCastType == CXXCast::CC_StaticCast)
      llvm::outs() << "cast type: static\n";
    else if (CXXCastType == CXXCast::CC_ReinterpretCast)
      llvm::outs() << "cast type: reinterpret\n";
    else if (CXXCastType == CXXCast::CC_DynamicCast)
      llvm::outs() << "cast type: dynamic\n";

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
};

int main(int argc, const char **argv) {
  // parse the command-line args passed to your code
//  tooling::CommonOptionsParser op(argc, argv, ClangCastCategory);
  // create a new Clang Tool instance (a LibTooling environment)
//  tooling::ClangTool Tool(op.getCompilations(), op.getSourcePathList());

  /// ===
  std::string code = "#include <stdint.h>\nvoid f(){\n(bool) 3.2f;\n(int) true;\nint x = 2;\nconst int y = (const int) x;\n(intptr_t) nullptr;}";
  std::unique_ptr<clang::ASTUnit> ast(clang::tooling::buildASTFromCode(code));

  // now you have the AST for the code snippet
//  clang::ASTContext * pctx = &(ast->getASTContext());
//  clang::TranslationUnitDecl * decl = pctx->getTranslationUnitDecl();
  /// ===
  std::vector<std::unique_ptr<ASTUnit>> ASTs;

//  int Status = Tool.buildASTs(ASTs);
//  int ASTStatus = 0;
//  if (Status == 1) {
//    // Building ASTs failed.
//    return 1;
//  } else if (Status == 2) {
//    ASTStatus |= 1;
//    llvm::errs() << "Failed to build AST for some of the files, "
//                 << "results may be incomplete."
//                 << "\n";
//  } else {
//    assert(Status == 0 && "Unexpected status returned");
//  }

  CStyleCastPrinter Printer;
  MatchFinder Finder;
  Finder.addMatcher(CStyleCastMatcher, &Printer);

  Finder.matchAST(ast->getASTContext());

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
//  std::unique_ptr<tooling::FrontendActionFactory> action_ptr =
//      tooling::newFrontendActionFactory<FindCStyleCastAction>();
  /// ===

}
