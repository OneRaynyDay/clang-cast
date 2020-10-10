#include "assert.h"
#include "ClangCast.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Basic/Diagnostic.h"
#include "clang/Basic/DiagnosticOptions.h"
#include "clang/Basic/FileManager.h"
#include "clang/Basic/LangOptions.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Frontend/TextDiagnosticPrinter.h"
#include "clang/Rewrite/Core/Rewriter.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Core/Replacement.h"
#include "clang/Tooling/Refactoring.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/ADT/IntrusiveRefCntPtr.h"
#include "llvm/Support/Error.h"

using namespace clang::ast_matchers;
using namespace clang;
using namespace cppcast;
using namespace llvm;

static llvm::cl::OptionCategory ClangCastCategory("clang-cast options");

StatementMatcher CStyleCastMatcher = cStyleCastExpr().bind("cast");

class CStyleCastReplacer : public MatchFinder::MatchCallback {
  using ReplacementsMap = std::map<std::string, tooling::Replacements>;
public:
  CStyleCastReplacer(ReplacementsMap& Replacements) : Replacements(Replacements) {}

  /// Given an ordered list of casts, use the ASTContext to report necessary
  /// changes to the cast expression.
  unsigned reportDiagnostic(const std::vector<CXXCast>& casts,
                        const ASTContext* Context,
                        const QualType& CanonicalSubExpressionType,
                        const QualType& CanonicalCastType){
    DiagnosticsEngine &DiagEngine = Context->getDiagnostics();
    // Set diagnostics to warning by default, and to INFO for edge cases.
    DiagnosticIDs::Level DiagLevel = DiagnosticIDs::Warning;
    std::string DiagMessage = "The C-style cast can be substituted for ";
    assert (!casts.empty());
    // There are 8 different situations in which we want to provide
    // different messages for.
    // 1. No-op cast (remove the cast)
    // 2. Only const cast
    // 3. Static cast
    // 4. Static cast + const cast
    // 5. Reinterpret cast
    // 6. Reinterpret cast + const cast
    // 7. C style cast (keep the cast as is)
    // 8. Invalid cast (this should never happen, and would be a bug)
    bool ConstCastRequired = casts.size() > 1 && casts[1] == CXXCast::CC_ConstCast;
    if (casts[0] == CXXCast::CC_NoOpCast) {
      // Case 1
      if (!ConstCastRequired) {
        DiagMessage = "No cast is necessary (no-op)";
        DiagLevel = DiagnosticIDs::Remark;
      }
        // Case 2
      else {
        DiagMessage += "'const_cast<" + CanonicalCastType.getAsString() + ">'";
      }
    }
    else if (casts[0] == CXXCast::CC_StaticCast || casts[0] == CXXCast::CC_ReinterpretCast) {
      std::string CastType = casts[0] == CXXCast::CC_StaticCast ? "static_cast" : "reinterpret_cast";
      // Case 3,5
      if (!ConstCastRequired) {
        DiagMessage += "'" + CastType + "<" + CanonicalCastType.getAsString() + ">'";
      }
        // Case 4,6
      else {
        DiagMessage += ("'const_cast<" + CanonicalCastType.getAsString() + ">("
                        + "'" + CastType + "<" + changeQualifiers(CanonicalCastType, CanonicalSubExpressionType, Context).getAsString() + ">())'");
      }
    }
    // Case 7
    else if (casts[0] == CXXCast::CC_CStyleCast) {
      DiagMessage = "Cannot infer C++ style cast. Keeping C-style cast";
      DiagLevel = DiagnosticIDs::Remark;
    }
    // Case 8
    else if (casts[0] == CXXCast::CC_InvalidCast) {
      DiagMessage = "clang-casts has encountered an error. Currently does not support the following cast";
      DiagLevel = DiagnosticIDs::Error;
    }

    return DiagEngine.getDiagnosticIDs()->getCustomDiagID(
        DiagLevel, DiagMessage);
  }

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
    const CharSourceRange CastRange = CharSourceRange::getTokenRange(
        CastExpression->getLParenLoc(),
        CastExpression->getRParenLoc());

    auto replaceWithCast = [&](const std::vector<CXXCast>& casts) {
      tooling::Replacement Rep(
          Context->getSourceManager(),
          CastRange,
          // TODO
          StringRef("(lmao)"),
          Context->getLangOpts());

      Error ErrorCheck = Replacements[std::string(Rep.getFilePath())].add(Rep);
      // TODO: Don't just consume it without checking.
      // move is required because copy constructor is deleted.
      consumeError(std::move(ErrorCheck));
    };

    std::vector<CXXCast> CastOrder;

    CastOrder.push_back(CXXCastType);
    if (RequireConstCast) {
      CastOrder.push_back(CXXCast::CC_ConstCast);
    }

    unsigned ID = reportDiagnostic(CastOrder, Context, CanonicalSubExpressionType, CanonicalCastType);
    // Reports the error at the location of the cast
    Context->getDiagnostics().Report(CastExpression->getExprLoc(), ID);

    replaceWithCast(CastOrder);

    auto &SourceManager = Context->getSourceManager();
    SourceLocation Loc =
        SourceManager.getSpellingLoc(CastExpression->getBeginLoc());
    FullSourceLoc DiagnosticLocation = FullSourceLoc(Loc, SourceManager);
    if (Loc.isInvalid()) {
      outs() << "Loc invalid"
                   << "\n";
      return;
    }
    const FileEntry *FileEntry =
        SourceManager.getFileEntryForID(SourceManager.getFileID(Loc));
    if (!FileEntry) {
      outs() << "File entry invalid"
                   << "\n";
      return;
    }
    outs() << "Found c-style cast expression in file "
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

  std::vector<std::unique_ptr<ASTUnit>> ASTs;

  int Status = Tool.buildASTs(ASTs);
  int ASTStatus = 0;
  if (Status == 1) {
    // Building ASTs failed.
    return 1;
  } else if (Status == 2) {
    ASTStatus |= 1;
    errs() << "Failed to build AST for some of the files, "
                 << "results may be incomplete."
                 << "\n";
  } else {
    assert(Status == 0 && "Unexpected status returned");
  }

  CStyleCastReplacer Replacer(Tool.getReplacements());
  MatchFinder Finder;
  Finder.addMatcher(CStyleCastMatcher, &Replacer);
  auto Factory = tooling::newFrontendActionFactory(&Finder);

  // Add diagnostics
  int ExitCode = Tool.run(Factory.get());
  LangOptions DefaultLangOptions;
  IntrusiveRefCntPtr<DiagnosticOptions> DiagOpts(new DiagnosticOptions());
  TextDiagnosticPrinter DiagnosticPrinter(errs(), &*DiagOpts);
  DiagnosticsEngine Diagnostics(
      IntrusiveRefCntPtr<DiagnosticIDs>(new DiagnosticIDs()), &*DiagOpts,
      &DiagnosticPrinter, false);

  auto &FileMgr = Tool.getFiles();
  SourceManager Sources(Diagnostics, FileMgr);
  Rewriter Rewrite(Sources, DefaultLangOptions);

  return ExitCode;
  // Tool.runAndSave(Factory.get());

  /// ===
  // std::string code = "#include <stdint.h>\nvoid f(){\n(bool) 3.2f;\n(int) true;\nint x = 2;\nchar c = 'a';\nconst int& y = (const int&) x;\n(const float*) &x;}"; std::unique_ptr<clang::ASTUnit> ast(clang::tooling::buildASTFromCode(code));

  // now you have the AST for the code snippet
  //  clang::ASTContext * pctx = &(ast->getASTContext());
  //  clang::TranslationUnitDecl * decl = pctx->getTranslationUnitDecl();
  /// ===
//
//  for (const auto &ast : ASTs) {
//    Finder.matchAST(ast->getASTContext());
//  }
//
//  outs() << "Replacements collected by the tool:\n";
//  auto toString = [](const tooling::Replacements& Replaces) {
//    std::string Result;
//    raw_string_ostream Stream(Result);
//    for (const auto Replace : Replaces) {
//      Stream << Replace.getFilePath() << ": " << Replace.getOffset() << ":+"
//             << Replace.getLength() << ":\"" << Replace.getReplacementText()
//             << "\"\n";
//    }
//    return Stream.str();
//  };
//  for (auto &p : Tool.getReplacements()) {
//    outs() << p.first << ":" << toString(p.second) << "\n";
//  }

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
