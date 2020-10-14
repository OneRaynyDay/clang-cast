#include "ClangCast.h"
#include "assert.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Basic/Diagnostic.h"
#include "clang/Basic/DiagnosticOptions.h"
#include "clang/Basic/FileManager.h"
#include "clang/Basic/LangOptions.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Frontend/ASTConsumers.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/TextDiagnosticPrinter.h"
#include "clang/Rewrite/Core/Rewriter.h"
#include "clang/Rewrite/Frontend/FixItRewriter.h"
#include "clang/Rewrite/Frontend/FrontendActions.h"
#include "clang/StaticAnalyzer/Frontend/FrontendActions.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/ADT/IntrusiveRefCntPtr.h"
#include "llvm/Support/Error.h"

using namespace clang::ast_matchers;
using namespace clang;
using namespace cppcast;
using namespace llvm;

namespace cli {
static llvm::cl::OptionCategory ClangCastCategory("clang-cast options");

llvm::cl::extrahelp ClangCastCategoryHelp(R"(
clang-cast finds C-style casts and attempts to convert them into C++ casts.
C++ casts are preferred since they are safer and more explicit than C-style casts.

For example:

double* p = nullptr;
(int*) p;

... is converted into:

double* p = nullptr;
reinterpret_cast<int*>(p);

When running clang-cast on a compilation unit, the tool will emit useful diagnostics.
The tool can be used to modify a file in-place or into a new file with an added suffix.
)");

llvm::cl::opt<bool>
    ModifyOption("modify",
                  llvm::cl::init(false),
                  llvm::cl::desc("If true, clang-cast will overwrite or write to a new file (-suffix option) with the casts replaced"),
                  llvm::cl::cat(ClangCastCategory));

llvm::cl::opt<std::string> SuffixOption(
    "suffix",
    llvm::cl::desc("If suffix is set, changes of a file F will be written to F+suffix"),
    llvm::cl::cat(ClangCastCategory));

llvm::cl::extrahelp CommonHelp(clang::tooling::CommonOptionsParser::HelpMessage);
} // namespace cli

StatementMatcher CStyleCastMatcher = cStyleCastExpr().bind("cast");

namespace rewriter {

class FixItRewriterOptions : public clang::FixItOptions {
public:
  FixItRewriterOptions(const std::string& RewriteSuffix = {})
      : RewriteSuffix(RewriteSuffix) {
    if (RewriteSuffix.empty()) {
      llvm::errs() << "Suffix passed in is empty - we are modifying in place.\n";
      InPlace = true;
    }
    else {
      llvm::errs() << "Suffix passed in is " << RewriteSuffix << ". We are not modifying in place.\n";
      InPlace = false;
    }
  }

  std::string RewriteFilename(const std::string& Filename, int& fd) override {
    // Set fd to -1 to mean that the file descriptor is not yet opened.
    fd = -1;
    const auto NewFilename = Filename + RewriteSuffix;
    llvm::outs() << "Writing to file " << NewFilename << " as a new file.\n";
    return NewFilename;
  }

private:
  std::string RewriteSuffix;
};

} // namespace rewriter

class CStyleCastReplacer : public MatchFinder::MatchCallback {
  using RewriterPtr = std::unique_ptr<clang::FixItRewriter>;
  rewriter::FixItRewriterOptions FixItOptions;
  bool Modify;

  RewriterPtr createRewriter(clang::ASTContext* Context) {
    auto Rewriter =
        std::make_unique<clang::FixItRewriter>(Context->getDiagnostics(),
                                               Context->getSourceManager(),
                                               Context->getLangOpts(),
                                               &FixItOptions);

    DiagnosticsEngine.setClient(Rewriter.get(), false);
    return Rewriter;
  }

public:
  CStyleCastReplacer(bool Modify, const std::string& Filename) : FixItOptions(Filename), Modify(Modify) {}

  CharSourceRange getRangeForSubExpression(const CStyleCastExpr* CastExpression,
                                           const ASTContext* Context) {
    const Expr* SubExpression = CastExpression->getSubExprAsWritten();
    const ParenExpr* ParenExpression;
    while ((ParenExpression = dyn_cast<ParenExpr>(SubExpression))) {
      SubExpression = ParenExpression->getSubExpr();
    }
    auto SubExprStart = SubExpression->getBeginLoc();
    auto SubExprEnd = Lexer::getLocForEndOfToken(
        SubExpression->getEndLoc(),
        0,
        Context->getSourceManager(),
        Context->getLangOpts());
    return CharSourceRange::getCharRange(SubExprStart, SubExprEnd);
  }

  /// There are a few cases for the replacement string:
  /// 1. No-op cast (remove the cast)
  /// 2. Only const cast
  /// 3. Static cast
  /// 4. Static cast + const cast
  /// 5. Reinterpret cast
  /// 6. Reinterpret cast + const cast
  /// 7. C style cast (keep the cast as is)
  std::string replaceExpression(const std::vector<CXXCast>& Casts,
                                const CStyleCastExpr* CastExpression,
                                const ASTContext* Context) {
    const Expr* SubExpression = CastExpression->getSubExprAsWritten();
    QualType CanonicalSubExpressionType = SubExpression->getType().getCanonicalType();
    QualType CanonicalCastType = CastExpression->getTypeAsWritten().getCanonicalType();

    std::string SubExpressionStr = Lexer::getSourceText(
                                       getRangeForSubExpression(CastExpression, Context),
                                       Context->getSourceManager(),
                                       Context->getLangOpts()).str();

    bool ConstCastRequired = Casts.size() > 1 && Casts[1] == CXXCast::CC_ConstCast;

    if (Casts[0] == CXXCast::CC_NoOpCast) {
      // Case 1
      if (!ConstCastRequired) {
        // our replacement is simply the subexpression (no cast needed)
        return SubExpressionStr;
      }
      // Case 2
      else {
        return "const_cast<" + CanonicalCastType.getAsString() +
               ">(" + SubExpressionStr + ")";
      }
    }
    else if (Casts[0] == CXXCast::CC_StaticCast || Casts[0] == CXXCast::CC_ReinterpretCast) {
      std::string CastTypeStr = Casts[0] == CXXCast::CC_StaticCast
                                    ? "static_cast"
                                    : "reinterpret_cast";
      // Case 3,5
      if (!ConstCastRequired) {
        return CastTypeStr + "<" + CanonicalCastType.getAsString() + ">(" +
               SubExpressionStr + ")";
      }
      // Case 4,6
      else {
        QualType IntermediateType = changeQualifiers(
            CanonicalCastType, CanonicalSubExpressionType, Context);
        return "const_cast<" + CanonicalCastType.getAsString() + ">(" +
               CastTypeStr + "<" + IntermediateType.getAsString() + ">(" +
               SubExpressionStr + "))";
      }
    }
    // This shouldn't happen
    llvm::errs() << "This shouldn't happen.\n";
    return {};
  }

  /// Given an ordered list of casts, use the ASTContext to report necessary
  /// changes to the cast expression.
  void reportDiagnostic(const std::vector<CXXCast>& Casts,
                        const CStyleCastExpr* CastExpression,
                        ASTContext* Context) {
    DiagnosticsEngine &DiagEngine = Context->getDiagnostics();
    // Set diagnostics to warning by default, and to INFO for edge cases.
    std::string DiagMessage = "The C-style cast can be replaced by '%0'";
    auto StartingLoc = CastExpression->getExprLoc();
    assert (!Casts.empty());

    // Invalid cast or dynamic (this should never happen, and would be a bug)
    if (Casts[0] == CXXCast::CC_InvalidCast || Casts[0] == CXXCast::CC_DynamicCast) {
      unsigned ID = DiagEngine.getDiagnosticIDs()->getCustomDiagID(DiagnosticIDs::Error, "clang-casts has encountered an error. Currently does not support the following cast");
      DiagEngine.Report(StartingLoc, ID);
      return;
    }
    if (Casts[0] == CXXCast::CC_CStyleCast) {
      unsigned ID = DiagEngine.getDiagnosticIDs()->getCustomDiagID(DiagnosticIDs::Remark, "The C-style cast cannot be converted into a C++ style cast. Skipping.");
      DiagEngine.Report(StartingLoc, ID);
      return;
    }

    auto Replacement = replaceExpression(Casts, CastExpression, Context);

    const auto FixIt = clang::FixItHint::CreateReplacement(CastExpression->getSourceRange(), Replacement);

    // Before we report, we create the rewriter if necessary:
    auto Rewriter = Modify ? createRewriter(Context) : nullptr;

    unsigned ID = DiagEngine.getDiagnosticIDs()->getCustomDiagID(
        DiagnosticIDs::Warning, DiagMessage);
    auto Builder = DiagEngine.Report(StartingLoc, ID);
    Builder.AddString(Replacement);
    // Reports the error at the location of the cast
    Builder.AddFixItHint(FixIt);

    llvm::outs() << "applying modify: " << Modify << "\n\n\n";

    if (Modify) {
      bool ModificationResult = Rewriter->WriteFixedFiles();
      llvm::outs() << "modification result: " << ModificationResult << ".\n";
    }
  }

  virtual void run(const MatchFinder::MatchResult& Result) {
    ASTContext *Context = Result.Context;
    const CStyleCastExpr* CastExpression = Result.Nodes.getNodeAs<CStyleCastExpr>("cast");

    if (!CastExpression)
      return;

    // Retrieving top level cast type
    const CXXCast CXXCastType = getCastKindFromCStyleCast(CastExpression);
    // Retrieving const cast requirements
    const bool RequireConstCast = requireConstCast(CastExpression, Context);
    std::vector<CXXCast> CastOrder;

    CastOrder.push_back(CXXCastType);
    if (RequireConstCast) {
      CastOrder.push_back(CXXCast::CC_ConstCast);
    }

    reportDiagnostic(CastOrder, CastExpression, Context);
  }
};

int main(int argc, const char **argv) {
  // parse the command-line args passed to your code
  tooling::CommonOptionsParser op(argc, argv, cli::ClangCastCategory);
  // create a new Clang Tool instance (a LibTooling environment)
  tooling::ClangTool Tool(op.getCompilations(), op.getSourcePathList());

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

  CStyleCastReplacer Replacer(cli::ModifyOption, cli::SuffixOption);
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
}
