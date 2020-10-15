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

namespace clang {

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
    PedanticOption("pedantic", llvm::cl::init(false),
                   llvm::cl::desc("If true, clang-cast will not assume "
                                  "qualification conversion extensions \n"
                                  "(this will lead to more false negatives) "
                                  "that clang adds. This is for projects \n"
                                  "which use the -pedantic flag and have "
                                  "extensions turned off."),
                   llvm::cl::cat(ClangCastCategory));

llvm::cl::opt<bool>
    ModifyOption("modify", llvm::cl::init(false),
                 llvm::cl::desc("If true, clang-cast will overwrite or "
                                "write to a new file (-suffix option) \n"
                                "with the casts replaced."),
                 llvm::cl::cat(ClangCastCategory));

llvm::cl::opt<bool>
    ReinterpretError("reinterpret-error", llvm::cl::init(false),
                     llvm::cl::desc("If true, clang-cast will issue an error "
                                    "for any C-style casts that are \n"
                                    "performing reinterpret_casts."),
                     llvm::cl::cat(ClangCastCategory));

llvm::cl::opt<std::string>
    SuffixOption("suffix",
                 llvm::cl::desc("If suffix is set, changes of "
                                "a file F will be written to F+suffix."),
                 llvm::cl::cat(ClangCastCategory));

llvm::cl::extrahelp
    CommonHelp(clang::tooling::CommonOptionsParser::HelpMessage);
} // namespace cli

namespace rewriter {

class FixItRewriterOptions : public clang::FixItOptions {
public:
  FixItRewriterOptions(const std::string &RewriteSuffix)
      : RewriteSuffix(RewriteSuffix) {
    if (RewriteSuffix.empty()) {
      llvm::errs()
          << "Suffix passed in is empty - we are modifying in place.\n";
      InPlace = true;
    } else {
      llvm::errs() << "Suffix passed in is " << RewriteSuffix
                   << ". We are not modifying in place.\n";
      InPlace = false;
    }
  }

  std::string RewriteFilename(const std::string &Filename, int &fd) override {
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

namespace cppcast {
class Replacer : public MatchFinder::MatchCallback {
  using RewriterPtr = std::unique_ptr<clang::FixItRewriter>;
  rewriter::FixItRewriterOptions FixItOptions;
  bool Modify;
  RewriterPtr Rewriter;
  bool Pedantic;
  bool ReinterpretError;

  RewriterPtr createRewriter(clang::ASTContext *Context) {
    auto Rewriter = std::make_unique<clang::FixItRewriter>(
        Context->getDiagnostics(), Context->getSourceManager(),
        Context->getLangOpts(), &FixItOptions);

    Context->getDiagnostics().setClient(Rewriter.get(), false);
    return Rewriter;
  }

public:
  // We can't initialize the RewriterPtr until we get an ASTContext.
  Replacer(const bool Modify, const std::string &Filename, const bool Pedantic,
           const bool ReinterpretError)
      : FixItOptions(Filename), Modify(Modify), Pedantic(Pedantic),
        ReinterpretError(ReinterpretError) {}

  CharSourceRange getRangeForExpression(const Expr *Expression,
                                        const ASTContext *Context) {
    const ParenExpr *ParenExpression;
    while ((ParenExpression = dyn_cast<ParenExpr>(Expression))) {
      Expression = ParenExpression->getSubExpr();
    }
    auto ExprStart = Expression->getBeginLoc();
    auto ExprEnd = Lexer::getLocForEndOfToken(Expression->getEndLoc(), 0,
                                              Context->getSourceManager(),
                                              Context->getLangOpts());
    return CharSourceRange::getCharRange(ExprStart, ExprEnd);
  }

  /// There are a few cases for the replacement string:
  /// 1. No-op cast (remove the cast)
  /// 2. Only const cast
  /// 3. Static cast
  /// 4. Static cast + const cast
  /// 5. Reinterpret cast
  /// 6. Reinterpret cast + const cast
  /// 7. C style cast (keep the cast as is)
  std::string replaceExpression(const std::vector<CXXCast> &Casts,
                                const CStyleCastExpr *CastExpression,
                                const ASTContext *Context) {
    const Expr *SubExpression = CastExpression->getSubExprAsWritten();
    QualType CanonicalSubExpressionType =
        SubExpression->getType().getCanonicalType();
    QualType CanonicalCastType =
        CastExpression->getTypeAsWritten().getCanonicalType();

    const auto &LangOpts = Context->getLangOpts();

    std::string SubExpressionStr =
        Lexer::getSourceText(getRangeForExpression(SubExpression, Context),
                             Context->getSourceManager(), LangOpts)
            .str();

    bool ConstCastRequired =
        Casts.size() > 1 && Casts[1] == CXXCast::CC_ConstCast;

    if (Casts[0] == CXXCast::CC_NoOpCast) {
      // Case 1
      if (!ConstCastRequired) {
        // our replacement is simply the subexpression (no cast needed)
        return SubExpressionStr;
      }
      // Case 2
      else {
        // const<>
        return cppCastToString(Casts[1]) + "<" +
               CanonicalCastType.getAsString(LangOpts) + ">(" +
               SubExpressionStr + ")";
      }
    } else if (Casts[0] == CXXCast::CC_StaticCast ||
               Casts[0] == CXXCast::CC_ReinterpretCast) {
      std::string CastTypeStr = cppCastToString(Casts[0]);
      // Case 3,5
      if (!ConstCastRequired) {
        return CastTypeStr + "<" + CanonicalCastType.getAsString(LangOpts) +
               ">(" + SubExpressionStr + ")";
      }
      // Case 4,6
      else {
        QualType IntermediateType = changeQualifiers(
            CanonicalCastType, CanonicalSubExpressionType, Context, Pedantic);
        return cppCastToString(Casts[1]) + "<" +
               CanonicalCastType.getAsString(LangOpts) + ">(" + CastTypeStr +
               "<" + IntermediateType.getAsString(LangOpts) + ">(" +
               SubExpressionStr + "))";
      }
    }
    // This shouldn't happen
    llvm_unreachable(
        "The type of cast passed in cannot produce a replacement.");
    return {};
  }

  /// Given an ordered list of casts, use the ASTContext to report necessary
  /// changes to the cast expression.
  void reportDiagnostic(const std::vector<CXXCast> &Casts,
                        const CStyleCastExpr *CastExpression,
                        ASTContext *Context) {
    // Before we report, we create the rewriter if necessary:
    if (Modify && Rewriter == nullptr) {
      Rewriter = createRewriter(Context);
    }

    DiagnosticsEngine &DiagEngine = Context->getDiagnostics();
    // Set diagnostics to warning by default, and to INFO for edge cases.
    const char DiagMessage[] = "The C-style cast can be replaced by '%0'";
    auto StartingLoc = CastExpression->getExprLoc();
    assert(!Casts.empty());

    // Invalid cast or dynamic (this should never happen, and would be a bug)
    if (Casts[0] == CXXCast::CC_InvalidCast ||
        Casts[0] == CXXCast::CC_DynamicCast) {
      unsigned ID = DiagEngine.getCustomDiagID(
          DiagnosticsEngine::Error,
          "clang-casts has encountered an error. Currently does not support "
          "the following cast");
      DiagEngine.Report(StartingLoc, ID);
      return;
    }
    if (Casts[0] == CXXCast::CC_CStyleCast) {
      unsigned ID = DiagEngine.getCustomDiagID(
          DiagnosticsEngine::Remark, "The C-style cast cannot be converted "
                                     "into a C++ style cast. Skipping.");
      DiagEngine.Report(StartingLoc, ID);
      return;
    }

    const auto Replacement = replaceExpression(Casts, CastExpression, Context);
    const auto CastRange = getRangeForExpression(CastExpression, Context);
    const auto FixIt =
        clang::FixItHint::CreateReplacement(CastRange, Replacement);

    auto DiagLevel =
        (Casts[0] == CXXCast::CC_ReinterpretCast && ReinterpretError)
            ? DiagnosticsEngine::Error
            : DiagnosticsEngine::Warning;

    unsigned ID = DiagEngine.getCustomDiagID(DiagLevel, DiagMessage);

    const DiagnosticBuilder &Builder = DiagEngine.Report(StartingLoc, ID);
    Builder << Replacement << FixIt;
  }

  virtual void run(const MatchFinder::MatchResult &Result) {
    ASTContext *Context = Result.Context;
    const CStyleCastExpr *CastExpression =
        Result.Nodes.getNodeAs<CStyleCastExpr>("cast");

    if (!CastExpression)
      return;

    // Retrieving top level cast type
    const CXXCast CXXCastType = getCastKindFromCStyleCast(CastExpression);
    std::vector<CXXCast> CastOrder;
    CastOrder.push_back(CXXCastType);

    // Retrieving const cast requirements if the cast type is proper, otherwise
    // encountering a dependent type requires more context and requireConstCast
    // may yield undefined behavior.
    if ((CXXCastType == CXXCast::CC_NoOpCast ||
         CXXCastType == CXXCast::CC_StaticCast ||
         CXXCastType == CXXCast::CC_ReinterpretCast) &&
        requireConstCast(CastExpression, Context, Pedantic)) {
      CastOrder.push_back(CXXCast::CC_ConstCast);
    }

    reportDiagnostic(CastOrder, CastExpression, Context);

    if (Modify) {
      if (!Rewriter->WriteFixedFiles()) {
        llvm::errs() << "Writing the FixItHint was unsuccessful.\n";
      }
    }
  }
};

class Consumer : public clang::ASTConsumer {
public:
  Consumer()
      : Handler(cli::ModifyOption, cli::SuffixOption, cli::PedanticOption,
                cli::ReinterpretError) {
    using namespace clang::ast_matchers;
    StatementMatcher CStyleCastMatcher = cStyleCastExpr().bind("cast");
    MatchFinder.addMatcher(CStyleCastMatcher, &Handler);
  }

  void HandleTranslationUnit(clang::ASTContext &Context) override {
    MatchFinder.matchAST(Context);
  }

private:
  Replacer Handler;
  clang::ast_matchers::MatchFinder MatchFinder;
};

class Action : public clang::ASTFrontendAction {
public:
  using ASTConsumerPointer = std::unique_ptr<clang::ASTConsumer>;

  Action() = default;

  ASTConsumerPointer CreateASTConsumer(clang::CompilerInstance &Compiler,
                                       llvm::StringRef Filename) override {
    return std::make_unique<Consumer>();
  }
};

struct ToolFactory : public clang::tooling::FrontendActionFactory {
  std::unique_ptr<clang::FrontendAction> create() override {
    std::unique_ptr<clang::FrontendAction> Ptr;
    Ptr.reset(new Action());
    return Ptr;
  }
};

} // namespace cppcast

} // namespace clang

int main(int argc, const char **argv) {
  tooling::CommonOptionsParser op(argc, argv, cli::ClangCastCategory);
  tooling::ClangTool Tool(op.getCompilations(), op.getSourcePathList());
  int ExitCode = Tool.run(new clang::cppcast::ToolFactory());
  return ExitCode;
}
