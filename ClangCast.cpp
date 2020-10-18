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
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Error.h"
#include <map>

using namespace clang::ast_matchers;
using namespace clang;
using namespace cppcast;
using namespace llvm;

namespace clang {

namespace cli {

// We can't make these enum-classes if we want to use the llvm CommandLine.h
// macros to define lists
// we also make these masks so we can construct a simple bitmask for testing
// inclusion.
enum ErrorOpts {
  err_static = 0b1,
  err_reinterpret = 0b10,
  err_const = 0b100,
  err_cstyle = 0b1000,
  err_noop = 0b10000,
  err_all = 0b11111,
};

// NOTE: There is no "fix_cstyle" because we can't fix them.
enum FixOpts {
  fix_static = 0b1,
  fix_reinterpret = 0b10,
  fix_const = 0b100,
  fix_noop = 0b1000,
  fix_all = 0b1111,
};

unsigned CXXCastToErrMask(const CXXCast &CXXCastKind) {
  switch (CXXCastKind) {
  case CXXCast::CC_StaticCast:
    return err_static;
  case CXXCast::CC_ReinterpretCast:
    return err_reinterpret;
  case CXXCast::CC_ConstCast:
    return err_const;
  case CXXCast::CC_CStyleCast:
    return err_cstyle;
  case CXXCast::CC_NoOpCast:
    return err_noop;
  default:
    // no such mask is supplied
    return 0;
  }
}

// We could be clever and merge with the above function,
// but it's better to write safer code.
unsigned CXXCastToFixMask(const CXXCast &CXXCastKind) {
  switch (CXXCastKind) {
  case CXXCast::CC_StaticCast:
    return fix_static;
  case CXXCast::CC_ReinterpretCast:
    return fix_reinterpret;
  case CXXCast::CC_ConstCast:
    return fix_const;
  case CXXCast::CC_NoOpCast:
    return fix_noop;
  default:
    // no such mask is supplied
    return 0;
  }
}

static llvm::cl::OptionCategory ClangCastCategory("clang-cast options");

llvm::cl::extrahelp ClangCastCategoryHelp(R"(
clang-cast finds C style casts and attempts to convert them into C++ casts.
C++ casts are preferred since they are safer and more explicit than C style casts.

For example:

double* p = nullptr;
(int*) p;

... is converted into:

double* p = nullptr;
reinterpret_cast<int*>(p);

When running clang-cast on a compilation unit, the tool will emit useful diagnostics.
The tool can be used to modify a file in-place or into a new file with an added suffix.
Clang-cast will not modify system headers, nor any file with the suffix .c (C files).
)");

llvm::cl::opt<bool>
    PedanticOption("pedantic", llvm::cl::init(false),
                   llvm::cl::desc("If true, clang-cast will not assume "
                                  "qualification conversion extensions \n"
                                  "(this will lead to more false negatives) "
                                  "that clang adds. This is for projects \n"
                                  "which use the -pedantic or -pedantic-errors "
                                  "flag and have extensions turned off."),
                   llvm::cl::cat(ClangCastCategory));

llvm::cl::list<ErrorOpts> ErrorOptList(
    llvm::cl::desc("For each flag set, clang-cast will issue an "
                   "error for any C style casts that are converted "
                   "to the following types."),
    llvm::cl::values(
        clEnumValN(err_static, "err-static", "Error on static_cast"),
        clEnumValN(err_reinterpret, "err-reinterpret",
                   "Error on reinterpret_cast"),
        clEnumValN(err_const, "err-const", "Error on const_cast"),
        clEnumValN(err_cstyle, "err-cstyle",
                   "Error on non-convertible C style casts"),
        clEnumValN(err_noop, "err-noop", "Error on unnecessary C style casts"),
        clEnumValN(err_all, "err-all", "Error for all of the above")),
    llvm::cl::cat(ClangCastCategory));

llvm::cl::list<FixOpts> FixOptList(
    llvm::cl::desc("For each flag set, clang-cast will apply a fix for the C "
                   "style casts that can be converted to the following types. "
                   "Note that for casts that require two consecutive C++ "
                   "casts, both flags need to be specified (or --fix-all)."),
    llvm::cl::values(
        clEnumValN(fix_static, "fix-static", "Apply fixes to static_cast"),
        clEnumValN(fix_reinterpret, "fix-reinterpret",
                   "Apply fixes to reinterpret_cast"),
        clEnumValN(fix_const, "fix-const", "Apply fixes to const_cast"),
        clEnumValN(fix_noop, "fix-noop", "Apply fixes to no-op cast"),
        clEnumValN(fix_all, "fix-all", "Apply fixes for all of the above")),
    llvm::cl::cat(ClangCastCategory));

llvm::cl::opt<std::string>
    SuffixOption("suffix",
                 llvm::cl::desc("If suffix is set, changes of "
                                "a file F will be written to F+suffix."),
                 llvm::cl::cat(ClangCastCategory));

llvm::cl::opt<bool>
    DontExpandIncludes("no-includes", llvm::cl::init(false),
                       llvm::cl::desc("Don't modify any include files."),
                       llvm::cl::cat(ClangCastCategory));

llvm::cl::opt<bool>
    PublishSummary("summary", llvm::cl::init(false),
                   llvm::cl::desc("If true, clang-cast gives a small summary "
                                  "of the statistics of casts through "
                                  "the entire translation unit."),
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
      InPlace = true;
    } else {
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
  // We switch between these two depending on whether a FixIt
  // should actually be applied.
  using RewriterPtr = std::unique_ptr<clang::FixItRewriter>;
  RewriterPtr Rewriter;
  DiagnosticConsumer* Printer;
  rewriter::FixItRewriterOptions FixItOptions;

  bool Pedantic;
  bool PublishSummary;
  unsigned TotalCasts;
  bool DontExpandIncludes;
  unsigned ErrMask;
  unsigned FixMask;
  std::map<CXXCast, unsigned> Statistics;
  std::set<StringRef> ChangedFiles;

  // The Context needs to be modifiable because we need to
  // call non-const functions on SourceManager
  void setRewriter(clang::ASTContext *Context) {
    if (!Rewriter) {
      Rewriter = std::make_unique<clang::FixItRewriter>(
          Context->getDiagnostics(), Context->getSourceManager(),
          Context->getLangOpts(), &FixItOptions);
    }
    // If we modify, we don't want the diagnostics engine to own it.
    // If we don't modify, we want the diagnostics engine to own the original client.
    Context->getDiagnostics().setClient(Rewriter.get(), false);
  }

public:
  // We can't initialize the RewriterPtr until we get an ASTContext.
  Replacer(const std::string &Filename, const bool Pedantic,
           bool PublishSummary, bool DontExpandIncludes,
           std::vector<cli::ErrorOpts> ErrorOptions,
           std::vector<cli::FixOpts> FixOptions)
      : Rewriter(nullptr), FixItOptions(Filename), Pedantic(Pedantic),
        PublishSummary(PublishSummary), TotalCasts(0),
        DontExpandIncludes(DontExpandIncludes),
        /* modify in ctr */ ErrMask(0),
        /* modify in ctr */ FixMask(0) {
    for (unsigned i = 0; i != ErrorOptions.size(); i++) {
      ErrMask |= ErrorOptions[i];
    }
    for (unsigned i = 0; i != FixOptions.size(); i++) {
      FixMask |= FixOptions[i];
    }
  }

  // TODO: Is this okay to do?
  virtual ~Replacer() {
    if (PublishSummary) {
      for (auto const &[CXXCastKind, Freq] : Statistics) {
        llvm::errs() << "The type " << cppCastToString(CXXCastKind)
                     << " has been issued " << Freq
                     << " times throughout the translation unit.\n";
      }
      if (FixMask) {
        llvm::errs() << "The following files were modified:\n";
        for (auto const &File : ChangedFiles) {
          llvm::errs() << "\t - " << File << "\n";
        }
      }
      llvm::errs() << "In total, there are " << TotalCasts
                   << " C style casts in the translation unit. Multiple C++ "
                      "casts may be used to convert a single C style cast.\n";
    }
  }

  CharSourceRange getRangeForExpression(const Expr *Expression,
                                        const ASTContext &Context) {
    // Also expand on macros:
    auto &Manager = Context.getSourceManager();

    const ParenExpr *ParenExpression;
    while ((ParenExpression = dyn_cast<ParenExpr>(Expression))) {
      Expression = ParenExpression->getSubExpr();
    }
    auto ExprStart = Manager.getSpellingLoc(Expression->getBeginLoc());
    auto ExprEnd = Lexer::getLocForEndOfToken(
        Manager.getSpellingLoc(Expression->getEndLoc()), 0,
        Context.getSourceManager(), Context.getLangOpts());

    return CharSourceRange::getCharRange(SourceRange{ExprStart, ExprEnd});
  }

  /// There are a few cases for the replacement string:
  /// 1. No-op cast (remove the cast)
  /// 2. Only const cast
  /// 3. Static cast
  /// 4. Static cast + const cast
  /// 5. Reinterpret cast
  /// 6. Reinterpret cast + const cast
  /// 7. C style cast (keep the cast as is)
  std::string replaceExpression(const CStyleCastOperation &Op,
                                CXXCast CXXCastKind, bool ConstCastRequired) {
    QualType CastType = Op.getCastType();
    const Expr &SubExpr = Op.getSubExprAsWritten();
    const ASTContext &Context = Op.getContext();
    const auto &LangOpts = Context.getLangOpts();

    std::string SubExpressionStr =
        Lexer::getSourceText(getRangeForExpression(&SubExpr, Context),
                             Context.getSourceManager(), Context.getLangOpts())
            .str();

    switch (CXXCastKind) {
    case CXXCast::CC_NoOpCast: {
      // Case 1
      if (!ConstCastRequired) {
        // our replacement is simply the subexpression (no cast needed)
        return SubExpressionStr;
      }
      // Case 2
      else {
        // const<>
        return cppCastToString(CXXCast::CC_ConstCast) + "<" +
               CastType.getAsString(LangOpts) + ">(" + SubExpressionStr + ")";
      }
    }
    case CXXCast::CC_StaticCast:
    case CXXCast::CC_ReinterpretCast: {
      std::string CastTypeStr = cppCastToString(CXXCastKind);
      // Case 3,5
      if (!ConstCastRequired) {
        return CastTypeStr + "<" + CastType.getAsString(LangOpts) + ">(" +
               SubExpressionStr + ")";
      }
      // Case 4,6
      else {
        QualType IntermediateType = Op.changeQualifiers();
        return cppCastToString(CXXCast::CC_ConstCast) + "<" +
               CastType.getAsString(LangOpts) + ">(" + CastTypeStr + "<" +
               IntermediateType.getAsString(LangOpts) + ">(" +
               SubExpressionStr + "))";
      }
    }
    default: {
      llvm_unreachable(
          "The type of cast passed in cannot produce a replacement.");
      return {};
    }
    }
  }

  /// Given an ordered list of casts, use the ASTContext to report necessary
  /// changes to the cast expression.
  bool reportDiagnostic(ASTContext *ModifiableContext,
                        const CStyleCastOperation &Op) {
    const auto &Context = Op.getContext();
    auto &DiagEngine = Context.getDiagnostics();

    // Set diagnostics to warning by default, and to INFO for edge cases.
    const auto &CastExpr = Op.getCStyleCastExpr();
    auto StartingLoc = CastExpr.getExprLoc();
    const auto& ExprRange = getRangeForExpression(&CastExpr, Context);

    CXXCast CXXCastKind = Op.getCastKindFromCStyleCast();

    // Invalid cast or dynamic (this should never happen, and would be a bug)
    if (CXXCastKind == CXXCast::CC_InvalidCast ||
        CXXCastKind == CXXCast::CC_DynamicCast) {
      reportWithLoc(
          DiagEngine, DiagnosticsEngine::Error,
          "clang-casts has encountered an error. Currently does not support "
          "the following cast",
          StartingLoc, ExprRange);
      return false;
    }
    if (CXXCastKind == CXXCast::CC_CStyleCast) {
      reportWithLoc(DiagEngine,
                    cli::CXXCastToErrMask(CXXCastKind) & ErrMask
                        ? DiagnosticsEngine::Error
                        : DiagnosticsEngine::Remark,
                    "C style cast cannot be converted "
                    "into a C++ style cast",
                    StartingLoc, ExprRange);
      return false;
    }

    bool ConstCastRequired = Op.requireConstCast();
    const auto Replacement =
        replaceExpression(Op, CXXCastKind, ConstCastRequired);
    const auto CastRange = getRangeForExpression(&CastExpr, Context);

    // Constructing bitmask and adding statistics
    unsigned CurErrMask = cli::CXXCastToErrMask(CXXCastKind);
    unsigned CurFixMask = cli::CXXCastToFixMask(CXXCastKind);
    if (ConstCastRequired) {
      CurErrMask |= cli::CXXCastToErrMask(CXXCast::CC_ConstCast);
      CurFixMask |= cli::CXXCastToFixMask(CXXCast::CC_ConstCast);
      Statistics[CXXCast::CC_ConstCast]++;
    }
    Statistics[CXXCastKind]++;


    // TODO: the location pointer looks funky when the cast expression is
    // in a macro.
    auto &Manager = Context.getSourceManager();
    auto Level = (CurErrMask & ErrMask) ? DiagnosticsEngine::Error
                                        : DiagnosticsEngine::Warning;
    if (Manager.isMacroBodyExpansion(StartingLoc)) {
      reportWithLoc(DiagEngine, Level,
                    "C style cast can be replaced by '%0' "
                    "(won't be fixed in macro)",
                    StartingLoc, Replacement, ExprRange);
    } else {
      // Set the diagnostic consumer accordingly.
      bool Modify = (CurFixMask & FixMask) == CurFixMask;
      setRewriter(ModifiableContext);

      if(Modify) {
        const auto FixIt =
            clang::FixItHint::CreateReplacement(CastRange, Replacement);
        reportWithLoc(DiagEngine, Level, "C style cast can be replaced by '%0'",
                      StartingLoc, Replacement, FixIt);
      }
      else {
        reportWithLoc(DiagEngine, Level, "C style cast can be replaced by '%0'",
                      StartingLoc, Replacement, ExprRange);
      }
      return Modify;
    }
    return false;
  }

  virtual void run(const MatchFinder::MatchResult &Result) {
    ASTContext *Context = Result.Context;
    auto &DiagEngine = Context->getDiagnostics();

    const CStyleCastExpr *CastExpression =
        Result.Nodes.getNodeAs<CStyleCastExpr>("cast");
    assert(CastExpression);

    const auto &Manager = Context->getSourceManager();
    const auto Loc = CastExpression->getBeginLoc();
    // We skip external headers
    if (Manager.isInExternCSystemHeader(Loc) || Manager.isInSystemHeader(Loc)) {
      return;
    }
    if (!Manager.isInMainFile(Loc) && DontExpandIncludes) {
      return;
    }

    TotalCasts++;

    CStyleCastOperation Op(*CastExpression, *Context, Pedantic);

    // If anything is to be modified
    if (reportDiagnostic(Context, Op)) {
      // Macro expanded Loc's aren't a part of a FileEntry.
      if (Manager.isMacroBodyExpansion(Loc))
        return;

      // Checking for symlinks
      const FileEntry *Entry =
          Manager.getFileEntryForID(Manager.getFileID(Loc));
      assert(Entry);
      const auto RealFilename = Entry->tryGetRealPathName();
      const auto Filename = Entry->getName();
      ChangedFiles.insert(Filename);

      if (RealFilename != Filename) {
        report(DiagEngine, DiagnosticsEngine::Warning,
               "The symlink at %0 pointing to %1 is changed to a file during "
               "modifications.",
               Filename, RealFilename);
      }

      if (Rewriter->WriteFixedFiles()) {
        report(DiagEngine, DiagnosticsEngine::Error,
               "Writing the FixItHint was unsuccessful.");
      }
    }
  }
};

class Consumer : public clang::ASTConsumer {
public:
  Consumer(StringRef Filename)
      : Handler(cli::SuffixOption, cli::PedanticOption,
                cli::PublishSummary, cli::DontExpandIncludes, cli::ErrorOptList,
                cli::FixOptList) {
    // For those who use a hybrid of C and C++ files, we don't want to modify
    // any source that may potentially involve C.
    // TODO WARNING: Header files shared between C and C++ files cannot be
    // determined easily by passing in AST's of translation units individually.
    if (Filename.endswith(".c")) {
      llvm::errs() << "File " << Filename
                   << " is detected to be a C file. Skipping.\n";
      return;
    }

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

  ASTConsumerPointer CreateASTConsumer(CompilerInstance &Compiler,
                                       StringRef Filename) override {
    return std::make_unique<Consumer>(Filename);
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
  const auto &CompDatabase = op.getCompilations();
  const auto Files = CompDatabase.getAllFiles();

  //  llvm::errs() << "reading in files: \n";
  //  for (auto& s : Files) {
  //    llvm::errs() << s << ", ";
  //  }
  //  llvm::errs() << "\n";

  tooling::ClangTool Tool(op.getCompilations(), op.getSourcePathList());
  int ExitCode = Tool.run(new clang::cppcast::ToolFactory());
  return ExitCode;
}
