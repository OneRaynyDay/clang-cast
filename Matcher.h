//===--- Matcher.h - clang-cast ---------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
///
/// \file
/// This file contains the ASTMatcher responsible for most of the diagnostics.
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANG_CAST_MATCHER_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANG_CAST_MATCHER_H

#include "Cast.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/Frontend/TextDiagnosticPrinter.h"
#include "clang/Lex/Lexer.h"

using namespace clang::ast_matchers;

namespace clang {
namespace cppcast {

/// Matcher is responsible for creating a CStyleCastOperation to perform
/// semantic analysis on the CStyleCastExpr and decide what potential
/// replacements are suitable for the expression.
///
/// The matcher decides whether to emit a warning or error or to additionally
/// perform a fix based off of the bit masks created by enums in CastOptions.h.
///
/// The Matcher emits summaries if the flags are set, containing some summary
/// statistics.
class Matcher : public MatchFinder::MatchCallback {
  using RewriterPtr = std::unique_ptr<clang::FixItRewriter>;
  /// The FixItRewriter is actually a composable DiagnosticConsumer which
  /// contains the original DiagnosticConsumer client, which is a
  /// TextDiagnosticPrinter.
  ///
  /// If we have Rewriter set as the client, FixIt's will be fixed on the file.
  /// We want to have granular control over which FixIt's to fix, so we do some
  /// light pointer manipulation with the DiagnosticEngine in setClient to
  /// switch back and forth between the TextDiagnosticPrinter and FixItRewriter.
  RewriterPtr Rewriter;
  rewriter::FixItRewriterOptions FixItOptions;
  DiagnosticConsumer *OriginalWriter;

  /// Whether or not the Matcher should emit code compliant with -pedantic
  bool Pedantic;

  /// Whether or not the Matcher should publish a short blurb upon finishing
  /// visiting a translation unit.
  bool PublishSummary;

  /// Number of C style casts encountered
  unsigned TotalCasts;

  /// Whether or not to diagnose & fix includes (Local modifications only)
  bool DontExpandIncludes;

  /// Bitmask to determine which C style cast powers should give an error.
  /// For example, if we met a cast that requires static cast,
  /// and static cast is 0x1, and our mask is 0x10011, since the last bit is a
  /// 1, we will emit the error.
  unsigned ErrMask;

  /// Bitmask to determine which C style casts to fix.
  unsigned FixMask;

  /// Keeps count of how many C++ cast conversion types there are.
  /// Note that for casts that require multiple C++ casts, multiple types are
  /// updated here.
  std::map<CXXCast, unsigned> Statistics;

  /// List of files that were modified from the tool.
  std::set<StringRef> ChangedFiles;

public:
  /// Initializes a new Matcher.
  /// \param FilenameSuffix the suffix to add to the filenames
  /// \param Pedantic whether to check & emit code compliant with -pedantic
  /// \param PublishSummary whether to publish a small summary at the end
  /// \param DontExpandIncludes whether to parse cast exprs in headers
  /// \param ErrorOptions vector of bitmasks for error/warn types of cast
  /// \param FixOptions vector of bitmasks for fixing types of cast
  Matcher(const std::string &FilenameSuffix, const bool Pedantic,
          bool PublishSummary, bool DontExpandIncludes,
          std::vector<cli::ErrorOpts> ErrorOptions,
          std::vector<cli::FixOpts> FixOptions);

  virtual ~Matcher();

  /// There are a few cases for the replacement string:
  /// 1. No-op cast (remove the cast)
  /// 2. Only const cast
  /// 3. Static cast
  /// 4. Static cast + const cast
  /// 5. Reinterpret cast
  /// 6. Reinterpret cast + const cast
  /// 7. C style cast (keep the cast as is)
  /// \param Op operation wrapper
  /// \param CXXCastKind kind of non const cast applied to the expr (can be
  /// noop)
  /// \param ConstCastRequired whether const cast should be added to the
  /// existing casts
  /// \return A string to replace the C style cast operation char range with.
  std::string replaceExpression(const CStyleCastOperation &Op,
                                CXXCast CXXCastKind, bool ConstCastRequired);

  /// Given an ordered list of casts, use the ASTContext to report necessary
  /// changes to the cast expression. Also performs a FixIt on the source code
  /// if necessary.
  /// \param ModifiableContext the context ptr needs to be modifiable in
  /// order to set the diagnostic client
  /// \param Op the operation wrapper
  /// \return true if a FixIt has been applied
  bool reportDiagnostic(ASTContext *ModifiableContext,
                        const CStyleCastOperation &Op);

  virtual void run(const MatchFinder::MatchResult &Result) override;

private:
  /// Given an expression, gives the character source range of the expr.
  CharSourceRange getRangeForExpression(const Expr *Expression,
                                        const ASTContext &Context);

  /// Sets a client to the diagnostic engine depending on Modify:
  /// if Modify is true, then we change the diagnostics client to a
  /// FixItRewriter which takes and owns the TextDiagnosticPrinter from the
  /// engine.
  ///
  /// If modify is false, then we can't just destroy the FixItRewriter, as the
  /// previous FixIt's would be gone. If we already created a rewriter, then the
  /// TextDiagnosticPrinter is owned by it when previously it was owned by the
  /// engine. We do nothing if the rewriter hasn't been initialized, but this is
  /// extremely precarious as it's juggling ownership between two objects as the
  /// FixIt's are applied to subsets of the program.
  ///
  /// This function was born out of a necessity to work with FixItRewriter's
  /// composition-of-consumers design which makes ownership very complicated.
  void setClient(clang::ASTContext *Context, bool Modify);

  /// A quick diagnostic warning for when symlinks are being overwritten by an
  /// actual file.
  void checkForSymlinks(const SourceManager &Manager, const SourceLocation &Loc,
                        DiagnosticsEngine &DiagEngine);
};

// We can't initialize the RewriterPtr until we get an ASTContext.
inline Matcher::Matcher(const std::string &FilenameSuffix, const bool Pedantic,
                        bool PublishSummary, bool DontExpandIncludes,
                        std::vector<cli::ErrorOpts> ErrorOptions,
                        std::vector<cli::FixOpts> FixOptions)
    : Rewriter(nullptr), FixItOptions(FilenameSuffix), Pedantic(Pedantic),
      PublishSummary(PublishSummary), TotalCasts(0),
      DontExpandIncludes(DontExpandIncludes),
      /* modify in ctr */ ErrMask(0),
      /* modify in ctr */ FixMask(0) {
  for (auto &ErrorBit : ErrorOptions) {
    ErrMask |= ErrorBit;
  }
  for (auto &FixBit : FixOptions) {
    FixMask |= FixBit;
  }
}

// TODO: Is this okay to do?
inline Matcher::~Matcher() {
  if (PublishSummary) {
    for (auto const &Pair : Statistics) {
      const auto &CXXCastKind = Pair.first;
      const auto &Freq = Pair.second;
      if (!Freq)
        continue;
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

inline CharSourceRange
Matcher::getRangeForExpression(const Expr *Expression,
                               const ASTContext &Context) {
  // Also expand on macros:
  const auto &Manager = Context.getSourceManager();

  const ParenExpr *ParenExpression;
  while ((ParenExpression = dyn_cast<ParenExpr>(Expression))) {
    Expression = ParenExpression->getSubExpr();
  }
  auto ExprStart = Manager.getSpellingLoc(Expression->getBeginLoc());
  auto ExprEnd = Lexer::getLocForEndOfToken(
      Manager.getSpellingLoc(Expression->getEndLoc()), /*Offset=*/0,
      Context.getSourceManager(), Context.getLangOpts());

  return CharSourceRange::getCharRange(SourceRange{ExprStart, ExprEnd});
}

inline std::string Matcher::replaceExpression(const CStyleCastOperation &Op,
                                              CXXCast CXXCastKind,
                                              bool ConstCastRequired) {
  assert(CXXCastKind != CXXCast::CC_ConstCast &&
         "Const cast enum cannot be passed in as CXXCastKind");
  llvm::outs() << "CONST CAST REQUIRED? " << ConstCastRequired << "\n";
  QualType CastType = Op.getCastTypeAsWritten();
  const Expr &SubExpr = Op.getSubExprAsWritten();
  const ASTContext &Context = Op.getContext();
  const auto &LangOpts = Context.getLangOpts();

  std::string SubExpressionStr =
      Lexer::getSourceText(getRangeForExpression(&SubExpr, Context),
                           Context.getSourceManager(), Context.getLangOpts())
          .str();

  switch (CXXCastKind) {
  case CXXCast::CC_NoOpCast: {
    if (!ConstCastRequired) {
      // our replacement is simply the subexpression (no cast needed)
      return SubExpressionStr;
    }
    return cppCastToString(CXXCast::CC_ConstCast) + "<" +
           CastType.getAsString(LangOpts) + ">(" + SubExpressionStr + ")";
  }
  case CXXCast::CC_StaticCast:
  case CXXCast::CC_ReinterpretCast: {
    std::string CastTypeStr = cppCastToString(CXXCastKind);
    if (!ConstCastRequired) {
      return CastTypeStr + "<" + CastType.getAsString(LangOpts) + ">(" +
             SubExpressionStr + ")";
    }
    QualType IntermediateType = Op.changeQualifiers();
    return cppCastToString(CXXCast::CC_ConstCast) + "<" +
           CastType.getAsString(LangOpts) + ">(" + CastTypeStr + "<" +
           IntermediateType.getAsString(LangOpts) + ">(" + SubExpressionStr +
           "))";
  }
  default: {
    llvm_unreachable(
        "The type of cast passed in cannot produce a replacement.");
    return {};
  }
  }
}

inline bool Matcher::reportDiagnostic(ASTContext *ModifiableContext,
                                      const CStyleCastOperation &Op) {
  // No FixItRewriter should be set as consumer until we need to fix anything.
  setClient(ModifiableContext, /*Modify=*/false);
  const auto &Context = Op.getContext();
  auto &DiagEngine = Context.getDiagnostics();

  // Set diagnostics to warning by default, and to INFO for edge cases.
  const auto &CastExpr = Op.getCStyleCastExpr();
  auto StartingLoc = CastExpr.getExprLoc();
  const auto &ExprRange = getRangeForExpression(&CastExpr, Context);

  CXXCast CXXCastKind = Op.getCastKindFromCStyleCast();
  bool ConstCastRequired = Op.requireConstCast();
  unsigned CurMask = CXXCastKind | (ConstCastRequired * CXXCast::CC_ConstCast);

  // Invalid cast or dynamic (this should never happen, and would be a bug)
  if (CurMask & (CXXCast::CC_InvalidCast | CXXCast::CC_DynamicCast)) {
    reportWithLoc(
        DiagEngine, DiagnosticsEngine::Error,
        "clang-casts has encountered an error. Currently does not support "
        "the following cast",
        StartingLoc, ExprRange);
    return false;
  }
  if (CurMask & CXXCast::CC_CStyleCast) {
    reportWithLoc(DiagEngine,
                  (CurMask & ErrMask) ? DiagnosticsEngine::Error
                                      : DiagnosticsEngine::Remark,
                  "C style cast cannot be converted "
                  "into a C++ style cast",
                  StartingLoc, ExprRange);
    return false;
  }

  const auto Replacement =
      replaceExpression(Op, CXXCastKind, ConstCastRequired);
  const auto CastRange = getRangeForExpression(&CastExpr, Context);

  Statistics[CXXCast::CC_ConstCast] += ConstCastRequired;
  Statistics[CXXCastKind]++;

  // TODO: the location pointer looks funky when the cast expression is
  // in a macro.
  const auto &Manager = Context.getSourceManager();
  auto Level = (CurMask & ErrMask) ? DiagnosticsEngine::Error
                                   : DiagnosticsEngine::Warning;
  if (Manager.isMacroBodyExpansion(StartingLoc)) {
    reportWithLoc(DiagEngine, Level,
                  "C style cast can be replaced by '%0' "
                  "(won't be fixed in macro)",
                  StartingLoc, Replacement, ExprRange);
    return false;
  }

  // Set the diagnostic consumer accordingly.
  bool Modify = (CurMask & FixMask) == CurMask;

  // TODO: For clang-tidy, we want to put a logical branch here and not input
  // FixIt if we don't want to modify it. If we set the consumer as
  // FixItRewriter permanently, emitting an error (from --err-all, for example)
  // will cause FixIt to emit "FIXIT: detected an error it cannot fix", which
  // clutters up the real diagnostics.
  setClient(ModifiableContext, Modify);
  const auto FixIt =
      clang::FixItHint::CreateReplacement(CastRange, Replacement);
  reportWithLoc(DiagEngine, Level, "C style cast can be replaced by '%0'",
                StartingLoc, Replacement, FixIt);
  return Modify;
}

inline void Matcher::run(const MatchFinder::MatchResult &Result) {
  ASTContext *Context = Result.Context;
  auto &DiagEngine = Context->getDiagnostics();

  const CStyleCastExpr *CastExpression =
      Result.Nodes.getNodeAs<CStyleCastExpr>("cast");
  assert(CastExpression && "CastExpr cannot be null");

  const auto &Manager = Context->getSourceManager();
  const auto Loc = CastExpression->getBeginLoc();
  // We skip external headers
  if (Manager.isInExternCSystemHeader(Loc) || Manager.isInSystemHeader(Loc) ||
      (!Manager.isInMainFile(Loc) && DontExpandIncludes)) {
    return;
  }

  TotalCasts++;
  CStyleCastOperation Op(*CastExpression, *Context, Pedantic);

  // If anything is to be modified
  if (reportDiagnostic(Context, Op)) {
    checkForSymlinks(Manager, Loc, DiagEngine);
    if (Rewriter->WriteFixedFiles()) {
      llvm::errs() << "Writing the FixItHint was unsuccessful.\n";
    }
  }
}

inline void Matcher::checkForSymlinks(const SourceManager &Manager,
                                      const SourceLocation &Loc,
                                      DiagnosticsEngine &DiagEngine) {
  const FileEntry *Entry = Manager.getFileEntryForID(Manager.getFileID(Loc));
  assert(Entry && "File entry cannot be null");
  const auto RealFilename = Entry->tryGetRealPathName();
  const auto Filename = Entry->getName();
  ChangedFiles.insert(Filename);

  if (RealFilename != Filename) {
    report(DiagEngine, DiagnosticsEngine::Warning,
           "The symlink at %0 pointing to %1 is changed to a file during "
           "modifications.",
           Filename, RealFilename);
  }
}

inline void Matcher::setClient(clang::ASTContext *Context, bool Modify) {
  auto &DiagEngine = Context->getDiagnostics();
  if (Modify) {
    // First time initializing, means that engine owns TDP.
    if (!Rewriter) {
      OriginalWriter = DiagEngine.getClient();
      Rewriter = std::make_unique<clang::FixItRewriter>(
          DiagEngine, Context->getSourceManager(), Context->getLangOpts(),
          &FixItOptions);
    }

    // If we modify, we don't want the diagnostics engine to own it.
    // If we don't modify, we want the diagnostics engine to own the original
    // client.
    Context->getDiagnostics().setClient(Rewriter.get(),
                                        /*ShouldOwnClient=*/false);
  } else {
    // Rewriter not initialized, therefore do nothing, as the TDP client
    // is still there and owned by engine.
    if (!Rewriter)
      return;
    // Rewriter is initialized, therefore set TDP (not owned by engine,
    // owned by FIR)
    Context->getDiagnostics().setClient(OriginalWriter,
                                        /*ShouldOwnClient=*/false);
  }
}

} // namespace cppcast
} // namespace clang

#endif
