//===--- Matcher.h - clang-cast ---------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANG_CAST_MATCHER_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANG_CAST_MATCHER_H

#include "Cast.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"

using namespace clang::ast_matchers;

namespace clang {
namespace cppcast {

/// Given a cast type enum of the form CXXCasts::CC_{type}, return the
/// string representation of that respective type.
std::string cppCastToString(const CXXCast &Cast) {
  switch (Cast) {
  case CXXCast::CC_ConstCast:
    return "const_cast";
  case CXXCast::CC_StaticCast:
    return "static_cast";
  case CXXCast::CC_ReinterpretCast:
    return "reinterpret_cast";
    // Below are only used for summary diagnostics
  case CXXCast::CC_CStyleCast:
    return "C style cast";
  case CXXCast::CC_NoOpCast:
    return "No-op cast";
  default:
    llvm_unreachable("The cast should never occur.");
    return {};
  }
}

class Matcher : public MatchFinder::MatchCallback {
  // We switch between these two depending on whether a FixIt
  // should actually be applied.
  using RewriterPtr = std::unique_ptr<clang::FixItRewriter>;
  RewriterPtr Rewriter;
  DiagnosticConsumer *Printer;
  rewriter::FixItRewriterOptions FixItOptions;

  bool Pedantic;
  bool PublishSummary;
  unsigned TotalCasts;
  bool DontExpandIncludes;
  unsigned ErrMask;
  unsigned FixMask;
  std::map<CXXCast, unsigned> Statistics;
  std::set<StringRef> ChangedFiles;

public:
  // We can't initialize the RewriterPtr until we get an ASTContext.
  Matcher(const std::string &Filename, const bool Pedantic, bool PublishSummary,
          bool DontExpandIncludes, std::vector<cli::ErrorOpts> ErrorOptions,
          std::vector<cli::FixOpts> FixOptions);

  virtual ~Matcher();

  CharSourceRange getRangeForExpression(const Expr *Expression,
                                        const ASTContext &Context);

  /// There are a few cases for the replacement string:
  /// 1. No-op cast (remove the cast)
  /// 2. Only const cast
  /// 3. Static cast
  /// 4. Static cast + const cast
  /// 5. Reinterpret cast
  /// 6. Reinterpret cast + const cast
  /// 7. C style cast (keep the cast as is)
  std::string replaceExpression(const CStyleCastOperation &Op,
                                CXXCast CXXCastKind, bool ConstCastRequired);

  /// Given an ordered list of casts, use the ASTContext to report necessary
  /// changes to the cast expression.
  bool reportDiagnostic(ASTContext *ModifiableContext,
                        const CStyleCastOperation &Op);

  virtual void run(const MatchFinder::MatchResult &Result);

  // The Context needs to be modifiable because we need to
  // call non-const functions on SourceManager
  void setRewriter(clang::ASTContext *Context);

  void checkForSymlinks(const SourceManager &Manager,
                        const SourceLocation &Loc,
                        DiagnosticsEngine& DiagEngine);
};

// We can't initialize the RewriterPtr until we get an ASTContext.
Matcher::Matcher(const std::string &Filename, const bool Pedantic,
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
Matcher::~Matcher() {
  if (PublishSummary) {
    for (auto const &[CXXCastKind, Freq] : Statistics) {
      if (!Freq) continue;
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

CharSourceRange Matcher::getRangeForExpression(const Expr *Expression,
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

std::string Matcher::replaceExpression(const CStyleCastOperation &Op,
                                       CXXCast CXXCastKind,
                                       bool ConstCastRequired) {
  assert(CXXCastKind != CXXCast::CC_ConstCast);
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

bool Matcher::reportDiagnostic(ASTContext *ModifiableContext,
                               const CStyleCastOperation &Op) {
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
  auto &Manager = Context.getSourceManager();
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
  if (Modify) {
    setRewriter(ModifiableContext);
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

void Matcher::run(const MatchFinder::MatchResult &Result) {
  ASTContext *Context = Result.Context;
  auto &DiagEngine = Context->getDiagnostics();

  const CStyleCastExpr *CastExpression =
      Result.Nodes.getNodeAs<CStyleCastExpr>("cast");
  assert(CastExpression);

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
      report(DiagEngine, DiagnosticsEngine::Error,
             "Writing the FixItHint was unsuccessful.");
    }
  }
}

void Matcher::checkForSymlinks(const SourceManager &Manager,
                               const SourceLocation &Loc,
                               DiagnosticsEngine& DiagEngine) {
  const FileEntry *Entry = Manager.getFileEntryForID(Manager.getFileID(Loc));
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
}

void Matcher::setRewriter(clang::ASTContext *Context) {
  if (!Rewriter) {
    Rewriter = std::make_unique<clang::FixItRewriter>(
        Context->getDiagnostics(), Context->getSourceManager(),
        Context->getLangOpts(), &FixItOptions);
  }
  // If we modify, we don't want the diagnostics engine to own it.
  // If we don't modify, we want the diagnostics engine to own the original
  // client.
  Context->getDiagnostics().setClient(Rewriter.get(), false);
}

} // namespace cppcast
} // namespace clang

#endif
