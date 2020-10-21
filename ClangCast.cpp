//===--- ClangCast.cpp - clang-cast -----------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
///
/// \file
/// This file is the main driver for the clang-cast tool.
///
//===----------------------------------------------------------------------===//

#include "Consumer.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Error.h"

using namespace clang::ast_matchers;
using namespace clang;
using namespace cppcast;
using namespace llvm;

namespace clang {
namespace cli {

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
        clEnumValN(EO_StaticCast, "err-static", "Error on static_cast"),
        clEnumValN(EO_ReinterpretCast, "err-reinterpret",
                   "Error on reinterpret_cast"),
        clEnumValN(EO_ConstCast, "err-const", "Error on const_cast"),
        clEnumValN(EO_CStyleCast, "err-cstyle",
                   "Error on non-convertible C style casts"),
        clEnumValN(EO_NoOpCast, "err-noop",
                   "Error on unnecessary C style casts"),
        clEnumValN(EO_All, "err-all", "Error for all of the above")),
    llvm::cl::cat(ClangCastCategory));

llvm::cl::list<FixOpts> FixOptList(
    llvm::cl::desc("For each flag set, clang-cast will apply a fix for the C "
                   "style casts that can be converted to the following types. "
                   "Note that for casts that require two consecutive C++ "
                   "casts, both flags need to be specified (or --fix-all)."),
    llvm::cl::values(
        clEnumValN(FO_StaticCast, "fix-static", "Apply fixes to static_cast"),
        clEnumValN(FO_ReinterpretCast, "fix-reinterpret",
                   "Apply fixes to reinterpret_cast"),
        clEnumValN(FO_ConstCast, "fix-const", "Apply fixes to const_cast"),
        clEnumValN(FO_NoOpCast, "fix-noop", "Apply fixes to no-op cast"),
        clEnumValN(FO_All, "fix-all", "Apply fixes for all of the above")),
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

namespace cppcast {

class Action : public clang::ASTFrontendAction {
public:
  using ASTConsumerPointer = std::unique_ptr<clang::ASTConsumer>;
  Action() = default;
  ASTConsumerPointer CreateASTConsumer(CompilerInstance &Compiler,
                                       StringRef Filename) override {
    if (!Compiler.getLangOpts().CPlusPlus) {
      llvm::report_fatal_error("clang-cast is only supported for C++.");
    }
    return std::make_unique<Consumer>(
        cli::SuffixOption, cli::PedanticOption, cli::PublishSummary,
        cli::DontExpandIncludes, cli::ErrorOptList, cli::FixOptList);
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

int main(int Argc, const char **Argv) {
  tooling::CommonOptionsParser Op(Argc, Argv, cli::ClangCastCategory);
  tooling::ClangTool Tool(Op.getCompilations(), Op.getSourcePathList());
  int ExitCode = Tool.run(new clang::cppcast::ToolFactory());
  return ExitCode;
}
