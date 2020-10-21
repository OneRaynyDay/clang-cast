//===--- Consumer.h - clang-cast --------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
///
/// \file
/// This file contains the ASTConsumer class used in FrontendAction.
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANG_CAST_CONSUMER_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANG_CAST_CONSUMER_H

#include "Matcher.h"
#include "clang/AST/ASTConsumer.h"

namespace clang {
namespace cppcast {

class Consumer : public clang::ASTConsumer {
public:
  template <typename... Args>
  Consumer(Args &&... AS) : Handler(std::forward<Args>(AS)...) {
    using namespace clang::ast_matchers;
    // TODO: Make this a constant instead of hardcode "cast"
    StatementMatcher CStyleCastMatcher = cStyleCastExpr().bind("cast");
    MatchFinder.addMatcher(CStyleCastMatcher, &Handler);
  }

  void HandleTranslationUnit(clang::ASTContext &Context) override {
    MatchFinder.matchAST(Context);
  }

private:
  Matcher Handler;
  clang::ast_matchers::MatchFinder MatchFinder;
};

} // namespace cppcast
} // namespace clang

#endif
