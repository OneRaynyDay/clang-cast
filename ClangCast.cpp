#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Tooling/Tooling.h"
#include "clang/Tooling/CommonOptionsParser.h"

using namespace clang;

static llvm::cl::OptionCategory ClangCastCategory("clang-cast options");

class FindCStyleCastVisitor
        : public RecursiveASTVisitor<FindCStyleCastVisitor> {
public:
    explicit FindCStyleCastVisitor(ASTContext *Context)
            : Context(Context) {}

    bool VisitCStyleCastExpr(CStyleCastExpr *CastExpression) {
        QualType CastType = CastExpression->getTypeAsWritten();
        QualType CanonicalCastType = CastType.getCanonicalType();
        Expr* SubExpression = CastExpression->getSubExprAsWritten();
        SubExpression->dump();
        if (!SubExpression) {
            llvm::outs() << "The expression is invalid.\n";
        }
        QualType SubExpressionType = SubExpression->getType();
        QualType SubExpressionCanonicalType = SubExpressionType.getCanonicalType();

        auto& SourceManager = Context->getSourceManager();
        SourceLocation Loc = SourceManager.getSpellingLoc(CastExpression->getBeginLoc());
        FullSourceLoc DiagnosticLocation = FullSourceLoc(Loc, SourceManager);
        if (Loc.isInvalid()) {
            llvm::outs() << "Loc invalid" << "\n";
            return false;
        }
        const FileEntry *FileEntry =
                SourceManager.getFileEntryForID(SourceManager.getFileID(Loc));
        if (!FileEntry) {
            llvm::outs() << "File entry invalid" << "\n";
            return false;
        }
        llvm::outs() << "Found c-style cast expression in file " <<
            FileEntry->getName() << " on line " << DiagnosticLocation.getSpellingLineNumber() <<
            " casting to type " << CanonicalCastType.getAsString() << " from type " <<
            SubExpressionCanonicalType.getAsString() << ".\n";
        return true;
    }

private:
    ASTContext *Context;
};

class FindCStyleCastConsumer : public clang::ASTConsumer {
public:
    explicit FindCStyleCastConsumer(ASTContext *Context)
            : Visitor(Context) {}

    virtual void HandleTranslationUnit(clang::ASTContext &Context) {
        Visitor.TraverseDecl(Context.getTranslationUnitDecl());
    }
private:
    FindCStyleCastVisitor Visitor;
};

class FindCStyleCastAction : public clang::ASTFrontendAction {
public:
    virtual std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(
            clang::CompilerInstance &Compiler, llvm::StringRef InFile) {
        return std::unique_ptr<clang::ASTConsumer>(
                new FindCStyleCastConsumer(&Compiler.getASTContext()));
    }
};

int main(int argc, const char **argv) {
    // parse the command-line args passed to your code
    tooling::CommonOptionsParser op(argc, argv, ClangCastCategory);
    // create a new Clang Tool instance (a LibTooling environment)
    tooling::ClangTool Tool(op.getCompilations(), op.getSourcePathList());

    // run the Clang Tool, creating a new FrontendAction (explained below)
    std::unique_ptr<tooling::FrontendActionFactory> action_ptr =
        tooling::newFrontendActionFactory<FindCStyleCastAction>();
    int result = Tool.run(action_ptr.get());
}
