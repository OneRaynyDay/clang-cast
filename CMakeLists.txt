set(LLVM_LINK_COMPONENTS
        support)

add_clang_tool(clang-cast
  ClangCast.cpp
  )

target_link_libraries(clang-cast
  PRIVATE
  clangTooling
  clangBasic
  clangRewriteFrontend
  clangASTMatchers
  )
