set(LLVM_LINK_COMPONENTS Support)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../../clang-cast
)

add_extra_unittest(ClangCastTests
    ClangCastTests.cpp
)

clang_target_link_libraries(ClangCastTests
    PRIVATE
    clangAST
    clangASTMatchers
    clangBasic
    clangFormat
    clangFrontend
    clangRewrite
    clangSerialization
    clangTooling
    clangToolingCore
)

target_link_libraries(ClangCastTests
    PRIVATE
    clangTooling
    clangBasic
    clangASTMatchers
)

