error() {
    echo "$*" >&2
    exit 1
}

clang-format \
    -i \
    --style="{BasedOnStyle: LLVM, IndentWidth: 4, ColumnLimit: 200, AllowShortEnumsOnASingleLine: false, AllowShortFunctionsOnASingleLine: None, IndentCaseLabels: true, InsertBraces: true, FixNamespaceComments: false}" \
    src/*.ccm \
    tests/*.ccm || error "could not format sources"
