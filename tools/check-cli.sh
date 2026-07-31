error() {
    echo "$*" >&2
    exit 1
}

contains_module() {
    for item in $2; do
        if [ "$item" = "$1" ]; then
            return 0
        fi
    done
    return 1
}

collect_tree() {
    if contains_module "$1" "$collected"; then
        return 0
    fi
    for dependency in $(sed -n 's/^\(export \)\{0,1\}import \([^;]*\);/\2/p' "src/$1.ccm"); do
        if [ -e "src/$dependency.ccm" ]; then
            collect_tree "$dependency" || return 1
        fi
    done
    collected="$collected $1"
    sources="$sources src/$1.ccm"
}

collected=""
sources=""

sh tools/build-cli.sh || error "could not build CLI"

collect_tree cli || error "could not collect CLI sources"

cppcheck \
    --enable=all \
    --error-exitcode=1 \
    --language=c++ \
    --std=c++20 \
    --suppress=constParameterCallback \
    --suppress=cstyleCast \
    --suppress=missingIncludeSystem \
    --suppress=normalCheckLevelMaxBranches \
    --suppress=uninitMemberVarNoCtor \
    --suppress=variableScope \
    $sources || error "cppcheck failed for CLI"
