error() {
    echo "$*" >&2
    exit 1
}

build_module() {
    clang \
        -fprebuilt-module-path=build \
        -std=c++20 \
        -g \
        -Os \
        -x c++-module \
        -fmodule-output="build/$1.pcm" \
        -c "src/$1.ccm" \
        -o "build/$1.o" || return 1
}

contains_module() {
    for item in $2; do
        if [ "$item" = "$1" ]; then
            return 0
        fi
    done
    return 1
}

module_dependencies() {
    for dependency in $(sed -n 's/^\(export \)\{0,1\}import \([^;]*\);/\2/p' "src/$1.ccm"); do
        if [ -e "src/$dependency.ccm" ]; then
            echo "$dependency"
        fi
    done
}

build_tree() {
    if contains_module "$1" "$built"; then
        return 0
    fi
    for dependency in $(module_dependencies "$1"); do
        build_tree "$dependency" || return 1
    done
    build_module "$1" || return 1
    built="$built $1"
    objects="$objects build/$1.o"
    sources="$sources src/$1.ccm"
}

built=""
objects=""
sources=""

mkdir -p build || error "could not create build directory"

build_tree fconf || error "could not build library modules"

rm -f build/libfconf.a || error "could not replace library archive"
ar rcs build/libfconf.a $objects || error "could not archive library"

c-with-namespaces check \
    --suppress-external-warnings \
    $sources \
    -- \
    -std=c89 \
    -Wall \
    -Wextra \
    -pedantic || error "could not verify library as C with Namespaces"
