error() {
    echo "$*" >&2
    exit 1
}

rm -rf build || error "could not remove build directory"
