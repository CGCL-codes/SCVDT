(function f() {
    do {
        return 23;
    } while (false);
    with (0) {
        try {
            return 42;
        } finally {
        }
    }
}());
