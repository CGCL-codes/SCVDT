function f0() {
    for (var v0 = 0; v0 < arguments.length; v0++) {
        if (arguments[v0] != v0 + 1) {
            print('FAIL');
        }
    }
    print('PASS');
}
