function f0(a, b) {
    function f1() {
        return b;
    }
    return arguments[0] + arguments[1] + f1();
}
f0(1, 2);
