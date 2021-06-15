function f0(...rest) {
    function f1() {
        return rest;
    }
    return f1;
}
assertEq(f0(1, 2, 3)().toString(), [
    1,
    2,
    3
].toString());
