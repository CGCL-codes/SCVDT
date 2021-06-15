function f0() {
    return function (a, b = a) {
        return b === 5;
    }(5);
}
if (!f0())
    throw new Error('Test failed');
