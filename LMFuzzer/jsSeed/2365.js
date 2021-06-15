function f0() {
    return function (a = 1, b = 2) {
        return a === 1 && b === 3;
    }(undefined, 3);
}
if (!f0())
    throw new Error('Test failed');
