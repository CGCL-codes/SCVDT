function f0() {
    return function (a, ...b) {
    }.length === 1 && function (...c) {
    }.length === 0;
}
if (!f0())
    throw new Error('Test failed');
