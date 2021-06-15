function f0(expected, actual, description) {
}
function f1() {
    f1(f1, 2474, 2480, f1);
}
try {
    f0('outer', f1(), 'Inner function statement should not have been called.');
} catch (e) {
}
