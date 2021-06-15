f2();
f2();
function f0(v) {
    throw 'Caught';
}
function f1(v) {
    SECTION:
        f0(f2, v, ': 3');
}
function f2(value, expect) {
    try {
        f1(value);
    } catch (e) {
    }
}
