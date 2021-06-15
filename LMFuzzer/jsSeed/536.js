/\2/.test('1');
function f0() {
    try {
        f0();
    } catch (e) {
        /\2/.test('1');
    }
}
f0();
