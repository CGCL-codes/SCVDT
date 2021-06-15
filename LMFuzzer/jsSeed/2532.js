function f0() {
    try {
        f0();
    } catch (e) {
        /(\2)(a)/.test('');
    }
}
f0();
