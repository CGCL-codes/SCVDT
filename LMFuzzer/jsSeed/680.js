function f0() {
    var v0 = '';
    function f1() {
        try {
            eval('');
            return v0;
        } catch (e) {
        }
    }
    return f1();
}
f0();
