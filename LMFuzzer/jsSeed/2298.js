function f0() {
    function f1() {
        return typeof this;
    }
    return f1() === 'undefined' && typeof this === 'undefined';
}
if (!f0()) {
    throw '\'this\' had incorrect value!';
}
