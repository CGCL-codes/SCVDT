function f0() {
    return function () {
        return typeof this;
    }() === 'undefined' && typeof this === 'undefined';
}
if (!f0()) {
    throw '\'this\' had incorrect value!';
}
