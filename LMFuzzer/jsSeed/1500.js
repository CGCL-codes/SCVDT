var v0 = function () {
    return function () {
        return typeof this;
    }() === 'undefined' && typeof this === 'undefined';
};
if (!v0()) {
    throw '\'this\' had incorrect value!';
}
