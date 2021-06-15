var v0 = function () {
    return typeof this;
};
if (v0() !== 'undefined') {
    throw '\'this\' had incorrect value!';
}
