var v0 = function () {
    return this;
};
if (new v0() === this || typeof new v0() === 'undefined') {
    throw '\'this\' had incorrect value!';
}
