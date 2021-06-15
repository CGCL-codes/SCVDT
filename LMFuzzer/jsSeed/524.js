function f0() {
    return typeof this;
}
if (f0() !== 'undefined') {
    throw '\'this\' had incorrect value!';
}
