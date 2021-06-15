function f0() {
    return this;
}
if (new f0() === this || typeof new f0() === 'undefined') {
    throw '\'this\' had incorrect value!';
}
