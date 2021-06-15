function f0(o) {
    o[{}] = 1;
    with (Object) {
    }
}
f0(Object.prototype);
