try {
    v0 = /x/;
    (function f() {
        v0.r = v0;
        return f();
    }());
} catch (e) {
}
