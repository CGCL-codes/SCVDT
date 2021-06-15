(function f() {
    try {
        f();
    } catch (e) {
        (async () => await 1).length;
    }
}());
