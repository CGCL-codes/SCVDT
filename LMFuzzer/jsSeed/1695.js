try {
    function f0() {
        [].slice({});
        f0();
    }
    f0();
} catch (e) {
}
