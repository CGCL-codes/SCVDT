v0 = function () {
};
try {
    (function () {
        v0(...function* () {
            yield 1;
            yield 2;
            yield 3;
        }());
    }());
} catch (e) {
}
