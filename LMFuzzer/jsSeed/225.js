(function () {
    function f0() {
        for (var v0 = 0; v0 < 2; ++v0) {
            print(this);
        }
    }
    f0();
    f0();
}());
