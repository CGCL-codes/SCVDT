var v0 = {
    p: function () {
        for (var v1 = 0; v1 < 9; ++v1);
        with (v0) {
            q();
        }
    }
};
v0.q = function () {
    eval('this.p()');
};
v0.p();
