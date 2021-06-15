function f0() {
    var v0 = 3;
    this.x = function () {
        return v0;
    };
    for (var v1 = 0; v1 < 9; v1++);
}
new f0();
