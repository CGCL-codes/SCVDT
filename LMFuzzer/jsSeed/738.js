function f0() {
    with (f0)
        this['00'] = function () {
        };
}
new f0();
