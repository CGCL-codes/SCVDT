var v0 = function () {
    var v1;
};
var v2 = {
    bar: function () {
        this;
        return 0;
    }
};
v0();
v2.bar();
WScript.Echo('PASS');
