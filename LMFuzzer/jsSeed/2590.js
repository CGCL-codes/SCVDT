var v0 = {
    has: function (name) {
        assertEq(1, 2);
    }
};
for (var v1 = 0; v1 < 10; v1++) {
    var v2 = /undefined/;
    v2.__proto__ = new Proxy(function () {
    }, v0);
}
