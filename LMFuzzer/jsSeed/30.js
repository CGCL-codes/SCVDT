var v0 = false;
var v1 = {};
var v2 = {
    toString: function () {
        assert(!v0);
        v0 = true;
        return '';
    }
};
var v3 = function () {
    return 0;
};
v1[v2] &= v3();
