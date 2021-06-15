v0 = new Float64Array(1);
v1 = {
    valueOf: function () {
        v2.y = 'bar';
        return 42;
    }
};
v2 = v0;
v2[0] = v1;
