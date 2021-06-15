v0 = new Array({}, {}, {});
Object.defineProperty(v0, 1, {
    get: function () {
        v0.length = 0;
        v0[0] = -2147483648;
    }
});
v1 = v0.includes(new Array());
