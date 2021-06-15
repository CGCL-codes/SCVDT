var v0 = 0;
var v1 = {
    toString: function () {
        v0++;
    }
};
var v2 = {};
for (var v3 = 0; v3 < 50; v3++)
    ++v2[v1];
