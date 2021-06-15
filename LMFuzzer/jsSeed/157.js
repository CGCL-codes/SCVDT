var v0 = [];
for (var v1 = 0; v1 < 200; ++v1)
    v0.push({});
var v2 = new Proxy({}, {
    preventExtensions() {
        return false;
    }
});
Object.preventExtensions(v2);
