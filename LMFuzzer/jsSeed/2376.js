var v0 = {};
var v1 = new Proxy(v0, {
    get preventExtensions() {
        Object.preventExtensions(v0);
    }
});
Object.preventExtensions(v1);
