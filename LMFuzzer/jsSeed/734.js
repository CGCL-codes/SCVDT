function f0() {
}
;
var v0 = new Proxy(f0, {
    get() {
        f0.prototype = 123;
    }
});
new v0();
