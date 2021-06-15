var v0 = new Proxy({}, {
    getOwnPropertyDescriptor: function () {
        gc();
    }
});
function f0() {
    this.x = 23;
}
f0.prototype = v0;
new f0();
new f0();
