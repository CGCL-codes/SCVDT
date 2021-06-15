this.__proto__ = Array.prototype;
Object.freeze(this);
function f0() {
    for (var v0 = 0; v0 < 10; v0++) {
        this.length = 1;
    }
}
f0();
