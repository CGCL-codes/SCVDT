delete Object.prototype.__proto__;
function f0() {
    this.toString = 1;
}
f0.apply({});
f0();
