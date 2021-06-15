function f0() {
    this.e = function () {
    };
    Object.defineProperty(this, 'e', { get: eval });
}
new f0();
