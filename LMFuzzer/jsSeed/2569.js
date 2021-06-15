function f0() {
    this.x = this.x.x;
}
f0.prototype.x = { x: 1 };
new f0();
