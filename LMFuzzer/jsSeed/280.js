function f0() {
    this.x = this[this.y = 'foo']--;
}
new f0();
