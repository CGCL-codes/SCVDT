function f0() {
    this.a = { text: 'Hello!' };
}
var v0 = new f0();
var v1 = new f0();
v1.b = {};
Object.defineProperty(v0, '2', {});
var v2 = new f0();
v2.a = {};
