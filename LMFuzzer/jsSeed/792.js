var v0 = { x: 2 };
var v1 = { y: 2 };
v1.__proto__ = v0;
function f0() {
    this.z = 1;
}
var v2 = new f0();
v2[1] = 'MyObjIndex';
v2.__proto__ = v1;
WScript.Echo('PASSED');
