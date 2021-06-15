var v0 = function (o) {
    o.prop1 = 1;
};
function f0(arg0, arg1) {
    this.prop0 = arg0;
    this.prop2 = arg1;
}
v1 = new f0();
Object.create(v1);
v0(v1);
WScript.Echo('PASSED');
