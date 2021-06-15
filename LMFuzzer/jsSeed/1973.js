function f0(o, i) {
    o[i] = o;
}
var v0 = new Array();
f0(v0, 'prop0');
f0(v0, 0);
f0(v0, 1);
f0(v0, 0);
v0.prop0.toString();
