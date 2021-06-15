function f0() {
}
;
function f1(o) {
    f0 = new Function('');
    eval('');
}
f1({});
f1({});
f0++;
