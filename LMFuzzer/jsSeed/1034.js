function f0() {
}
;
function f1(o) {
    f0 = new Function('');
}
f1({});
f1({});
f0++;
