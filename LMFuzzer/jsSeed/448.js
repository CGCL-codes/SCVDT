function f0() {
}
;
f0.prop = 1;
if (delete f0.prop !== true) {
    $ERROR('#1: function MyFunction(){}; MyFunction.prop = 1; delete MyFunction.prop === true');
}
