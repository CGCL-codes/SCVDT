load("201224b0d1c296b45befd2285e95dd42.js");
// arrow functions are not implicitly strict-mode code

load("19d7bc83becec11ee32c3a85fbc4d93d.js");

var f = a => { with (a) return f(); };
assertEq(f({f: () => 7}), 7);

f = a => function () { with (a) return f(); };
assertEq(f({f: () => 7})(), 7);

f = (a = {x: 1, x: 2}) => b => { "use strict"; return a.x; };
assertEq(f()(0), 2);

