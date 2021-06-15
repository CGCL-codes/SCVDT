load("201224b0d1c296b45befd2285e95dd42.js");
function f() {
  eval("g=function() { \
          for (let x=0; x < 2; ++x) { \
            d=x \
          } \
        }")
  g();
  eval("var d")
  g();
}

f();
assertEq(d, 1);
