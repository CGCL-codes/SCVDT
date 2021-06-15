load("201224b0d1c296b45befd2285e95dd42.js");

try {
    x = evalcx('')
    toSource = (function() {
        x = (new WeakMap).get(function() {})
    })
    valueOf = (function() {
        schedulegc(x)
    })
    this + ''
    for (v of this) {}
} catch (e) {}
gc()
this + 1
