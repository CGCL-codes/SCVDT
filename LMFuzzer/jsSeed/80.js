(function f() {
    let v0 = new function () {
    }();
    this.__defineGetter__('x', function () {
        ({ e: v0 });
    });
}());
print(v0);
