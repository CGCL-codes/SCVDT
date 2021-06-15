v0 = {};
v0.__defineGetter__('foobar', function () {
    return 42;
});
v0.a = 1;
v0.b = 2;
v0.c = 3;
v0.__defineGetter__('foobar', function () {
    return 42;
});
