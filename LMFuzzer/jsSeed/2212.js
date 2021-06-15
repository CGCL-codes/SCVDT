function f0(str) {
    for (var v0 = 0; v0 < 10; v0++) {
        v1 = /foo(ba(r))?/.exec(str);
        var v2 = v1[0] + ' ' + v1[1] + ' ' + v1[2];
    }
}
f0('foobar');
f0('foo');
