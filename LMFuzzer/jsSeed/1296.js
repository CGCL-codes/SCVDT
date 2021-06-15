for (var v0 = -1000; v0 < 1000; v0++) {
    var v1 = v0 / 10;
    if (-Math.ceil(-v1) !== Math.floor(v1)) {
        $ERROR('#1: \'x = ' + v1 + '; Math.floor(x) !== -Math.ceil(-x)\'');
    }
}
