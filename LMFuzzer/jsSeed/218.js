(function () {
    throw function f(a, b) {
        if (a.h == b) {
            return eval('((function(){return 1})())!=this');
        }
        f(b);
    }([], 0);
}());
