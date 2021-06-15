function f0(__v_9) {
    var v0 = 0;
    var v1 = 10000;
    while (v1-- != 0) {
        __v_9.push(0);
        if (++v0 >= 2)
            return __v_9;
        v0 = {};
    }
}
v2 = f0([]);
