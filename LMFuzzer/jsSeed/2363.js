for (var v0 = 0; v0 < 100; ++v0) {
    var v1 = [];
    for (var v2 = 0; v2 < 1000; ++v2)
        v1.push(v2);
    while (v1.length)
        v1.splice(v1.length / 2, 1);
}
