function f0() {
    const v0 = 0;
    return function () {
        switch (7) {
        case v0:
        }
    };
}
for (var v1 = 0; v1 < 2; v1++) {
    let v2 = f0;
    v2();
}
