var v0 = new Proxy(new Array(1), { has: () => true });
var v1 = v0.concat();
if (v1[0] !== undefined || v1.length !== 1) {
    print('failed');
} else {
    print('passed');
}
