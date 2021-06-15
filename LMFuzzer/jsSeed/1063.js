try {
    var v0 = Object.getPrototypeOf(Int8Array);
    var v1 = Reflect.construct(v0, [], Int8Array);
    new Int8Array(4).set(v1);
} catch (e) {
}
