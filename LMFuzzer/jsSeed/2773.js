try {
    var v0 = Object.getPrototypeOf(Int8Array);
    var v1 = Reflect.construct(v0, [], Int8Array);
    Int8Array.prototype.values.call(v1).next();
} catch (e) {
}
