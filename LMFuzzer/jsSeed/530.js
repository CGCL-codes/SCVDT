v0 = {};
v1 = v0;
v0.toString = function () {
    new Int8Array(ArrayBuffer)[0] = new Float32Array(ArrayBuffer)[0];
};
print(v0 << v1);
