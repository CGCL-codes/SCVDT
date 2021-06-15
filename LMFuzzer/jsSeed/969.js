var v0, v1;
v0 = '';
for (v1 = 0; v1 < 10; v1 += 1) {
    if (v1 < 5)
        continue;
    v0 += v1;
}
if (v0 !== '56789') {
    $ERROR('#1: __str === "56789". Actual:  __str ===' + v0);
}
