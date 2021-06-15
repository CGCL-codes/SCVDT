var v0, v1;
v0 = '';
for (v1 = 0; v1 < 10; v1 += 1) {
    if (v1 > 5)
        break;
    v0 += v1;
}
if (v0 !== '012345') {
    $ERROR('#1:__str === "012345". Actual: __str ===' + v0);
}
