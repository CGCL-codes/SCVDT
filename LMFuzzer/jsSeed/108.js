var v0 = 0;
for (p in Number)
    v0++;
if (v0 > 0) {
    $ERROR('#1: count=0; for (p in Number) count++; count > 0. Actual: ' + v0);
}
