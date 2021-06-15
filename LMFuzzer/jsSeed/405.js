JSON.parse('[1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0]', function (k, v) {
    return '';
});
v0 = '[';
for (v1 = 0; v1 < 2048; v1++)
    v0 += '1,';
v0 += '1]';
JSON.parse(v0);
