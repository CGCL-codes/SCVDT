var v0;
for (var v1 in this) {
    if (v1 === '__declared__var')
        v0 = true;
}
if (!v0) {
    $ERROR('#1: When using property attributes, {DontEnum} not used');
}
var v2;
