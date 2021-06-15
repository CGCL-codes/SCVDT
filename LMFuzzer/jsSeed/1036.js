var v0 = Date.UTC;
if (v0 === 1)
    Date.UTC = 2;
else
    Date.UTC = 1;
if (Date.UTC === v0) {
    $ERROR('#1: The Date.UTC has not the attribute ReadOnly');
}
