var v0 = Date.parse;
if (v0 === 1)
    Date.parse = 2;
else
    Date.parse = 1;
if (Date.parse === v0) {
    $ERROR('#1: The Date.parse has not the attribute ReadOnly');
}
