try {
    v0 = v0;
} catch (e) {
    $ERROR('#1: Declaration variable inside "do-while" statement is admitted');
}
do
    var v0;
while (false);
