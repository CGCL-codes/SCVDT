var v0 = new String(1);
if (v0.valueOf() !== '' + 1) {
    $ERROR('#1: __string__obj = new String(1); __string__obj.valueOf() === ""+1. Actual: __string__obj.valueOf() ===' + v0.valueOf());
}
