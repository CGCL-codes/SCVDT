var v0 = new String(1);
if (v0.toString() !== '' + 1) {
    $ERROR('#1: __string__obj = new String(1); __string__obj.toString() === ""+1. Actual: __string__obj.toString() ===' + v0.toString());
}
