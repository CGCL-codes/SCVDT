var v0 = new String('ABC');
if (v0.charAt(3) !== '') {
    $ERROR('#1: __instance = new String("ABC"); __instance.charAt(3) === "". Actual: __instance.charAt(3) ===' + v0.charAt(3));
}
