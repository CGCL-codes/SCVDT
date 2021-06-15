Error.prepareStackTrace = (e, s) => s;
var v0 = Error().stack[0].constructor;
try {
    new v0(3, 6).toString();
} catch (e) {
}
