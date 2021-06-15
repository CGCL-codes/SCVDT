eval(' (function(){this.feat=1}).call()');
if (this['feat'] !== 1) {
    $ERROR('#1: If thisArg is null or undefined, the called function is passed the global object as the this value');
}
