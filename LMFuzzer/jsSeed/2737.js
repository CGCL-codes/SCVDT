Function('this.feat=1').call(void 0);
if (this['feat'] !== 1) {
    $ERROR('#1: If thisArg is null or undefined, the called function is passed the global object as the this value');
}
