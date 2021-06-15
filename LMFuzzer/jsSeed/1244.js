Function('this.field="battle"').call(void 0);
if (this['field'] !== 'battle') {
    $ERROR('#1: If thisArg is null or undefined, the called function is passed the global object as the this value');
}
