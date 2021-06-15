Function('this.field="oil"').apply(undefined);
if (this['field'] !== 'oil') {
    $ERROR('#1: If thisArg is null or undefined, the called function is passed the global object as the this value');
}
