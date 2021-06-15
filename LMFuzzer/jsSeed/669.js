var v0 = { fooProp: 'fooooooo' };
if (!('fooProp' in v0)) {
    $ERROR('#1: var __obj={fooProp:"fooooooo"}; "fooProp" in __obj');
}
