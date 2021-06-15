v0 = () => {
    let v1;
    with ({})
        v1 = () => {
            'use strict';
            delete this;
        };
    return v1;
};
v0()();
v0 = () => eval('"use strict"; delete this');
v0();
