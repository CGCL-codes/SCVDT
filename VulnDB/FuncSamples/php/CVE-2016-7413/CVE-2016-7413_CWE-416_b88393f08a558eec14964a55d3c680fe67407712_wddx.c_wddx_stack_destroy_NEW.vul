static int wddx_stack_destroy(wddx_stack *stack)
{
	register int i;

	if (stack->elements) {
		for (i = 0; i < stack->top; i++) {
			if (((st_entry *)stack->elements[i])->data
					&& ((st_entry *)stack->elements[i])->type != ST_FIELD)	{
				zval_ptr_dtor(&((st_entry *)stack->elements[i])->data);
			}
			if (((st_entry *)stack->elements[i])->varname) {
				efree(((st_entry *)stack->elements[i])->varname);
			}
			efree(stack->elements[i]);
		}
		efree(stack->elements);
	}
	return SUCCESS;
}
