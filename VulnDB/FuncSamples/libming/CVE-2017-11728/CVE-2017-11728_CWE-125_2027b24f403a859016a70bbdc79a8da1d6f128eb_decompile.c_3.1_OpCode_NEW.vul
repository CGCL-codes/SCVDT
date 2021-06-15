static inline int OpCode(SWF_ACTION *actions, int n, int maxn)
{
	if(!n || n >= maxn)
	{
#if DEBUG
		SWF_warn("OpCode: want %i, max %i\n", n, maxn);
#endif
		return -999;
	} else if (n < 1) {

#if DEBUG
		SWF_warn("OpCode: want %i < 1\n", n);
#endif
		return -998;
        }
	return actions[n].SWF_ACTIONRECORD.ActionCode;
}
