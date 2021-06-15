static int jpc_crg_getparms(jpc_ms_t *ms, jpc_cstate_t *cstate, jas_stream_t *in)
{
	jpc_crg_t *crg = &ms->parms.crg;
	jpc_crgcomp_t *comp;
	uint_fast16_t compno;
	crg->numcomps = cstate->numcomps;
	if (!(crg->comps = jas_alloc2(cstate->numcomps, sizeof(uint_fast16_t)))) {
		return -1;
	}
	for (compno = 0, comp = crg->comps; compno < cstate->numcomps;
	  ++compno, ++comp) {
		if (jpc_getuint16(in, &comp->hoff) ||
		  jpc_getuint16(in, &comp->voff)) {
			jpc_crg_destroyparms(ms);
			return -1;
		}
	}
	return 0;
}
