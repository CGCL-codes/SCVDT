static u_char *php_parserr(u_char *cp, querybuf *answer, int type_to_fetch, int store, int raw, zval **subarray)
{
	u_short type, class, dlen;
	u_long ttl;
	long n, i;
	u_short s;
	u_char *tp, *p;
	char name[MAXHOSTNAMELEN];
	int have_v6_break = 0, in_v6_break = 0;

	*subarray = NULL;

	n = dn_expand(answer->qb2, answer->qb2+65536, cp, name, sizeof(name) - 2);
	if (n < 0) {
		return NULL;
	}
	cp += n;

	GETSHORT(type, cp);
	GETSHORT(class, cp);
	GETLONG(ttl, cp);
	GETSHORT(dlen, cp);
	if (type_to_fetch != T_ANY && type != type_to_fetch) {
		cp += dlen;
		return cp;
	}

	if (!store) {
		cp += dlen;
		return cp;
	}

	ALLOC_INIT_ZVAL(*subarray);
	array_init(*subarray);

	add_assoc_string(*subarray, "host", name, 1);
	add_assoc_string(*subarray, "class", "IN", 1);
	add_assoc_long(*subarray, "ttl", ttl);

	if (raw) {
		add_assoc_long(*subarray, "type", type);
		add_assoc_stringl(*subarray, "data", (char*) cp, (uint) dlen, 1);
		cp += dlen;
		return cp;
	}

	switch (type) {
		case DNS_T_A:
			add_assoc_string(*subarray, "type", "A", 1);
			snprintf(name, sizeof(name), "%d.%d.%d.%d", cp[0], cp[1], cp[2], cp[3]);
			add_assoc_string(*subarray, "ip", name, 1);
			cp += dlen;
			break;
		case DNS_T_MX:
			add_assoc_string(*subarray, "type", "MX", 1);
			GETSHORT(n, cp);
			add_assoc_long(*subarray, "pri", n);
			/* no break; */
		case DNS_T_CNAME:
			if (type == DNS_T_CNAME) {
				add_assoc_string(*subarray, "type", "CNAME", 1);
			}
			/* no break; */
		case DNS_T_NS:
			if (type == DNS_T_NS) {
				add_assoc_string(*subarray, "type", "NS", 1);
			}
			/* no break; */
		case DNS_T_PTR:
			if (type == DNS_T_PTR) {
				add_assoc_string(*subarray, "type", "PTR", 1);
			}
			n = dn_expand(answer->qb2, answer->qb2+65536, cp, name, (sizeof name) - 2);
			if (n < 0) {
				return NULL;
			}
			cp += n;
			add_assoc_string(*subarray, "target", name, 1);
			break;
		case DNS_T_HINFO:
			/* See RFC 1010 for values */
			add_assoc_string(*subarray, "type", "HINFO", 1);
			n = *cp & 0xFF;
			cp++;
			add_assoc_stringl(*subarray, "cpu", (char*)cp, n, 1);
			cp += n;
			n = *cp & 0xFF;
			cp++;
			add_assoc_stringl(*subarray, "os", (char*)cp, n, 1);
			cp += n;
			break;
		case DNS_T_TXT:
			{
				int ll = 0;
				zval *entries = NULL;

				add_assoc_string(*subarray, "type", "TXT", 1);
				tp = emalloc(dlen + 1);
				
				MAKE_STD_ZVAL(entries);
				array_init(entries);
				
				while (ll < dlen) {
					n = cp[ll];
					if ((ll + n) >= dlen) {
						// Invalid chunk length, truncate
						n = dlen - (ll + 1);
					}
					memcpy(tp + ll , cp + ll + 1, n);
					add_next_index_stringl(entries, cp + ll + 1, n, 1);
					ll = ll + n + 1;
				}
				tp[dlen] = '\0';
				cp += dlen;

				add_assoc_stringl(*subarray, "txt", tp, (dlen>0)?dlen - 1:0, 0);
				add_assoc_zval(*subarray, "entries", entries);
			}
			break;
		case DNS_T_SOA:
			add_assoc_string(*subarray, "type", "SOA", 1);
			n = dn_expand(answer->qb2, answer->qb2+65536, cp, name, (sizeof name) -2);
			if (n < 0) {
				return NULL;
			}
			cp += n;
			add_assoc_string(*subarray, "mname", name, 1);
			n = dn_expand(answer->qb2, answer->qb2+65536, cp, name, (sizeof name) -2);
			if (n < 0) {
				return NULL;
			}
			cp += n;
			add_assoc_string(*subarray, "rname", name, 1);
			GETLONG(n, cp);
			add_assoc_long(*subarray, "serial", n);
			GETLONG(n, cp);
			add_assoc_long(*subarray, "refresh", n);
			GETLONG(n, cp);
			add_assoc_long(*subarray, "retry", n);
			GETLONG(n, cp);
			add_assoc_long(*subarray, "expire", n);
			GETLONG(n, cp);
			add_assoc_long(*subarray, "minimum-ttl", n);
			break;
		case DNS_T_AAAA:
			tp = (u_char*)name;
			for(i=0; i < 8; i++) {
				GETSHORT(s, cp);
				if (s != 0) {
					if (tp > (u_char *)name) {
						in_v6_break = 0;
						tp[0] = ':';
						tp++;
					}
					tp += sprintf((char*)tp,"%x",s);
				} else {
					if (!have_v6_break) {
						have_v6_break = 1;
						in_v6_break = 1;
						tp[0] = ':';
						tp++;
					} else if (!in_v6_break) {
						tp[0] = ':';
						tp++;
						tp[0] = '0';
						tp++;
					}
				}
			}
			if (have_v6_break && in_v6_break) {
				tp[0] = ':';
				tp++;
			}
			tp[0] = '\0';
			add_assoc_string(*subarray, "type", "AAAA", 1);
			add_assoc_string(*subarray, "ipv6", name, 1);
			break;
		case DNS_T_A6:
			p = cp;
			add_assoc_string(*subarray, "type", "A6", 1);
			n = ((int)cp[0]) & 0xFF;
			cp++;
			add_assoc_long(*subarray, "masklen", n);
			tp = (u_char*)name;
			if (n > 15) {
				have_v6_break = 1;
				in_v6_break = 1;
				tp[0] = ':';
				tp++;
			}
			if (n % 16 > 8) {
				/* Partial short */
				if (cp[0] != 0) {
					if (tp > (u_char *)name) {
						in_v6_break = 0;
						tp[0] = ':';
						tp++;
					}
					sprintf((char*)tp, "%x", cp[0] & 0xFF);
				} else {
					if (!have_v6_break) {
						have_v6_break = 1;
						in_v6_break = 1;
						tp[0] = ':';
						tp++;
					} else if (!in_v6_break) {
						tp[0] = ':';
						tp++;
						tp[0] = '0';
						tp++;
					}
				}
				cp++;
			}
			for (i = (n + 8) / 16; i < 8; i++) {
				GETSHORT(s, cp);
				if (s != 0) {
					if (tp > (u_char *)name) {
						in_v6_break = 0;
						tp[0] = ':';
						tp++;
					}
					tp += sprintf((char*)tp,"%x",s);
				} else {
					if (!have_v6_break) {
						have_v6_break = 1;
						in_v6_break = 1;
						tp[0] = ':';
						tp++;
					} else if (!in_v6_break) {
						tp[0] = ':';
						tp++;
						tp[0] = '0';
						tp++;
					}
				}
			}
			if (have_v6_break && in_v6_break) {
				tp[0] = ':';
				tp++;
			}
			tp[0] = '\0';
			add_assoc_string(*subarray, "ipv6", name, 1);
			if (cp < p + dlen) {
				n = dn_expand(answer->qb2, answer->qb2+65536, cp, name, (sizeof name) - 2);
				if (n < 0) {
					return NULL;
				}
				cp += n;
				add_assoc_string(*subarray, "chain", name, 1);
			}
			break;
		case DNS_T_SRV:
			add_assoc_string(*subarray, "type", "SRV", 1);
			GETSHORT(n, cp);
			add_assoc_long(*subarray, "pri", n);
			GETSHORT(n, cp);
			add_assoc_long(*subarray, "weight", n);
			GETSHORT(n, cp);
			add_assoc_long(*subarray, "port", n);
			n = dn_expand(answer->qb2, answer->qb2+65536, cp, name, (sizeof name) - 2);
			if (n < 0) {
				return NULL;
			}
			cp += n;
			add_assoc_string(*subarray, "target", name, 1);
			break;
		case DNS_T_NAPTR:
			add_assoc_string(*subarray, "type", "NAPTR", 1);
			GETSHORT(n, cp);
			add_assoc_long(*subarray, "order", n);
			GETSHORT(n, cp);
			add_assoc_long(*subarray, "pref", n);
			n = (cp[0] & 0xFF);
			add_assoc_stringl(*subarray, "flags", (char*)++cp, n, 1);
			cp += n;
			n = (cp[0] & 0xFF);
			add_assoc_stringl(*subarray, "services", (char*)++cp, n, 1);
			cp += n;
			n = (cp[0] & 0xFF);
			add_assoc_stringl(*subarray, "regex", (char*)++cp, n, 1);
			cp += n;
			n = dn_expand(answer->qb2, answer->qb2+65536, cp, name, (sizeof name) - 2);
			if (n < 0) {
				return NULL;
			}
			cp += n;
			add_assoc_string(*subarray, "replacement", name, 1);
			break;
		default:
			zval_ptr_dtor(subarray);
			*subarray = NULL;
			cp += dlen;
			break;
	}

	return cp;
}
