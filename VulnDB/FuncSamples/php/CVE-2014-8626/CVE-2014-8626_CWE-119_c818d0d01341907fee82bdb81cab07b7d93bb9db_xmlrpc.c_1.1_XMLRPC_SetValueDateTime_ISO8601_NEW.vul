void XMLRPC_SetValueDateTime_ISO8601(XMLRPC_VALUE value, const char* s) {
   if(value) {
      time_t time_val = 0;
      if(s) {
         value->type = xmlrpc_datetime;
         date_from_ISO8601(s, &time_val);
         value->i = time_val;
         simplestring_clear(&value->str);
         simplestring_add(&value->str, s);
      }
   }
}
