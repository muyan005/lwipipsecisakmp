/* DO NOT EDIT-- this file is automatically generated.  */

#ifndef _IPSEC_FLD_H_
#define _IPSEC_FLD_H_

#include "field.h"

struct constant_map;





extern struct field ipsec_sit_fld[];

#define IPSEC_SIT_SIT_OFF 0
#define IPSEC_SIT_SIT_LEN 4
extern struct constant_map *ipsec_sit_sit_maps[];
#define GET_IPSEC_SIT_SIT(buf) field_get_num (ipsec_sit_fld + 0, buf)
#define SET_IPSEC_SIT_SIT(buf, val) field_set_num (ipsec_sit_fld + 0, buf, val)
#define IPSEC_SIT_LABELED_DOMAIN_ID_OFF 4
#define IPSEC_SIT_LABELED_DOMAIN_ID_LEN 4
#define GET_IPSEC_SIT_LABELED_DOMAIN_ID(buf) field_get_num (ipsec_sit_fld + 1, buf)
#define SET_IPSEC_SIT_LABELED_DOMAIN_ID(buf, val) field_set_num (ipsec_sit_fld + 1, buf, val)
#define IPSEC_SIT_SECRECY_LENGTH_OFF 8
#define IPSEC_SIT_SECRECY_LENGTH_LEN 2
#define GET_IPSEC_SIT_SECRECY_LENGTH(buf) field_get_num (ipsec_sit_fld + 2, buf)
#define SET_IPSEC_SIT_SECRECY_LENGTH(buf, val) field_set_num (ipsec_sit_fld + 2, buf, val)
#define IPSEC_SIT_RESERVED_1_OFF 10
#define IPSEC_SIT_RESERVED_1_LEN 2
#define GET_IPSEC_SIT_RESERVED_1(buf) field_get_num (ipsec_sit_fld + 3, buf)
#define SET_IPSEC_SIT_RESERVED_1(buf, val) field_set_num (ipsec_sit_fld + 3, buf, val)
#define IPSEC_SIT_SECRECY_CAT_LENGTH_OFF 12
#define IPSEC_SIT_SECRECY_CAT_LENGTH_LEN 2
#define GET_IPSEC_SIT_SECRECY_CAT_LENGTH(buf) field_get_num (ipsec_sit_fld + 4, buf)
#define SET_IPSEC_SIT_SECRECY_CAT_LENGTH(buf, val) field_set_num (ipsec_sit_fld + 4, buf, val)
#define IPSEC_SIT_RESERVED_2_OFF 14
#define IPSEC_SIT_RESERVED_2_LEN 2
#define GET_IPSEC_SIT_RESERVED_2(buf) field_get_num (ipsec_sit_fld + 5, buf)
#define SET_IPSEC_SIT_RESERVED_2(buf, val) field_set_num (ipsec_sit_fld + 5, buf, val)
#define IPSEC_SIT_INTEGRITY_LENGTH_OFF 16
#define IPSEC_SIT_INTEGRITY_LENGTH_LEN 2
#define GET_IPSEC_SIT_INTEGRITY_LENGTH(buf) field_get_num (ipsec_sit_fld + 6, buf)
#define SET_IPSEC_SIT_INTEGRITY_LENGTH(buf, val) field_set_num (ipsec_sit_fld + 6, buf, val)
#define IPSEC_SIT_RESERVED_3_OFF 18
#define IPSEC_SIT_RESERVED_3_LEN 2
#define GET_IPSEC_SIT_RESERVED_3(buf) field_get_num (ipsec_sit_fld + 7, buf)
#define SET_IPSEC_SIT_RESERVED_3(buf, val) field_set_num (ipsec_sit_fld + 7, buf, val)
#define IPSEC_SIT_INTEGRITY_CAT_LENGTH_OFF 20
#define IPSEC_SIT_INTEGRITY_CAT_LENGTH_LEN 2
#define GET_IPSEC_SIT_INTEGRITY_CAT_LENGTH(buf) field_get_num (ipsec_sit_fld + 8, buf)
#define SET_IPSEC_SIT_INTEGRITY_CAT_LENGTH(buf, val) field_set_num (ipsec_sit_fld + 8, buf, val)
#define IPSEC_SIT_RESERVED_4_OFF 22
#define IPSEC_SIT_RESERVED_4_LEN 2
#define GET_IPSEC_SIT_RESERVED_4(buf) field_get_num (ipsec_sit_fld + 9, buf)
#define SET_IPSEC_SIT_RESERVED_4(buf, val) field_set_num (ipsec_sit_fld + 9, buf, val)
#define IPSEC_SIT_SZ 24

extern struct field ipsec_id_fld[];

#define IPSEC_ID_PROTO_OFF 0
#define IPSEC_ID_PROTO_LEN 1
#define GET_IPSEC_ID_PROTO(buf) field_get_num (ipsec_id_fld + 0, buf)
#define SET_IPSEC_ID_PROTO(buf, val) field_set_num (ipsec_id_fld + 0, buf, val)
#define IPSEC_ID_PORT_OFF 1
#define IPSEC_ID_PORT_LEN 2
#define GET_IPSEC_ID_PORT(buf) field_get_num (ipsec_id_fld + 1, buf)
#define SET_IPSEC_ID_PORT(buf, val) field_set_num (ipsec_id_fld + 1, buf, val)
#define IPSEC_ID_SZ 3

#endif /* _IPSEC_FLD_H_ */
