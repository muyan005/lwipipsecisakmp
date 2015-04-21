/* DO NOT EDIT-- this file is automatically generated.  */

#include "constants.h"
#include "field.h"
#include "ipsec_fld.h"
#include "isakmp_num.h"
#include "ipsec_num.h"





struct field ipsec_sit_fld[] = {
	{ "SIT", 0, 4, mask, ipsec_sit_sit_maps },
	{ "LABELED_DOMAIN_ID", 4, 4, num, 0 },
	{ "SECRECY_LENGTH", 8, 2, num, 0 },
	{ "RESERVED_1", 10, 2, ign, 0 },
	{ "SECRECY_CAT_LENGTH", 12, 2, num, 0 },
	{ "RESERVED_2", 14, 2, ign, 0 },
	{ "INTEGRITY_LENGTH", 16, 2, num, 0 },
	{ "RESERVED_3", 18, 2, ign, 0 },
	{ "INTEGRITY_CAT_LENGTH", 20, 2, num, 0 },
	{ "RESERVED_4", 22, 2, ign, 0 },
	{ 0, 0, 0, 0, 0 }
};

struct constant_map *ipsec_sit_sit_maps[] = {
	ipsec_sit_cst, 0
};

struct field ipsec_id_fld[] = {
	{ "PROTO", 0, 1, num, 0 },
	{ "PORT", 1, 2, num, 0 },
	{ 0, 0, 0, 0, 0 }
};
