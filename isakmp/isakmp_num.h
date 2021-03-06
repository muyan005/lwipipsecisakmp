/* DO NOT EDIT-- this file is automatically generated.  */

#ifndef _ISAKMP_NUM_H_
#define _ISAKMP_NUM_H_

#include "constants.h"





extern struct constant_map isakmp_payload_cst[];

#define ISAKMP_PAYLOAD_NONE 0
#define ISAKMP_PAYLOAD_SA 1
#define ISAKMP_PAYLOAD_PROPOSAL 2
#define ISAKMP_PAYLOAD_TRANSFORM 3
#define ISAKMP_PAYLOAD_KEY_EXCH 4
#define ISAKMP_PAYLOAD_ID 5
#define ISAKMP_PAYLOAD_CERT 6
#define ISAKMP_PAYLOAD_CERT_REQ 7
#define ISAKMP_PAYLOAD_HASH 8
#define ISAKMP_PAYLOAD_SIG 9
#define ISAKMP_PAYLOAD_NONCE 10
#define ISAKMP_PAYLOAD_NOTIFY 11
#define ISAKMP_PAYLOAD_DELETE 12
#define ISAKMP_PAYLOAD_VENDOR 13
#define ISAKMP_PAYLOAD_ATTRIBUTE 14
#define ISAKMP_PAYLOAD_SAK 15
#define ISAKMP_PAYLOAD_SAT 16
#define ISAKMP_PAYLOAD_KD 17
#define ISAKMP_PAYLOAD_SEQ 18
#define ISAKMP_PAYLOAD_POP 19
#define ISAKMP_PAYLOAD_NAT_D 20
#define ISAKMP_PAYLOAD_NAT_OA 21
#define ISAKMP_PAYLOAD_RESERVED_MIN 22
#define ISAKMP_PAYLOAD_RESERVED_MAX 127
#define ISAKMP_PAYLOAD_PRIVATE_MIN 128
#define ISAKMP_PAYLOAD_NAT_D_DRAFT 130
#define ISAKMP_PAYLOAD_NAT_OA_DRAFT 131
#define ISAKMP_PAYLOAD_PRIVATE_MAX 255
#define ISAKMP_PAYLOAD_MAX 255

extern struct constant_map isakmp_exch_cst[];

#define ISAKMP_EXCH_NONE 0
#define ISAKMP_EXCH_BASE 1
#define ISAKMP_EXCH_ID_PROT 2
#define ISAKMP_EXCH_AUTH_ONLY 3
#define ISAKMP_EXCH_AGGRESSIVE 4
#define ISAKMP_EXCH_INFO 5
#define ISAKMP_EXCH_TRANSACTION 6
#define ISAKMP_EXCH_FUTURE_MIN 7
#define ISAKMP_EXCH_FUTURE_MAX 31
#define ISAKMP_EXCH_DOI_MIN 32
#define ISAKMP_EXCH_DOI_MAX 255

extern struct constant_map isakmp_flags_cst[];

#define ISAKMP_FLAGS_ENC 1
#define ISAKMP_FLAGS_COMMIT 2
#define ISAKMP_FLAGS_AUTH_ONLY 4

extern struct constant_map isakmp_certenc_cst[];

#define ISAKMP_CERTENC_NONE 0
#define ISAKMP_CERTENC_PKCS 1
#define ISAKMP_CERTENC_PGP 2
#define ISAKMP_CERTENC_DNS 3
#define ISAKMP_CERTENC_X509_SIG 4
#define ISAKMP_CERTENC_X509_KE 5
#define ISAKMP_CERTENC_KERBEROS 6
#define ISAKMP_CERTENC_CRL 7
#define ISAKMP_CERTENC_ARL 8
#define ISAKMP_CERTENC_SPKI 9
#define ISAKMP_CERTENC_X509_ATTR 10
#define ISAKMP_CERTENC_KEYNOTE 11
#define ISAKMP_CERTENC_HASH_URL_PKIX_CERT 12
#define ISAKMP_CERTENC_HASH_URL_PKIX_BUNDLE 13
#define ISAKMP_CERTENC_RESERVED_MIN 14
#define ISAKMP_CERTENC_RESERVED_MAX 255

extern struct constant_map isakmp_notify_cst[];

#define ISAKMP_NOTIFY_INVALID_PAYLOAD_TYPE 1
#define ISAKMP_NOTIFY_DOI_NOT_SUPPORTED 2
#define ISAKMP_NOTIFY_SITUATION_NOT_SUPPORTED 3
#define ISAKMP_NOTIFY_INVALID_COOKIE 4
#define ISAKMP_NOTIFY_INVALID_MAJOR_VERSION 5
#define ISAKMP_NOTIFY_INVALID_MINOR_VERSION 6
#define ISAKMP_NOTIFY_INVALID_EXCHANGE_TYPE 7
#define ISAKMP_NOTIFY_INVALID_FLAGS 8
#define ISAKMP_NOTIFY_INVALID_MESSAGE_ID 9
#define ISAKMP_NOTIFY_INVALID_PROTOCOL_ID 10
#define ISAKMP_NOTIFY_INVALID_SPI 11
#define ISAKMP_NOTIFY_INVALID_TRANSFORM_ID 12
#define ISAKMP_NOTIFY_ATTRIBUTES_NOT_SUPPORTED 13
#define ISAKMP_NOTIFY_NO_PROPOSAL_CHOSEN 14
#define ISAKMP_NOTIFY_BAD_PROPOSAL_SYNTAX 15
#define ISAKMP_NOTIFY_PAYLOAD_MALFORMED 16
#define ISAKMP_NOTIFY_INVALID_KEY_INFORMATION 17
#define ISAKMP_NOTIFY_INVALID_ID_INFORMATION 18
#define ISAKMP_NOTIFY_INVALID_CERT_ENCODING 19
#define ISAKMP_NOTIFY_INVALID_CERTIFICATE 20
#define ISAKMP_NOTIFY_CERT_TYPE_UNSUPPORTED 21
#define ISAKMP_NOTIFY_INVALID_CERT_AUTHORITY 22
#define ISAKMP_NOTIFY_INVALID_HASH_INFORMATION 23
#define ISAKMP_NOTIFY_AUTHENTICATION_FAILED 24
#define ISAKMP_NOTIFY_INVALID_SIGNATURE 25
#define ISAKMP_NOTIFY_ADDRESS_NOTIFICATION 26
#define ISAKMP_NOTIFY_NOTIFY_SA_LIFETIME 27
#define ISAKMP_NOTIFY_CERTIFICATE_UNAVAILABLE 28
#define ISAKMP_NOTIFY_UNSUPPORTED_EXCHANGE_TYPE 29
#define ISAKMP_NOTIFY_UNEQUAL_PAYLOAD_LENGTHS 30
#define ISAKMP_NOTIFY_RESERVED_MIN 31
#define ISAKMP_NOTIFY_RESERVED_MAX 8191
#define ISAKMP_NOTIFY_PRIVATE_MIN 8192
#define ISAKMP_NOTIFY_PRIVATE_MAX 16383
#define ISAKMP_NOTIFY_STATUS_CONNECTED 16384
#define ISAKMP_NOTIFY_STATUS_RESERVED1_MIN 16385
#define ISAKMP_NOTIFY_STATUS_RESERVED1_MAX 24575
#define ISAKMP_NOTIFY_STATUS_DOI_MIN 24576
#define ISAKMP_NOTIFY_STATUS_DOI_MAX 32767
#define ISAKMP_NOTIFY_STATUS_PRIVATE_MIN 32768
#define ISAKMP_NOTIFY_STATUS_DPD_R_U_THERE 36136
#define ISAKMP_NOTIFY_STATUS_DPD_R_U_THERE_ACK 36137
#define ISAKMP_NOTIFY_STATUS_PRIVATE_MAX 40959
#define ISAKMP_NOTIFY_STATUS_RESERVED2_MIN 40960
#define ISAKMP_NOTIFY_STATUS_RESERVED2_MAX 65535

extern struct constant_map isakmp_v2_notify_cst[];

#define ISAKMP_V2_NOTIFY_UNSUPPORTED_CRITICAL_PAYLOAD 1
#define ISAKMP_V2_NOTIFY_INVALID_IKE_SPI 4
#define ISAKMP_V2_NOTIFY_INVALID_MAJOR_VERSION 5
#define ISAKMP_V2_NOTIFY_INVALID_SYNTAX 7
#define ISAKMP_V2_NOTIFY_INVALID_MESSAGE_ID 9
#define ISAKMP_V2_NOTIFY_INVALID_SPI 11
#define ISAKMP_V2_NOTIFY_NO_PROPOSAL_CHOSEN 14
#define ISAKMP_V2_NOTIFY_AUTHENTICATION_FAILED 24
#define ISAKMP_V2_NOTIFY_SINGLE_PAIR_REQUIRED 34
#define ISAKMP_V2_NOTIFY_NO_ADDITIONAL_SAS 35
#define ISAKMP_V2_NOTIFY_INTERNAL_ADDRESS_FAILURE 36
#define ISAKMP_V2_NOTIFY_FAILED_CP_REQUIRED 37
#define ISAKMP_V2_NOTIFY_TS_UNACCEPTABLE 38
#define ISAKMP_V2_NOTIFY_RESERVED_MIN 39
#define ISAKMP_V2_NOTIFY_RESERVED_MAX 8191
#define ISAKMP_V2_NOTIFY_PRIVATE_MIN 8192
#define ISAKMP_V2_NOTIFY_PRIVATE_MAX 16383
#define ISAKMP_V2_NOTIFY_STATUS_RESERVED1_MIN 16384
#define ISAKMP_V2_NOTIFY_STATUS_RESERVED1_MAX 24577
#define ISAKMP_V2_NOTIFY_STATUS_INITIAL_CONTACT 24578
#define ISAKMP_V2_NOTIFY_STATUS_SET_WINDOW_SIZE 24579
#define ISAKMP_V2_NOTIFY_STATUS_ADDITIONAL_IS_POSSIBLE 24580
#define ISAKMP_V2_NOTIFY_STATUS_IPCOMP_SUPPORTED 24581
#define ISAKMP_V2_NOTIFY_STATUS_NAT_DETECTION_SOURCE_IP 24582
#define ISAKMP_V2_NOTIFY_STATUS_NAT_DETECTION_DESTINATION_IP 24583
#define ISAKMP_V2_NOTIFY_STATUS_COOKIE 24584
#define ISAKMP_V2_NOTIFY_STATUS_USE_TRANSPORT_MODE 24585
#define ISAKMP_V2_NOTIFY_STATUS_HTTP_CERT_LOOKUP_SUPPORTED 24586
#define ISAKMP_V2_NOTIFY_STATUS_RESERVED2_MIN 24587
#define ISAKMP_V2_NOTIFY_STATUS_RESERVED2_MAX 40959
#define ISAKMP_V2_NOTIFY_STATUS_PRIVATE_MIN 40960
#define ISAKMP_V2_NOTIFY_STATUS_PRIVATE_MAX 65535

extern struct constant_map isakmp_doi_cst[];

#define ISAKMP_DOI_ISAKMP 0

extern struct constant_map isakmp_proto_cst[];

#define ISAKMP_PROTO_ISAKMP 1

extern struct constant_map isakmp_cfg_cst[];

#define ISAKMP_CFG_REQUEST 1
#define ISAKMP_CFG_REPLY 2
#define ISAKMP_CFG_SET 3
#define ISAKMP_CFG_ACK 4
#define ISAKMP_CFG_FUTURE_MIN 5
#define ISAKMP_CFG_FUTURE_MAX 127
#define ISAKMP_CFG_PRIVATE_MIN 128
#define ISAKMP_CFG_PRIVATE_MAX 255

extern struct constant_map isakmp_cfg_attr_cst[];

#define ISAKMP_CFG_ATTR_INTERNAL_IP4_ADDRESS 1
#define ISAKMP_CFG_ATTR_INTERNAL_IP4_NETMASK 2
#define ISAKMP_CFG_ATTR_INTERNAL_IP4_DNS 3
#define ISAKMP_CFG_ATTR_INTERNAL_IP4_NBNS 4
#define ISAKMP_CFG_ATTR_INTERNAL_ADDRESS_EXPIRY 5
#define ISAKMP_CFG_ATTR_INTERNAL_IP4_DHCP 6
#define ISAKMP_CFG_ATTR_APPLICATION_VERSION 7
#define ISAKMP_CFG_ATTR_INTERNAL_IP6_ADDRESS 8
#define ISAKMP_CFG_ATTR_INTERNAL_IP6_NETMASK 9
#define ISAKMP_CFG_ATTR_INTERNAL_IP6_DNS 10
#define ISAKMP_CFG_ATTR_INTERNAL_IP6_NBNS 11
#define ISAKMP_CFG_ATTR_INTERNAL_IP6_DHCP 12
#define ISAKMP_CFG_ATTR_INTERNAL_IP4_SUBNET 13
#define ISAKMP_CFG_ATTR_SUPPORTED_ATTRIBUTES 14
#define ISAKMP_CFG_ATTR_INTERNAL_IP6_SUBNET 15
#define ISAKMP_CFG_ATTR_FUTURE_MIN 16
#define ISAKMP_CFG_ATTR_FUTURE_MAX 16383
#define ISAKMP_CFG_ATTR_PRIVATE_MIN 16384
#define ISAKMP_CFG_ATTR_PRIVATE_MAX 32767

extern struct constant_map isakmp_eap_code_cst[];

#define ISAKMP_EAP_CODE_REQUEST 1
#define ISAKMP_EAP_CODE_RESPONSE 2
#define ISAKMP_EAP_CODE_SUCCESS 3
#define ISAKMP_EAP_CODE_FAILURE 4

extern struct constant_map isakmp_eap_type_cst[];

#define ISAKMP_EAP_TYPE_IDENTITY 1
#define ISAKMP_EAP_TYPE_NOTIFICATION 2
#define ISAKMP_EAP_TYPE_NAK 3
#define ISAKMP_EAP_TYPE_MD5_CHALLENGE 4
#define ISAKMP_EAP_TYPE_OTP 5
#define ISAKMP_EAP_TYPE_TOKEN 6


#endif /* _ISAKMP_NUM_H_ */
