/* DO NOT EDIT-- this file is automatically generated.  */

#ifndef _IPSEC_NUM_H_
#define _IPSEC_NUM_H_

#include "constants.h"





extern struct constant_map ipsec_doi_cst[];

#define IPSEC_DOI_IPSEC 1

extern struct constant_map ipsec_attr_cst[];

#define IPSEC_ATTR_SA_LIFE_TYPE 1
#define IPSEC_ATTR_SA_LIFE_DURATION 2
#define IPSEC_ATTR_GROUP_DESCRIPTION 3
#define IPSEC_ATTR_ENCAPSULATION_MODE 4
#define IPSEC_ATTR_AUTHENTICATION_ALGORITHM 5
#define IPSEC_ATTR_KEY_LENGTH 6
#define IPSEC_ATTR_KEY_ROUNDS 7
#define IPSEC_ATTR_COMPRESS_DICTIONARY_SIZE 8
#define IPSEC_ATTR_COMPRESS_PRIVATE_ALGORITHM 9
#define IPSEC_ATTR_ECN_TUNNEL 10

extern struct constant_map ipsec_duration_cst[];

#define IPSEC_DURATION_SECONDS 1
#define IPSEC_DURATION_KILOBYTES 2

extern struct constant_map ipsec_encap_cst[];

#define IPSEC_ENCAP_TUNNEL 1
#define IPSEC_ENCAP_TRANSPORT 2
#define IPSEC_ENCAP_UDP_ENCAP_TUNNEL 3
#define IPSEC_ENCAP_UDP_ENCAP_TRANSPORT 4
#define IPSEC_ENCAP_UDP_ENCAP_TUNNEL_DRAFT 61443
#define IPSEC_ENCAP_UDP_ENCAP_TRANSPORT_DRAFT 61444

extern struct constant_map ipsec_auth_cst[];

#define IPSEC_AUTH_HMAC_MD5 1
#define IPSEC_AUTH_HMAC_SHA 2
#define IPSEC_AUTH_DES_MAC 3
#define IPSEC_AUTH_KPDK 4
#define IPSEC_AUTH_HMAC_SHA2_256 5
#define IPSEC_AUTH_HMAC_SHA2_384 6
#define IPSEC_AUTH_HMAC_SHA2_512 7
#define IPSEC_AUTH_HMAC_RIPEMD 8

extern struct constant_map ipsec_id_cst[];

#define IPSEC_ID_IPV4_ADDR 1
#define IPSEC_ID_FQDN 2
#define IPSEC_ID_USER_FQDN 3
#define IPSEC_ID_IPV4_ADDR_SUBNET 4
#define IPSEC_ID_IPV6_ADDR 5
#define IPSEC_ID_IPV6_ADDR_SUBNET 6
#define IPSEC_ID_IPV4_RANGE 7
#define IPSEC_ID_IPV6_RANGE 8
#define IPSEC_ID_DER_ASN1_DN 9
#define IPSEC_ID_DER_ASN1_GN 10
#define IPSEC_ID_KEY_ID 11

extern struct constant_map ike_attr_cst[];

#define IKE_ATTR_ENCRYPTION_ALGORITHM 1
#define IKE_ATTR_HASH_ALGORITHM 2
#define IKE_ATTR_AUTHENTICATION_METHOD 3
#define IKE_ATTR_GROUP_DESCRIPTION 4
#define IKE_ATTR_GROUP_TYPE 5
#define IKE_ATTR_GROUP_PRIME 6
#define IKE_ATTR_GROUP_GENERATOR_1 7
#define IKE_ATTR_GROUP_GENERATOR_2 8
#define IKE_ATTR_GROUP_CURVE_A 9
#define IKE_ATTR_GROUP_CURVE_B 10
#define IKE_ATTR_LIFE_TYPE 11
#define IKE_ATTR_LIFE_DURATION 12
#define IKE_ATTR_PRF 13
#define IKE_ATTR_KEY_LENGTH 14
#define IKE_ATTR_FIELD_SIZE 15
#define IKE_ATTR_GROUP_ORDER 16
#define IKE_ATTR_BLOCK_SIZE 17


extern struct constant_map ike_encrypt_cst[];

#define IKE_ENCRYPT_DES_CBC 1
#define IKE_ENCRYPT_IDEA_CBC 2
#define IKE_ENCRYPT_BLOWFISH_CBC 3
#define IKE_ENCRYPT_RC5_R16_B64_CBC 4
#define IKE_ENCRYPT_3DES_CBC 5
#define IKE_ENCRYPT_CAST_CBC 6
#define IKE_ENCRYPT_AES_CBC 7

extern struct constant_map ike_hash_cst[];

#define IKE_HASH_MD5 1
#define IKE_HASH_SHA 2
#define IKE_HASH_TIGER 3
#define IKE_HASH_SHA2_256 4
#define IKE_HASH_SHA2_384 5
#define IKE_HASH_SHA2_512 6

extern struct constant_map ike_auth_cst[];

#define IKE_AUTH_PRE_SHARED 1
#define IKE_AUTH_DSS 2
#define IKE_AUTH_RSA_SIG 3
#define IKE_AUTH_RSA_ENC 4
#define IKE_AUTH_RSA_ENC_REV 5
#define IKE_AUTH_EL_GAMAL_ENC 6
#define IKE_AUTH_EL_GAMAL_ENC_REV 7
#define IKE_AUTH_ECDSA_SIG 8

extern struct constant_map ike_group_desc_cst[];

#define IKE_GROUP_DESC_MODP_768 1
#define IKE_GROUP_DESC_MODP_1024 2
#define IKE_GROUP_DESC_EC2N_155 3
#define IKE_GROUP_DESC_EC2N_185 4
#define IKE_GROUP_DESC_MODP_1536 5
#define IKE_GROUP_DESC_EC2N_163sect 6
#define IKE_GROUP_DESC_EC2N_163K 7
#define IKE_GROUP_DESC_EC2N_283sect 8
#define IKE_GROUP_DESC_EC2N_283K 9
#define IKE_GROUP_DESC_EC2N_409sect 10
#define IKE_GROUP_DESC_EC2N_409K 11
#define IKE_GROUP_DESC_EC2N_571sect 12
#define IKE_GROUP_DESC_EC2N_571K 13
#define IKE_GROUP_DESC_MODP_2048 14
#define IKE_GROUP_DESC_MODP_3072 15
#define IKE_GROUP_DESC_MODP_4096 16
#define IKE_GROUP_DESC_MODP_6144 17
#define IKE_GROUP_DESC_MODP_8192 18

extern struct constant_map ike_group_cst[];

#define IKE_GROUP_MODP 1
#define IKE_GROUP_ECP 2
#define IKE_GROUP_EC2N 3

extern struct constant_map ike_duration_cst[];

#define IKE_DURATION_SECONDS 1
#define IKE_DURATION_KILOBYTES 2

extern struct constant_map ike_prf_cst[];


extern struct constant_map ipsec_sit_cst[];

#define IPSEC_SIT_IDENTITY_ONLY 1
#define IPSEC_SIT_SECRECY 2
#define IPSEC_SIT_INTEGRITY 4

extern struct constant_map ipsec_proto_cst[];

#define IPSEC_PROTO_IPSEC_AH 2
#define IPSEC_PROTO_IPSEC_ESP 3
#define IPSEC_PROTO_IPCOMP 4

extern struct constant_map ipsec_transform_cst[];

#define IPSEC_TRANSFORM_KEY_IKE 1

extern struct constant_map ipsec_ah_cst[];

#define IPSEC_AH_MD5 2
#define IPSEC_AH_SHA 3
#define IPSEC_AH_DES 4
#define IPSEC_AH_SHA2_256 5
#define IPSEC_AH_SHA2_384 6
#define IPSEC_AH_SHA2_512 7
#define IPSEC_AH_RIPEMD 8

extern struct constant_map ipsec_esp_cst[];

#define IPSEC_ESP_DES_IV64 1
#define IPSEC_ESP_DES 2
#define IPSEC_ESP_3DES 3
#define IPSEC_ESP_RC5 4
#define IPSEC_ESP_IDEA 5
#define IPSEC_ESP_CAST 6
#define IPSEC_ESP_BLOWFISH 7
#define IPSEC_ESP_3IDEA 8
#define IPSEC_ESP_DES_IV32 9
#define IPSEC_ESP_RC4 10
#define IPSEC_ESP_NULL 11
#define IPSEC_ESP_AES 12
#define IPSEC_ESP_AES_CTR 13
#define IPSEC_ESP_AES_GCM_16 20
#define IPSEC_ESP_AES_GMAC 23
#define IPSEC_ESP_AES_MARS 249
#define IPSEC_ESP_AES_RC6 250
#define IPSEC_ESP_AES_RIJNDAEL 251
#define IPSEC_ESP_AES_SERPENT 252
#define IPSEC_ESP_AES_TWOFISH 253

extern struct constant_map ipsec_ipcomp_cst[];

#define IPSEC_IPCOMP_OUI 1
#define IPSEC_IPCOMP_DEFLATE 2
#define IPSEC_IPCOMP_LZS 3
#define IPSEC_IPCOMP_V42BIS 4

extern struct constant_map ipsec_notify_cst[];

#define IPSEC_NOTIFY_RESPONDER_LIFETIME 24576
#define IPSEC_NOTIFY_REPLAY_STATUS 24577
#define IPSEC_NOTIFY_INITIAL_CONTACT 24578

extern struct constant_map ike_exch_cst[];

#define IKE_EXCH_QUICK_MODE 32
#define IKE_EXCH_NEW_GROUP_MODE 33

#endif /* _IPSEC_NUM_H_ */