TARGET = ISAKMPD

LIBS   += base libc libm keynote libcrypto lwip  config libc_lwip_nic_dhcp
# plug-in to libc
LIBS   += config_args  libc_lwip  libc_log libc_log config_args # libc-resolv 

      

SRC_C   = app.c attribute.c cert.c connection.c constants.c conf.c \
		cookie.c crypto.c dh.c doi.c exchange.c exchange_num.c \
		field.c hash.c if.c ike_auth.c ike_main_mode.c \
		ike_phase_1.c ike_quick_mode.c init.c ipsec.c ipsec_fld.c \
		ipsec_num.c isakmpd.c isakmp_doi.c isakmp_fld.c isakmp_num.c \
		key.c libcrypto.c log.c message.c \
		prf.c sa.c sysdep.c timer.c transport.c virtual.c udp.c \
		ui.c util.c x509.c \
		pf_key_v2.c policy.c ike_aggressive.c isakmp_cfg.c \
		dpd.c monitor.c monitor_fdpass.c nat_traversal.c udp_encap.c \
		vendor.c dummies.c



#C_OPT  += -w -Wstrict-prototypes -Wmissing-prototypes \
#		-Wmissing-declarations   -I

C_OPT  += -w  -Wcomment -I

vpath %.c $$(PRG_DIR)
