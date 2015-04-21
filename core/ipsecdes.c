/*
 * embedded IPsec	
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 */

/** @file des.c
 *  @brief code for DES and 3DES in CBC mode 
 *
 *  @author  Niklaus Schild <n.schild@gmx.ch> <BR>
 *
 *  <B>OUTLINE:</B>
 *	This module contains mainly code extracted from the libssl library.
 *  We use this code to implement a DES73DES-CBC.
 *
 *  <B>IMPLEMENTATION:</B>
 * 	"This product includes cryptographic software written by
 * 	Eric Young (eay@cryptsoft.com)" (taken form www.openssl.org)"
 *
 *  <B>NOTES:</B>
 *
 *
 * This document is part of <EM>embedded IPsec<BR>
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.<BR>
 * This file contains code from the OpenSSL Project<BR>
 * portions Copyright (c) 1998-2003 OpenSSL (www.openssl.org)
 *</EM><HR>
 */


#include <string.h>

#include "ipsec/ipsecdes.h"
#include "ipsec/debug.h"

	
/**
 * 3DES-CBC function calculates a digest from a given data buffer and a given key.
 *
 * @param text		pointer to input data
 * @param text_len	length of input data
 * @param key		pointer to encryption key (192 bits)
 * @param iv		initialization vector
 * @param mode		defines whether encryption or decryption should be performed
 * @param output	en- or decrypted input data
 * @return void
 *
 */
void cipher_3des_cbc(unsigned char* text, int text_len, 
                     unsigned char* key, unsigned char* iv, int mode, unsigned char*  output)
{
	int ret_val;
	DES_key_schedule ks1, ks2, ks3;

	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER, 
	              "cipher_3des_cbc", 
				  ("text=%p, text_len=%d, key=%p, iv=%p, mode=%d, output=%p",
			      (void *)text, text_len, (void *)key, (void *)iv, mode, (void *)output)
				 );
	
	
	ret_val = DES_set_key_checked((const_DES_cblock*)(key + 0*8), &ks1);
	if(ret_val != 0) {
		IPSEC_LOG_ERR("ipsec_esp_decapsulate", IPSEC_STATUS_BAD_KEY, ("DES_set_key_checked(&cbc1_key,&ks1) could not set 1st 3DES key - ret_val = %d\n", ret_val)) ;
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "cipher_3des_cbc", ("void") );
		return;
	}

	ret_val = DES_set_key_checked((const_DES_cblock*)(key + 1*8), &ks2);
	if(ret_val != 0) {
		IPSEC_LOG_ERR("ipsec_esp_decapsulate", IPSEC_STATUS_BAD_KEY, ("DES_set_key_checked(&cbc2_key,&ks2) could not set 2nd 3DES key - ret_val = %d\n", ret_val)) ;
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "cipher_3des_cbc", ("void") );
		return;
	}

	ret_val = DES_set_key_checked((const_DES_cblock*)(key + 2*8), &ks3);
	if(ret_val != 0) {
		IPSEC_LOG_ERR("ipsec_esp_decapsulate", IPSEC_STATUS_BAD_KEY, ("DES_set_key_checked(&cbc3_key,&ks3) could not set 3rd 3DES key - ret_val = %d\n", ret_val)) ;
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "cipher_3des_cbc", ("void") );
		return;
	}

	DES_ede3_cbc_encrypt(text, output, text_len, (DES_key_schedule *)&ks1 ,(DES_key_schedule *)&ks2, (DES_key_schedule *)&ks3, (DES_cblock*)iv, mode);

	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "cipher_3des_cbc", ("void") );
}

