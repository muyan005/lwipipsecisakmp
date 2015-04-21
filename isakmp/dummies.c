/**
 * \brief  Dummy functions
 * \author Josef Soentgen
 * \date   2014-05-19
 */

/*
 * Copyright (C) 2014 Genode Labs GmbH
 *
 * This file is part of the Genode OS framework, which is distributed
 * under the terms of the GNU General Public License version 2.
 */

/* Genode includes */
#include <stdio.h>

typedef long DUMMY;

enum {
	SHOW_DUMMY = 1,
};

#define DUMMY(retval, name) \
DUMMY name(void) { \
	if (SHOW_DUMMY) \
		fprintf(stderr, #name " called (from %p) not implemented", __builtin_return_address(0)); \
	return retval; \
}





DUMMY(-1, sendmsg)
DUMMY(-1, getifaddrs)
DUMMY(-1, freeifaddrs)
DUMMY(-1,setresgid)
DUMMY(-1,setresuid) /*
DUMMY(-1,setservent)
DUMMY(-1,getprotobyname)
DUMMY(-1,setprotoent)*/

int _sigaction()   { return -1; }
int  getpid()      { return -1; }
