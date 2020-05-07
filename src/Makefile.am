AM_CFLAGS=	-Wall -Wextra -pedantic -Wshadow -Wpointer-arith -Wcast-align
AM_CFLAGS+=	-Wwrite-strings -Wmissing-prototypes -Wmissing-declarations
AM_CFLAGS+=	-Wnested-externs -Winline -Wno-long-long  -Wunused-variable
AM_CFLAGS+=	-Wstrict-prototypes -Werror
AM_LDFLAGS=	-L.
CC=		clang

lib_LTLIBRARIES = libschannel.la
nobase_include_HEADERS = schannel.h  schtypes.h

libschannel_la_SOURCES = schn_init.c	schn_unwrap.c	schn_util.c	schn_wrap.c
