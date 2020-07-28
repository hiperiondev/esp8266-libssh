#
# Component Makefile
#

COMPONENT_SRCDIRS := ./
COMPONENT_ADD_INCLUDEDIRS := ./ 
COMPONENT_PRIV_INCLUDEDIRS :=

CFLAGS += -DSSH_MALLOC\(a\)=pvPortMalloc\(a\)
CFLAGS += -DSSH_CALLOC\(a,b\)=pvPortCalloc\(a,b\)
CFLAGS += -DSSH_REALLOC\(a,b\)=pvPortRealloc\(a,b\)
CFLAGS += -DSSH_FREE\(a\)=vPortFree\(a\)