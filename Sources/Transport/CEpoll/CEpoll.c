//
//  CEpoll.c
//  CEpoll
//
//  Translation-unit anchor for the otherwise header-only ``CEpoll`` shim — the module's interface is the
//  umbrella header, which re-exports <sys/epoll.h>. The file-scope typedef keeps the translation unit
//  non-empty (valid C, no `-Wempty-translation-unit`) without exporting any symbol.
//

#include "include/CEpoll.h"

typedef int CEpollModuleAnchor;
