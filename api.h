/*
   p0f - API query code
   --------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef _HAVE_API_H
#define _HAVE_API_H

#include "types.h"

#define P0F_QUERY_MAGIC4     0x50304604
#define P0F_QUERY_MAGIC6     0x50304606
#define P0F_RESP_MAGIC       0x50304605

#define P0F_STATUS_BADQUERY  0x00
#define P0F_STATUS_OK        0x10
#define P0F_STATUS_NOMATCH   0x20

#define P0F_STR_MAX          31

#define P0F_MATCH_FUZZY      0x01
#define P0F_MATCH_GENERIC    0x02

/* Keep these structures aligned to avoid architecture-specific padding. */

struct p0f_api_query {

  u32 magic;                            /* Must be P0F_QUERY_MAGIC4 or P0F_QUERY_MAGIC6 */
  u8  addr[16];                         /* IP address (big endian left align) */
  u16 port;                             /* Source port                        */

} __attribute__((packed));

struct p0f_api_response {

  u32 magic;                            /* Must be P0F_RESP_MAGIC             */
  u32 status;                           /* P0F_STATUS_*                       */

  u8 raw_syn_sig[24];                   /* First 24 bytes of *host_data.last_syn */

} __attribute__((packed));

#ifdef _FROM_P0F

void handle_query(struct p0f_api_query* q, struct p0f_api_response* r);

#endif /* _FROM_API */

#endif /* !_HAVE_API_H */
