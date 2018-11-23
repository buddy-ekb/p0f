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

#define P0F_RESP_MAGIC_HIT   0x50304610
#define P0F_RESP_MAGIC_MISS  0x50304620

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

  u32 magic;                            /* Must be P0F_RESP_MAGIC_HIT or P0F_RESP_MAGIC_MISS */

  u16 raw_tcp_sig_len;                  /* Text length of raw TCP signature   */
  u16 raw_ssl_sig_len;                  /* Text length of raw SSL signature   */

  u8  sig_buffer[1024];                 /* Buffer for text of signatures      */

} __attribute__((packed));

#ifdef _FROM_P0F

void handle_query(struct p0f_api_query* q, struct p0f_api_response* r, u32* response_len);

#endif /* _FROM_API */

#endif /* !_HAVE_API_H */
