/*
   p0f - API query code
   --------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#define _FROM_API

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "types.h"
#include "config.h"
#include "debug.h"
#include "alloc-inl.h"
#include "p0f.h"
#include "api.h"
#include "process.h"
#include "readfp.h"
#include "tcp.h"

/* Process API queries. */

void handle_query(struct p0f_api_query* q, struct p0f_api_response* r, u32* response_len) {

  struct host_data* h;

  memset(r, 0, sizeof(struct p0f_api_response));

  r->magic = P0F_RESP_MAGIC;
  *response_len = sizeof(struct p0f_api_response) - sizeof r->sig_buffer;

  if (q->magic != P0F_QUERY_MAGIC4 && q->magic != P0F_QUERY_MAGIC6) {

    WARN("Query with bad magic (0x%x).", q->magic);

    r->status = P0F_STATUS_BADQUERY;

    return;

  }

  u8 ip_ver = q->magic == P0F_QUERY_MAGIC4 ? IP_VER4 : IP_VER6;
  h = lookup_host(q->addr, q->port, ip_ver);

  if (!h) {
    if (debug_file)
      DEBUGF("af %s/%d\n", addr_to_str(q->addr, ip_ver), q->port);

    r->status = P0F_STATUS_NOMATCH;
    return;
  }

  touch_host(h, 0);

  r->status = P0F_STATUS_OK;

  u32 buf_offset = 0;

  if (sizeof r->sig_buffer - buf_offset >= h->raw_tcp_sig_len) {
    r->raw_tcp_sig_len = h->raw_tcp_sig_len;
    memcpy(&r->sig_buffer[buf_offset], h->raw_tcp_sig, h->raw_tcp_sig_len);
    buf_offset += h->raw_tcp_sig_len;
  }

  if (sizeof r->sig_buffer - buf_offset >= h->raw_ssl_sig_len) {
    r->raw_ssl_sig_len = h->raw_ssl_sig_len;
    memcpy(&r->sig_buffer[buf_offset], h->raw_ssl_sig, h->raw_ssl_sig_len);
    buf_offset += h->raw_ssl_sig_len;
  }

  *response_len += buf_offset;

/*  r->bad_sw      = h->bad_sw;
  r->last_nat    = h->last_nat;
  r->last_chg    = h->last_chg;
  r->up_mod_days = h->up_mod_days;
  r->distance    = h->distance;
  r->os_match_q  = h->last_quality;

  if (h->last_up_min != -1) r->uptime_min = h->last_up_min;*/

}
