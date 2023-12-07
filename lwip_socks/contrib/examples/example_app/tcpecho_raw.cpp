/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
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
 * This file is part of and a contribution to the lwIP TCP/IP stack.
 *
 * Credits go to Adam Dunkels (and the current maintainers) of this software.
 *
 * Christiaan Simons rewrote this file to get a more stable echo example.
 */

/**
 * @file
 * TCP echo server example using raw API.
 *
 * Echos all bytes sent by connecting client,
 * and passively closes when client is done.
 *
 */

#include "lwip/opt.h"
#include "lwip/debug.h"
#include "lwip/stats.h"
#include "lwip/tcp.h"
#include "lwip/tcpip.h"
#include "async_simple/coro/Lazy.h"
#include "tcpecho_raw.h"
#include "common.h"
#include "iocontext.h"

#if LWIP_TCP && LWIP_CALLBACK_API

static struct tcp_pcb *tcpecho_raw_pcb;
std::unordered_map<void*, socks::socks_client*> map_sc;

enum tcpecho_raw_states
{
  ES_NONE = 0,
  ES_ACCEPTED,
  ES_RECEIVED,
  ES_CLOSING
};

struct tcpecho_raw_state
{
  u8_t state;
  u8_t retries;
  struct tcp_pcb *pcb;
  /* pbuf (chain) to recycle */
  struct pbuf *p;
};

static void
tcpecho_raw_free(struct tcpecho_raw_state *es)
{
  if (es != NULL) {
    if (es->p) {
      /* free the buffer chain if present */
      pbuf_free(es->p);
    }

    mem_free(es);
  }
}

static void
tcpecho_raw_close(struct tcp_pcb *tpcb)
{
    //tcp_arg(tpcb, NULL);
    tcp_sent(tpcb, NULL);
    tcp_recv(tpcb, NULL);
    tcp_err(tpcb, NULL);
    tcp_poll(tpcb, NULL, 0);

    //tcpecho_raw_free(es);

    tcp_close(tpcb);
}

static void
tcpecho_raw_send(struct tcp_pcb *tpcb, struct tcpecho_raw_state *es)
{
  struct pbuf *ptr;
  err_t wr_err = ERR_OK;

  while ((wr_err == ERR_OK) &&
         (es->p != NULL) &&
         (es->p->len <= tcp_sndbuf(tpcb))) {
    ptr = es->p;

    /* enqueue data for transmission */
    wr_err = tcp_write(tpcb, ptr->payload, ptr->len, 1);
    if (wr_err == ERR_OK) {
      u16_t plen;

      plen = ptr->len;
      /* continue with next pbuf in chain (if any) */
      es->p = ptr->next;
      if(es->p != NULL) {
        /* new reference! */
        pbuf_ref(es->p);
      }
      /* chop first pbuf from chain */
      pbuf_free(ptr);
      /* we can read more data now */
      tcp_recved(tpcb, plen);
    } else if(wr_err == ERR_MEM) {
      /* we are low on memory, try later / harder, defer to poll */
      es->p = ptr;
    } else {
      /* other problem ?? */
    }
  }
}

static void
tcpecho_raw_error(void *arg, err_t err)
{
    printf(__FUNCTION__);
    printf("\n");

  LWIP_UNUSED_ARG(err);


  //tcpecho_raw_free(es);
}

static err_t
tcpecho_raw_poll(void *arg, struct tcp_pcb *tpcb)
{
  err_t ret_err = ERR_OK;
  //if (tpcb->state == CLOSE_WAIT) {
      //tcp_shutdown(tpcb, 0, 1);
  //}
  return ret_err;
}

static err_t
tcpecho_raw_sent(void *arg, struct tcp_pcb *tpcb, u16_t len)
{
    printf(__FUNCTION__);
    printf("\n");
    return ERR_OK;
    /////
  struct tcpecho_raw_state *es;

  LWIP_UNUSED_ARG(len);

  es = (struct tcpecho_raw_state *)arg;
  es->retries = 0;

  if(es->p != NULL) {
    /* still got pbufs to send */
    tcp_sent(tpcb, tcpecho_raw_sent);
    tcpecho_raw_send(tpcb, es);
  } else {
    /* no more pbufs to send */
    if(es->state == ES_CLOSING) {
      tcpecho_raw_close(tpcb);
    }
  }
  return ERR_OK;
}

static err_t
tcpecho_raw_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
    if (p == NULL) {
        tcpecho_raw_close(tpcb);
    }
    else {
        uint8_t* d = new uint8_t[p->tot_len];
        pbuf2Data(p, d, p->tot_len);
        uint32_t ssize = async_simple::coro::syncAwait(map_sc[(void*)tpcb]->sendData(d, p->tot_len));
        delete[] d;
        printf("recv:%p\n", tpcb);
        tcp_recved(tpcb, p->tot_len);
        pbuf_free(p);
        tcp_write(tpcb, "rec", 4, 1);
    }
    return ERR_OK;
//////////////////////////////////
  struct tcpecho_raw_state *es;
  err_t ret_err;

  LWIP_ASSERT("arg != NULL",arg != NULL);
  es = (struct tcpecho_raw_state *)arg;
  if (p == NULL) {
    /* remote host closed connection */
    es->state = ES_CLOSING;
    if(es->p == NULL) {
      /* we're done sending, close it */
      tcpecho_raw_close(tpcb);
    } else {
      /* we're not done yet */
      tcpecho_raw_send(tpcb, es);
    }
    ret_err = ERR_OK;
  } else if(err != ERR_OK) {
    /* cleanup, for unknown reason */
    LWIP_ASSERT("no pbuf expected here", p == NULL);
    ret_err = err;
  }
  else if(es->state == ES_ACCEPTED) {
    /* first data chunk in p->payload */
    es->state = ES_RECEIVED;
    /* store reference to incoming pbuf (chain) */
    es->p = p;
    tcpecho_raw_send(tpcb, es);
    ret_err = ERR_OK;
  } else if (es->state == ES_RECEIVED) {
    /* read some more data */
    if(es->p == NULL) {
      es->p = p;
      tcpecho_raw_send(tpcb, es);
    } else {
      struct pbuf *ptr;

      /* chain pbufs to the end of what we recv'ed previously  */
      ptr = es->p;
      pbuf_cat(ptr,p);
    }
    ret_err = ERR_OK;
  } else {
    /* unknown es->state, trash data  */
    tcp_recved(tpcb, p->tot_len);
    pbuf_free(p);
    ret_err = ERR_OK;
  }
  return ret_err;
}
struct SendDataArg {
    uint8_t* data = nullptr;
    uint32_t len = 0;
    tcp_pcb* pcb = nullptr;
    void* msg = nullptr;
    SendDataArg(uint32_t len)
    {
        if (len > 0) {
            this->data = new uint8_t[len];
            this->len = len;
        }
    }
    ~SendDataArg()
    {
        if (data) delete[] data;
        if (msg) tcpip_callbackmsg_delete((struct tcpip_callback_msg*)msg);
    }
};
void callback_send(void* arg)
{
    SendDataArg* dataarg = (SendDataArg*)arg;
    if (dataarg->data != nullptr) {
        tcp_write(dataarg->pcb, dataarg->data, dataarg->len,1);
    } else {
        tcpecho_raw_close(dataarg->pcb);
        std::cout << "tcpecho_raw_close\n";
        socks::socks_client* sc = map_sc[dataarg->pcb];
        delete sc;
        map_sc.erase(dataarg->pcb);
    }
    
    delete dataarg;
}
static err_t
tcpecho_raw_accept(void *arg, struct tcp_pcb *newpcb, err_t err)
{
    if (newpcb == nullptr) {
        printf(__FUNCTION__":newpcb is null!\n");
        return ERR_ARG;
    }
    printf("accept:%p\n", newpcb);
    tcp_arg(newpcb, arg);
    err_t ret_err;

    /* 现在就设置其优先级。 当 pcb 用完时，可以中止低优先级的 pcb，以创建优先级更高的新 pcb。新的优先级更高的 pcb。*/
    tcp_setprio(newpcb, TCP_PRIO_MIN);


    /* pass newly allocated es to our callbacks */
    //tcp_arg(newpcb, es);
    tcp_recv(newpcb, tcpecho_raw_recv);
    tcp_err(newpcb, tcpecho_raw_error);
    tcp_poll(newpcb, tcpecho_raw_poll, 0);
    //对方主机已确认接收到数据的回调
    tcp_sent(newpcb, tcpecho_raw_sent);
    
    ret_err = ERR_OK;
    ConnectCtx* ctx = (ConnectCtx*)(((struct netif*)arg)->state);
    auto sc = new socks::socks_client(IoContext::getIoContext());
    map_sc.emplace(std::make_pair((void*)newpcb,sc));

    //char remote_ip[40] = { 0 };
    //WinDivertHelperFormatIPv4Address(ntohl(addr.Socket.RemoteAddr[0]), remote_ip, 40);
    std::string prxoy_ip = "127.0.0.1";
    std::string proxy_port = "7890";
    std::string rip = asio::ip::make_address_v4(ntohl(newpcb->local_ip.u_addr.ip4.addr)).to_string();
    std::string port = std::to_string(newpcb->local_port);
    sc->start_socks(prxoy_ip, proxy_port,
        rip, port, [](const asio::error_code& ec) {
            std::cout << "socks5 error:" << ec.message() << "\n";
        }).start([](async_simple::Try<void> Result) {
            if (Result.hasError()) {
                try {
                    std::rethrow_exception(Result.getException());
                }
                catch (const std::exception& e) {
                    std::cout << e.what() << "\n";
                }
            } else
                std::cout << "socks5 connect successfully.\n";
            });

    sc->ctx = newpcb;
    
    sc->asyncRead([](asio::error_code ec, uint8_t* data, uint32_t len,void* pcb){

        SendDataArg* arg = new SendDataArg(len);
        if (len <= 0 || ec || data == nullptr) {

        } else {
            memcpy(arg->data, data, len);
        }
        arg->pcb = (tcp_pcb*)pcb;
        struct tcpip_callback_msg* cb_msg = tcpip_callbackmsg_new(callback_send, arg);
        arg->msg = cb_msg;
        tcpip_callbackmsg_trycallback(cb_msg);
        }).start([](async_simple::Try<void> Result) {
            if (Result.hasError()) {
                try {
                    std::rethrow_exception(Result.getException());
                }
                catch (const std::exception& e) {
                    std::cout << e.what() << "\n";
                }
            } else
                std::cout << "asyncRead successfully.\n";
            });
    return ret_err;
}

void
tcpecho_raw_init(struct netif* net_if, uint32_t* dest_ip,uint16_t port,uint8_t is_ipv4)
{
    if (is_ipv4) {
        tcpecho_raw_pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
        
        if (tcpecho_raw_pcb != NULL) {
            tcpecho_raw_pcb->callback_arg = net_if;
            err_t err;
            ip_addr_t addr;
            addr.type = IPADDR_TYPE_V4;
            addr.u_addr.ip4.addr = dest_ip[0];
            err = tcp_bind(tcpecho_raw_pcb, &addr, port);
            if (err == ERR_OK) {
                tcpecho_raw_pcb = tcp_listen(tcpecho_raw_pcb);
                tcp_accept(tcpecho_raw_pcb, tcpecho_raw_accept);
            } else {
                /* abort? output diagnostic? */
            }
        } else {
            /* abort? output diagnostic? */
            printf("tcp_new_ip_type v4 null!\n");
        }
    } else {
        tcpecho_raw_pcb = tcp_new_ip_type(IPADDR_TYPE_V6);
        if (tcpecho_raw_pcb != NULL) {
            tcpecho_raw_pcb->callback_arg = net_if;
            err_t err;
            ip_addr_t addr;
            addr.type = IPADDR_TYPE_V6;
            MEMCPY(addr.u_addr.ip6.addr, dest_ip, sizeof(uint32_t) * 4);
            err = tcp_bind(tcpecho_raw_pcb, &addr, port);
            if (err == ERR_OK) {
                tcpecho_raw_pcb = tcp_listen(tcpecho_raw_pcb);
                tcp_accept(tcpecho_raw_pcb, tcpecho_raw_accept);
            } else {
                /* abort? output diagnostic? */
            }
        } else {
            /* abort? output diagnostic? */
            printf("tcp_new_ip_type v6 null!\n");
        }
    }

}

#endif /* LWIP_TCP && LWIP_CALLBACK_API */
