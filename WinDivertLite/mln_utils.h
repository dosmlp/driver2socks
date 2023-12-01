
/*
 * Copyright (C) Niklaus F.Schen.
 */
#ifndef __MLN_DEFS_H
#define __MLN_DEFS_H

#ifdef __DEBUG__
#include <assert.h>
#define ASSERT(x) assert(x)
#else
#define ASSERT(x);
#endif

/*
 * container_of and offsetof
 */
#define mln_offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#define mln_container_of(ptr, type, member) ({\
    type *__rptr = NULL;\
    if ((ptr) != NULL) {\
        __rptr = (type *)((char *)((const typeof(((type *)0)->member) *)(ptr)) - mln_offsetof(type, member));\
    }\
    __rptr;\
})

/*
 * nonnull attribute
 */
#define __NONNULL1(x)
#define __NONNULL2(x,y)
#define __NONNULL3(x,y,z)
#define __NONNULL4(w,x,y,z)
#define __NONNULL5(v,w,x,y,z)



/*
 * Chain
 */
#define MLN_CHAIN_FUNC_DECLARE(prefix,type,ret_attr,func_attr); \
    ret_attr prefix##_chain_add(type **head, type **tail, type *node) func_attr;\
    ret_attr prefix##_chain_del(type **head, type **tail, type *node) func_attr;

#define MLN_CHAIN_FUNC_DEFINE(prefix,type,ret_attr,prev_ptr,next_ptr); \
    ret_attr prefix##_chain_add(type **head, type **tail, type *node) \
    {\
        if (head == NULL || tail == NULL || node == NULL) return;\
        node->prev_ptr = node->next_ptr = NULL;\
        if (*head == NULL) {\
            *head = *tail = node;\
            return ;\
        }\
        (*tail)->next_ptr = node;\
        node->prev_ptr = (*tail);\
        *tail = node;\
    }\
    \
    ret_attr prefix##_chain_del(type **head, type **tail, type *node) \
    {\
        if (head == NULL || tail == NULL || node == NULL) return;\
        if (*head == node) {\
            if (*tail == node) {\
                *head = *tail = NULL;\
            } else {\
                *head = node->next_ptr;\
                (*head)->prev_ptr = NULL;\
            }\
        } else {\
            if (*tail == node) {\
                *tail = node->prev_ptr;\
                (*tail)->next_ptr = NULL;\
            } else {\
                node->prev_ptr->next_ptr = node->next_ptr;\
                node->next_ptr->prev_ptr = node->prev_ptr;\
            }\
        }\
        node->prev_ptr = node->next_ptr = NULL;\
    }

#define mln_bigendian_encode(num,buf,Blen); \
{\
    size_t i;\
    for (i = 0; i < Blen; ++i) {\
        *(buf)++ = ((mln_u64_t)(num) >> ((Blen-i-1) << 3)) & 0xff;\
    }\
}

#define mln_bigendian_decode(num,buf,Blen); \
{\
    size_t i;\
    num = 0;\
    for (i = 0; i < Blen; ++i, ++buf) {\
        num |= ((((mln_u64_t)(*(buf))) & 0xff) << (((Blen)-i-1) << 3));\
    }\
}

#if defined(WIN32)
extern int pipe(int fds[2]);
extern int socketpair(int domain, int type, int protocol, int sv[2]);
#define mln_socket_close closesocket
#else
#define mln_socket_close close
#endif

#define MLN_AUTHOR "Niklaus F.Schen"

#endif

