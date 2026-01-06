// common.h
#ifndef __COMMON_H
#define __COMMON_H

struct lb_config {
    __u32 real_server_ip;     // 백엔드 IP
    __u32 lb_vip;             // 가상 IP (VIP)
    unsigned char src_mac[6]; // LB MAC
    unsigned char dst_mac[6]; // Gateway/Real MAC
};

#endif