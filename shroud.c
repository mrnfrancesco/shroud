/*
    Shroud - Proof of concept of a false-positive-based anti SYN scan
    Copyright (C) 2017 Francesco Marano (@mrnfrancesco)
 
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <libnet.h>
#include <pcap/pcap.h>

#include <inttypes.h>
#include <err.h>


#ifndef __GNUC__
#  define  __attribute__(x)
#endif

struct packet_handler_args {
    libnet_t *l;
    libnet_ptag_t ipv4_tag;
    libnet_ptag_t tcp_tag;
};



static void packet_handler(u_char *user_args, const struct pcap_pkthdr *cap_header, const u_char *packet);
static void exit_with_error(pcap_t *pcap_handle, libnet_t *l, const char *err_buff) __attribute__((noreturn));

static int get_tcp_open_ports(uint16_t *port_lst);


int main(void) {

    const char * const device = "lo";

#ifdef DEBUG
    printf("Using device: \"%s\"\n", device);
#endif

    int port_cnt;
    uint16_t port_lst[65535] = {0};
    if ((port_cnt = get_tcp_open_ports(port_lst)) == -1) {
        exit_with_error(NULL, NULL, "Unable to get open ports");
    }

#ifdef DEBUG
    printf("Discovered open ports (%d): [ ", port_cnt);
    for (int i = 0; i < port_cnt; ++i) {
        printf("%hu ", port_lst[i]);
    }
    printf("]\n");
#endif

    /* Init libnet with raw IPv4 socket */
    char libnet_err_buff[LIBNET_ERRBUF_SIZE];
    libnet_t *l = libnet_init(LIBNET_RAW4, device, libnet_err_buff);
    if (l == NULL) {
        exit_with_error(NULL, NULL, libnet_err_buff);
    }

    /* Enable device to sniff traffic */
    char pcap_err_buff[PCAP_ERRBUF_SIZE] = { 0 };
    pcap_t *pcap_handle = pcap_open_live(
            libnet_getdevice(l),    /* device name */
            1500,                   /* snapshot length */
            0,                      /* non-promiscuous mode */
            2000,                   /* read timeout (ms) */
            pcap_err_buff           /* error buffer */
    );
    if (pcap_handle == NULL) {
        exit_with_error(NULL, l, pcap_err_buff);
    }
    if (strlen(pcap_err_buff) != 0) {
        fprintf(stderr, "[WARN] pcap: %s\n", pcap_err_buff);
    }

    /* Finds the IPv4 network number and netmask */
    bpf_u_int32 netp, maskp; /* netmask and ip address */
    if (pcap_lookupnet(device, &netp, &maskp, pcap_err_buff) == -1) {
        exit_with_error(pcap_handle, l, pcap_err_buff);
    }

    /* Compiles filter expression to speed-up execution */
    struct bpf_program fp;
    const char * const base_filter = ""
        "(not src and dst host 0.0.0.0) and "
        "(tcp[tcpflags] & tcp-syn != 0) and "
        "(tcp[tcpflags] & tcp-ack = 0)";

    const char * const port_exclude_fmt = " and (not dst port %h"PRIu16")";

    char * filter = calloc(strlen(base_filter) + (port_cnt * 26), sizeof(char));
    if (filter == NULL) {
        exit_with_error(pcap_handle, l, "Cannot allocate enough memory for filter string");
    }
    strncpy(filter, base_filter, strlen(base_filter));
    for(int i = 0; i < port_cnt; ++i) {
        snprintf(filter + strlen(filter), 26, port_exclude_fmt, port_lst[i]);
    }

#ifdef DEBUG
    printf("Applying filter: \"%s\"\n", filter);
#endif
    if (pcap_compile(pcap_handle, &fp, filter, 1, maskp) == -1) {
        exit_with_error(pcap_handle, l, pcap_geterr(pcap_handle));
    }

    /* Applies filter expression */
    if (pcap_setfilter(pcap_handle, &fp) == -1) {
        exit_with_error(pcap_handle, l, pcap_geterr(pcap_handle));
    }

    /* Free BPF program and filter */
    pcap_freecode(&fp);

    /* Seeds the pseudo-random number generator */
    if (libnet_seed_prand(l) == -1) {
        exit_with_error(pcap_handle, l, "Cannot seeds the pseudo-random number generator");
    }

    struct packet_handler_args args = {
        .l = l,
        .ipv4_tag = 0,
        .tcp_tag = 0
    };

#ifdef DEBUG
    puts("Waiting for incoming SYN packets...\n");
#endif

    /* Process packets from a filtered live capture */
    if (pcap_loop(pcap_handle, 0, packet_handler, (u_char *) &args) == -1) {
        exit_with_error(pcap_handle, l, pcap_geterr(pcap_handle));
    }

    /* Shuts down the libnet session */
    pcap_close(pcap_handle);
    libnet_destroy(l);
    exit(EXIT_SUCCESS);
}



static void packet_handler(u_char *user_args, const struct pcap_pkthdr *cap_header, const u_char *packet) {

    struct packet_handler_args *args = (struct packet_handler_args *) user_args;

    libnet_t *l = args->l;
    struct libnet_ipv4_hdr *ip = (struct libnet_ipv4_hdr *)(packet + LIBNET_ETH_H);
    struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr *)((u_char *)ip + (ip->ip_hl << 2));

#ifdef DEBUG
    printf(
        "%s:%"PRIu16" > %s:%"PRIu16"\t[seq: %"PRIu32"\tack: %"PRIu32"]\n",
        libnet_addr2name4(ip->ip_src.s_addr, LIBNET_DONT_RESOLVE),
        ntohs(tcp->th_sport),
        libnet_addr2name4(ip->ip_dst.s_addr, LIBNET_DONT_RESOLVE),
        ntohs(tcp->th_dport),
        ntohl(tcp->th_seq), ntohl(tcp->th_ack)
    );
#endif

    /* Build SYN-ACK response */
    libnet_ptag_t tcp_tag, ipv4_tag;

    tcp_tag = libnet_build_tcp(
            htons(tcp->th_dport),                       /* source port */
            htons(tcp->th_sport),                       /* destination port */
            libnet_get_prand(LIBNET_PRu32),             /* sequence number */
            htonl((tcp->th_seq) + 1),                   /* acknowledgement number */
            TH_SYN | TH_ACK,                            /* control flags */
            (uint16_t) libnet_get_prand(LIBNET_PRu16),  /* window size */
            0,                                          /* checksum */
            0,                                          /* urgent pointer */
            LIBNET_TCP_H,                               /* total length of the TCP packet */
            NULL,                                       /* payload */
            0,                                          /* payload length */
            l,                                          /* pointer to a libnet context */
            args->tcp_tag                               /* protocol tag */
    );

    if (tcp_tag == -1) {
        fprintf(stderr, "[ERR] Unable to build TCP header: %s\n", libnet_geterror(l));
    } else {
        args->tcp_tag = tcp_tag;
    }

    ipv4_tag = libnet_build_ipv4(
            LIBNET_IPV4_H + LIBNET_TCP_H,               /* total length of the IP packet */
            0,                                          /* type of service bits */
            (uint16_t) libnet_get_prand(LIBNET_PRu16),  /* IP identification number */
            0,                                          /* fragmentation bits and offset */
            (uint8_t) libnet_get_prand(LIBNET_PR8),     /* time to live in the network */
            IPPROTO_TCP,                                /* upper layer protocol */
            0,                                          /* checksum */
            ip->ip_dst.s_addr,                          /* source IPv4 address */
            ip->ip_src.s_addr,                          /* destination IPv4 address */
            NULL,                                       /* payload */
            0,                                          /* payload length */
            l,                                          /* pointer to a libnet context */
            args->ipv4_tag                              /* protocol tag */
    );

    if (ipv4_tag == -1) {
        fprintf(stderr, "[ERR] Unable to build IPv4 header: %s\n", libnet_geterror(l));
    } else {
        args->ipv4_tag = ipv4_tag;
    }

    if (libnet_write(l) == -1) {
        fprintf(stderr, "[ERR] Unable to send packet: %s\n", libnet_geterror(l));
    }
}



static void exit_with_error(pcap_t *pcap_handle, libnet_t *l, const char *err_buff) {
    if (pcap_handle != NULL) {
        pcap_close(pcap_handle);
    }
    if (l != NULL) {
        libnet_destroy(l);
    }

    errx(EXIT_FAILURE, "%s", (err_buff != NULL && strlen(err_buff) != 0) ? err_buff : "Unknown error");
}


static int get_tcp_open_ports(uint16_t *port_lst) {
    FILE *fp = NULL;
    if ((fp = fopen("/proc/net/tcp", "r")) == NULL) {
        return EXIT_FAILURE;
    }

    /*
     * Line format example is the following:
     * sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
     * 0: 0100007F:1B1E 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 30575 1 ffff88021a2c8000 99 0 0 10 0
     */
    char line[256];

    /* Skip header */
    if (fgets(line, sizeof(line), fp) == NULL) {
        return EXIT_FAILURE;
    }

    uint16_t port_cnt = 0;

    while (fgets(line, sizeof(line), fp) != NULL) {
        size_t n = strlen(line);
        if (n == 0 || line[n-1] != '\n') {
            return EXIT_FAILURE;
        }
        line[n-1] = 0;

        char *tmp = NULL;
        uint16_t lport, rport;

        /* Ignore first colon */
        if ((tmp = strchr(line, ':')) == NULL) { continue; }

        /* Retrieve local port */
        if ((tmp = strchr(tmp + 2, ':')) == NULL) { continue; }
        sscanf(tmp + 1, "%hx", &lport);

        /* Retrieve remote port */
        if ((tmp = strchr(tmp + 2, ':')) == NULL) { continue; }
        sscanf(tmp + 1, "%hx", &rport);

        if (rport == 0) {
            port_lst[port_cnt++] = lport;
        }
    }

    return port_cnt;
}
