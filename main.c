#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <time.h>
#include <sys/resource.h>

static char **host_list = NULL;
static size_t host_list_size = 0;
static u_int32_t verdict = NF_ACCEPT;

static int cmp_host(const void *a, const void *b) {
    const char * const *sa = a;
    const char * const *sb = b;
    return strcmp(*sa, *sb);
}

static void load_host_list(const char *fname) {
    FILE *fp = fopen(fname, "r");
    if (!fp) { perror("fopen"); exit(1); }

    size_t cap = 100000;
    host_list = malloc(cap * sizeof(char*));
    if (!host_list) { perror("malloc"); exit(1); }

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char *comma = strchr(line, ',');
        if (!comma) continue;
        *comma = '\0';
        char *host = comma + 1;
        char *nl = strpbrk(host, "\r\n");
        if (nl) *nl = '\0';
        if (host_list_size >= cap) {
            cap *= 2;
            host_list = realloc(host_list, cap * sizeof(char*));
            if (!host_list) { perror("realloc"); exit(1); }
        }
        host_list[host_list_size++] = strdup(host);
    }
    fclose(fp);

    qsort(host_list, host_list_size, sizeof(char*), cmp_host);
}

static u_int32_t print_pkt(struct nfq_data *tb) {
    unsigned char *data;
    int ret = nfq_get_payload(tb, &data);
    if (ret >= 0) {
        u_int32_t iphdr_len  = (data[0] & 0x0F) * 4;
        u_int32_t tcphdr_len = ((data[iphdr_len + 12] & 0xF0) >> 4) * 4;
        unsigned char *http = data + iphdr_len + tcphdr_len;
        int http_len = ret - iphdr_len - tcphdr_len;

        if (http_len > 0) {
            char *p = strstr((char*)http, "Host: ");
            if (p) {
                p += 6;
                char *end = strpbrk(p, " \r\n");
                char tmp = end ? *end : '\0';
                if (end) *end = '\0';

                char *key = p;
                if (bsearch(&key, host_list, host_list_size, sizeof(char*), cmp_host)) {
                    printf("BLOCKED: %s\n", key);
                    verdict = NF_DROP;
                }

                if (end) *end = tmp;
            }
        }
    }
    u_int32_t id = 0;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(tb);
    if (ph) id = ntohl(ph->packet_id);
    return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data) {
    u_int32_t id = print_pkt(nfa);
    int ret = nfq_set_verdict(qh, id, verdict, 0, NULL);
    verdict = NF_ACCEPT;
    return ret;
}

void usage(void) {
    printf("syntax: netfilter-test <top-1m.csv>\n");
    printf("  CSV 포맷: rank,hostname (예: 1,google.com)\n");
}

int main(int argc, char **argv) {
    if (argc != 2) { usage(); return -1; }
    const char *listfile = argv[1];

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    load_host_list(listfile);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double ms = (t1.tv_sec - t0.tv_sec)*1000.0 + (t1.tv_nsec - t0.tv_nsec)/1e6;
    printf("Loaded %zu hosts in %.2f ms\n", host_list_size, ms);

    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    printf("Memory (max RSS) = %ld KB\n", ru.ru_maxrss);

    struct nfq_handle *h = nfq_open();
    if (!h) { fprintf(stderr, "nfq_open() error\n"); exit(1); }
    if (nfq_unbind_pf(h, AF_INET) < 0 ||
        nfq_bind_pf(h, AF_INET)   < 0) {
        fprintf(stderr, "nfq_bind_pf() error\n"); exit(1);
    }
    struct nfq_q_handle *qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) { fprintf(stderr, "nfq_create_queue() error\n"); exit(1); }
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "nfq_set_mode() error\n"); exit(1);
    }

    int fd = nfq_fd(h);
    char buf[4096] __attribute__ ((aligned));
    while (1) {
        int rv = recv(fd, buf, sizeof(buf), 0);
        if (rv >= 0) {
            nfq_handle_packet(h, buf, rv);
        } else if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        } else {
            perror("recv failed");
            break;
        }
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
    for (size_t i = 0; i < host_list_size; i++) free(host_list[i]);
    free(host_list);
    return 0;
}
