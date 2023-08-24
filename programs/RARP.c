#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>

// ARP header structure
struct arp_header {
    unsigned short htype;
    unsigned short ptype;
    unsigned char hlen;
    unsigned char plen;
    unsigned short oper;
    unsigned char sha[6];
    unsigned char spa[4];
    unsigned char tha[6];
    unsigned char tpa[4];
};

int main() {
    int sockfd;
    struct arp_header arp;
    unsigned char src_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};  // Source MAC address
    unsigned char src_ip[4] = {192, 168, 1, 1};  // Source IP address

    // Create a raw socket
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd == -1) {
        perror("socket");
        exit(1);
    }

    // Fill ARP header
    arp.htype = htons(1);  // Ethernet
    arp.ptype = htons(ETH_P_IP);  // IPv4
    arp.hlen = 6;  // MAC address length
    arp.plen = 4;  // IP address length
    arp.oper = htons(1);  // ARP request
    memcpy(arp.sha, src_mac, 6);
    memcpy(arp.spa, src_ip, 4);
    memset(arp.tha, 0, 6);
    memset(arp.tpa, 0, 4);

    // Set destination address (broadcast MAC address)
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = htonl(INADDR_BROADCAST);

    // Send ARP request
    ssize_t bytes_sent = sendto(sockfd, &arp, sizeof(arp), 0, (struct sockaddr *)&dest, sizeof(dest));
    if (bytes_sent == -1) {
        perror("sendto");
        exit(1);
    }

    printf("ARP request sent!\n");

    close(sockfd);

    return 0;
}
