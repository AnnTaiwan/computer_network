#ifndef TCP_H
#define TCP_H
#include <stdint.h>
#include <stddef.h>
#define TCP_OPT_MAX 40 // Maximum length for TCP options
#define MAX_DATA_SIZE 1024*2

#define URG_FLAG 0x20 // 00100000
#define ACK_FLAG 0x10 // 00010000
#define PSH_FLAG 0x08 // 00001000
#define RST_FLAG 0x04 // 00000100
#define SYN_FLAG 0x02 // 00000010
#define FIN_FLAG 0x01 // 00000001
struct TCP_segment {
    uint16_t src_port;          // Source Port (16 bits)
    uint16_t dst_port;          // Destination Port (16 bits)
    uint32_t sequence_num;      // Sequence Number (32 bits)
    uint32_t acknowledgment;    // Acknowledgment Number (32 bits)
    uint8_t hdr_len : 4;        // Header Length (4 bits)
    uint8_t reserved : 6;       // Reserved (6 bits)
    uint8_t flags : 6;          // Flags (6 bits)
    uint16_t advertised_window; // Window Size (16 bits)
    uint16_t checksum;          // Checksum (16 bits)
    uint16_t urgent_pointer;    // Urgent Pointer (16 bits)
    uint8_t options[TCP_OPT_MAX]; // Options (Variable length, up to 40 bytes)
    char data[MAX_DATA_SIZE];     // Data (Variable length)
};

void initialize_tcp_segment(struct TCP_segment *segment);
void set_flag(struct TCP_segment *segment, uint8_t flag);
void clear_flag(struct TCP_segment *segment, uint8_t flag);
#endif
