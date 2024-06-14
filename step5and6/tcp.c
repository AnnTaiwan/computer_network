#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "tcp.h"




// Function to set a flag
void set_flag(struct TCP_segment *segment, uint8_t flag) {
    segment->flags |= flag;
}

// Function to clear a flag
void clear_flag(struct TCP_segment *segment, uint8_t flag) {
    segment->flags &= ~flag;
}

// Function to initialize a TCP segment
void initialize_tcp_segment(struct TCP_segment *segment) {
    segment->src_port = 12345;  // Example source port
    segment->dst_port = 80;     // Example destination port (HTTP)
    segment->sequence_num = rand() % 10000 + 1;  // Random sequence number between 1 and 10000
    segment->acknowledgment = 0;  // Placeholder, to be set by receiver
    segment->hdr_len = 5;  // Header length (5*4 = 20 bytes)
    segment->reserved = 0;
    segment->flags = 0;  // Placeholder for flags
    segment->advertised_window = 65535;  // Max window size
    segment->checksum = 0;  // Placeholder for checksum
    segment->urgent_pointer = 0;
    memset(segment->options, 0, TCP_OPT_MAX);  // Zero out options

    // Assuming data is provided by the caller
    memset(segment->data, 0, MAX_DATA_SIZE);  // Initialize data to zeros
}

