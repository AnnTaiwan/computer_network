#include "tcp.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <math.h>
#include <time.h>
#include <fcntl.h>


#define BUFFER_SIZE 1024

#define FILE_TRANSFER 1
#define MATH_CALCULATION 2
#define DNS_QUERY 3

#define TXT 1
#define MP4 2 
#define JPG 3
int RTT = 30;       		// ms
int MSS = 1024; 		 	// 1 Kbytes
int THRESHOLD = 65536; 		// 64 Kbytes
int RBUFFER_SZIE = 524288; 	// 512 Kbytes


uint16_t SERVER_PORT = 0;
struct TCP_segment seg1, seg2, response;


//set a command
struct TCP_segment setCommandSeg(int socket, const char *command) {
	printf("Set a command to get %s.\n", command);
    struct TCP_segment seg;
    initialize_tcp_segment(&seg);
    seg.src_port = 0;
    seg.dst_port = SERVER_PORT;
    seg.sequence_num = seg1.sequence_num+1;
    set_flag(&seg, PSH_FLAG);
    strcpy(seg.data, command);
    return seg;
}

void perform_file_transfer(int file_type, char *file_name, int server_socket) {
    // Send request type to server
    int request_type = FILE_TRANSFER;
    send(server_socket, &request_type, sizeof(request_type), 0);

    // Send file name to server
    //char file_name[256] = "example.txt";
    send(server_socket, file_name, sizeof(file_name), 0);

    // Receive file size from server
    int file_size;
    recv(server_socket, &file_size, sizeof(file_size), 0);

    // Receive and save the file contents
    FILE *file = fopen(file_name, "wb");
    if (file == NULL) {
        perror("File creation failed");
        return;
    }

    char buffer[1024];
    int bytes_received, total_bytes_received = 0;
    while (total_bytes_received < file_size) {
        bytes_received = recv(server_socket, buffer, sizeof(buffer), 0);
        fwrite(buffer, 1, bytes_received, file);
        total_bytes_received += bytes_received;
    }

    fclose(file);
}

void perform_dns_query(char *name, int server_fd){
	printf("\t(1)Now, IN DNS query: %s.\n", name);
    struct TCP_segment seg = setCommandSeg(server_fd, name);
	
	char ipstr[INET_ADDRSTRLEN]; // Buffer to store the IP address
	// send command
	send(server_fd, &seg, sizeof(seg), 0);

	// receive reesponse
	recv(server_fd, &ipstr, sizeof(ipstr), 0);
	
	// result
	printf("\t(2)DNS result for %s: %s\n", name, ipstr);
}

// Function to generate a random initial sequence number (ISN)
uint32_t generate_isn() {
    return rand() % 10000 + 1;
}

/*
argv[1] = ip
argv[2] = dest_port
*/
int main(int argc, char**argv) 
{
	if (argc < 3) {
        fprintf(stderr, "Usage: %s <server_ip> <server_port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    char *server_ip = argv[1];
    uint16_t server_port = atoi(argv[2]);
    SERVER_PORT = server_port;
    //char buffer[BUFFER_SIZE] = {0};
    // init status
	printf("Server's IP address: %s\n", server_ip);
	printf("Server's port: %hu\n\n", server_port);
	
	
	srand(time(NULL));  // Seed the random number generator
	//printf("%d, Argv1:%s, argv1:%s\n",argc,argv[2], argv[1]);
    
    //struct TCP_segment *segment = (struct TCP_segment *)malloc(sizeof(struct TCP_segment) + data_length);
	int sock;
    struct sockaddr_in server_addr;
	
	uint32_t client_isn = generate_isn();
    uint32_t server_isn;

	// Create a raw socket
    if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) { // int socket(int domain, int type, int protocol);
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    // Set socket options
    //int opt = 1;
   // if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
   //     perror("Error setting client socket options");
   //     exit(1);
  //  }
   
    // Fill server address structure
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);
    
    // Connect to server
    // start 3-way handshaking
    printf("(Start three-way handshake, connecting...)\n");
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect failed");
        close(sock);
        exit(EXIT_FAILURE);
    }
    // pich a client_port randomly
    uint16_t client_port = (rand() % 1000) + 10000;
    
    initialize_tcp_segment(&seg1);
    initialize_tcp_segment(&seg2);
	initialize_tcp_segment(&response);
	
    // Send SYN
    seg1.src_port = client_port;
    seg1.dst_port = server_port;
    seg1.sequence_num = client_isn;
    set_flag(&seg1, SYN_FLAG);
    //printf("(Sending SYN packet...)\n");
    if (send(sock, &seg1, sizeof(seg1), 0) < 0) {
        perror("send failed");
        close(sock);
        exit(EXIT_FAILURE);
    }
	printf("\t(1)Send packet : SYN => SEQ=%d : ACK=%d\n", seg1.sequence_num, seg1.acknowledgment);
    // Receive SYN-ACK
    if (recv(sock, &response, sizeof(response), 0) < 0) {
        perror("recv failed");
        close(sock);
        exit(EXIT_FAILURE);
    }
    
    if (response.flags & SYN_FLAG && response.flags & ACK_FLAG) {
        //printf("(Received SYN-ACK packet...)\n");
        printf("\t(2)Receive packet : SYN-ACK => SEQ=%d : ACK=%d\n", response.sequence_num, response.acknowledgment);
        server_isn = response.sequence_num;
    } else {
        printf("Unexpected packet flags: %d\n", response.flags);
        close(sock);
        exit(EXIT_FAILURE);
    }
	
    // Send ACK
    seg2.src_port = client_port;
    seg2.dst_port = server_port;
    seg2.sequence_num = client_isn + 1;
    seg2.acknowledgment = server_isn + 1;
    set_flag(&seg2, ACK_FLAG);
    //printf("(Sending ACK packet...)\n");
    if (send(sock, &seg2, sizeof(seg2), 0) < 0) {
        perror("send failed");
        close(sock);
        exit(EXIT_FAILURE);
    }
	printf("\t(3)Send packet : ACK => SEQ=%d : ACK=%d\n", seg2.sequence_num, seg2.acknowledgment);
    printf("(Three-way handshake completed.)\n");
    // tasks
    printf("(Requested tasks.)\n");
    int i;
    for(i = 3; i < argc; i++)
    {
		
		printf("(task%d %s)\n", i-3, argv[i]);
		if (strstr(argv[i], ".txt") != NULL) {
		    //perform_file_transfer(TXT);
		}
		else if(strstr(argv[i], ".mp4") != NULL){
			//perform_file_transfer(MP4);
		}
	   	else if(strstr(argv[i], ".jpg") != NULL){
			//perform_file_transfer(JPG);
		}
		else if(strstr(argv[i], ".") != NULL){
			perform_dns_query(argv[i], sock);
		}
   	}
	close(sock);

	return 0;
}
