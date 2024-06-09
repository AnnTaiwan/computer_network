#include "tcp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>
#include <fcntl.h>
#include <netdb.h>
#define MAX_PENDING_CONNECTIONS 5
#define BUFFER_SIZE 1024
#define STRING_SIZE 256

#define FILE_TRANSFER 1
#define MATH_CALCULATION 2
#define DNS_QUERY 3

int RTT = 30;       		// ms
int MSS = 1024; 		 	// 1 Kbytes
int THRESHOLD = 65536; 		// 64 Kbytes
int RBUFFER_SZIE = 524288; 	// 512 Kbytes

/*
void handle_file_transfer(int client_fd) {
    // Receive file name from client
    char file_name[STRING_SIZE];
    recv(client_fd, file_name, sizeof(file_name), 0);

    // Open the file
    int file = open(file_name, O_RDONLY);
    if (file < 0) {
        perror("File not found");
        return;
    }

    // Get the file size
    struct stat file_stat;
    fstat(file, &file_stat);
    int file_size = file_stat.st_size;

    // Send the file size to client
    send(client_fd, &file_size, sizeof(file_size), 0);

    // Read and send the file contents in chunks
    char buffer[BUFFER_SIZE];
    int bytes_read;
    while ((bytes_read = read(file, buffer, sizeof(buffer))) > 0) {
        send(client_socket, buffer, bytes_read, 0);
    }

    // Close the file
    close(file);
}
*/

void handle_dns_query(int client_fd, struct TCP_segment* ptr_command) {
	printf("\t(1)Receive packet : PCH => SEQ=%d : ACK=%d\n", ptr_command->sequence_num, ptr_command->acknowledgment);
    printf("\t(2)DNS_query: %s\n", ptr_command->data);
    
    struct addrinfo hints, *res, *p;
    int status;
    char ipstr[INET_ADDRSTRLEN]; // Buffer to store the IP address

    // Set up hints for getaddrinfo
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // Use AF_INET for IPv4
    hints.ai_socktype = SOCK_STREAM; // Use SOCK_STREAM for TCP

    // Resolve the network name (domain name) to IP address
    if ((status = getaddrinfo(ptr_command->data, NULL, &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        exit(EXIT_FAILURE);
    }

    // Iterate over the results and get the IP address
    for (p = res; p != NULL; p = p->ai_next) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
        void *addr = &(ipv4->sin_addr);
        inet_ntop(p->ai_family, addr, ipstr, INET_ADDRSTRLEN);
    }

    // Free the memory allocated by getaddrinfo
    freeaddrinfo(res);
	printf("\t(3)Send IP address result to client.\n");
    // Send the IP address back to the client
    send(client_fd, ipstr, strlen(ipstr), 0);
    
}

// Function to generate a random initial sequence number (ISN)
uint32_t generate_isn() {
    return rand() % 10000 + 1;
}
int main(int argc, char**argv) 
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <server_port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    uint16_t server_port = atoi(argv[1]);
    printf("Server's port: %hu\n\n", server_port);
    
    
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    struct TCP_segment seg1, seg2, seg3;
	initialize_tcp_segment(&seg1);
    initialize_tcp_segment(&seg2);
	initialize_tcp_segment(&seg3);
	
    srand(time(NULL));  // Seed the random number generator
    
    /*
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};
    char *hello = "Hello from server";
 	*/
    // Create a socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }
	
	// Fill server address structure
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    
    // Bind the socket
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_fd, MAX_PENDING_CONNECTIONS) < 0) {
        perror("listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    printf("(Server is listening on port %d)\n", server_port);
    
    // Accept a connection
    if ((client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len)) < 0) { // use empty client_addr to accept the client info 
        perror("accept failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    
    // Print client's address information
	printf("Client's IP address: %s\n", inet_ntoa(client_addr.sin_addr));
	printf("Client's port: %d\n", ntohs(client_addr.sin_port));


    //printf("(Client connected)\n");
    printf("(Start three-way handshake, connecting...)\n");
    // Receive SYN
    if (recv(client_fd, &seg1, sizeof(seg1), 0) < 0) {
        perror("recv failed");
        close(client_fd);
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    if (seg1.flags & SYN_FLAG) {
        printf("\t(1)Receive packet : SYN from %s : %hu : SYN => SEQ=%d : ACK=%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), seg1.sequence_num, seg1.acknowledgment);

        // Send SYN-ACK
        uint32_t server_isn = generate_isn();
        initialize_tcp_segment(&seg2);
        seg2.src_port = ntohs(server_addr.sin_port);
        seg2.dst_port = seg1.src_port;
        seg2.sequence_num = server_isn; // randomly choose one
        seg2.acknowledgment = seg1.sequence_num + 1;
        set_flag(&seg2, SYN_FLAG);
        set_flag(&seg2, ACK_FLAG);

        if (send(client_fd, &seg2, sizeof(seg2), 0) < 0) {
            perror("send failed");
            close(client_fd);
            close(server_fd);
            exit(EXIT_FAILURE);
        }

        printf("\t(2)Send a packet : SYN-ACK to %s : %hu : SYN => SEQ=%d : ACK=%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), seg2.sequence_num, seg2.acknowledgment);

        // Receive ACK
        if (recv(client_fd, &seg3, sizeof(seg3), 0) < 0) {
            perror("recv failed");
            close(client_fd);
            close(server_fd);
            exit(EXIT_FAILURE);
        }

        if (seg3.flags & ACK_FLAG) {
            printf("\t(3)Receive packet : ACK from %s : %hu : SYN => SEQ=%d : ACK=%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), seg3.sequence_num, seg3.acknowledgment);
        } else {
            printf("Unexpected packet flags: %d\n", seg3.flags);
            close(client_fd);
            close(server_fd);
            exit(EXIT_FAILURE);
        }
    }
	printf("(Three-way handshake completed.)\n");
    // Connection established, further communication can be done here
	
	while (1) {
		struct TCP_segment recv_command;
    	recv(client_fd, &recv_command, sizeof(recv_command), 0);
    	//printf("AAAname:%s\n", recv_command.data);
    	
    	if (strstr(recv_command.data, ".txt") != NULL) {
		    //handle_file_transfer(client_socket);
		}
		else if(strstr(recv_command.data, ".mp4") != NULL){
			//handle_file_transfer(client_socket);
		}
	   	else if(strstr(recv_command.data, ".jpg") != NULL){
			//handle_math_calculation(client_socket);
		}
		else if(strstr(recv_command.data, ".") != NULL){
			printf("(Start to handle query from %s : %hu.)\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
			handle_dns_query(client_fd, &recv_command);
		}
		
    	
    	
		// Receive request type from client
		//int request_type;
		//recv(client_fd, &request_type, sizeof(request_type), 0);
/*
		if (request_type == FILE_TRANSFER) {
		    //handle_file_transfer(client_socket);
		} else if (request_type == MATH_CALCULATION) {
		    //handle_math_calculation(client_socket);
		} else if (request_type == DNS_QUERY) {
		    handle_dns_query(client_socket);
		}
*/
		// Close the client connection
		close(client_fd);
		break;
    }
	// Display the received result




    close(client_fd);
    close(server_fd);
    
    
    return 0;
}

