#include "tcp.h"
#include "cal.h"
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
int cwnd = 1, rwnd=32768;

uint16_t SERVER_PORT = 0;
struct TCP_segment seg1, seg2, seg3;
//set a command
struct TCP_segment setResponseSeg(int socket, const char *result, struct TCP_segment last_seg) {
    struct TCP_segment response;
    initialize_tcp_segment(&response);
    response.src_port = SERVER_PORT;
    response.dst_port = last_seg.src_port;
    response.sequence_num = last_seg.acknowledgment; // randomly choose one
    response.acknowledgment = seg1.sequence_num + 1;
    set_flag(&response, PSH_FLAG);

    strcpy(response.data, result);
    return response;
}

void setResponse(char *data)
{
	initialize_tcp_segment(&seg2);
    seg2.src_port = SERVER_PORT;
    seg2.dst_port = seg1.src_port;
    seg2.sequence_num = seg1.acknowledgment;
    seg2.acknowledgment = seg1.sequence_num+1+strlen(seg1.data);
    strcpy(seg2.data, data);
    set_flag(&seg2, PSH_FLAG);
    set_flag(&seg2, ACK_FLAG);
}
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

void handle_dns_query(int client_fd, int server_fd) {
	if ((seg1.flags & PSH_FLAG) == 0) 
	{
		perror("receive failed, expecting PCH");
        close(client_fd);
        close(server_fd);
        exit(EXIT_FAILURE);
    }

	printf("\t(1)Receive packet : PCH => SEQ=%d : ACK=%d\n", seg1.sequence_num, seg1.acknowledgment);
    printf("Do DNS_query: %s\n", seg1.data);
    
    struct addrinfo hints, *res, *p;
    int status;
    char ipstr[INET_ADDRSTRLEN]; // Buffer to store the IP address

    // Set up hints for getaddrinfo
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // Use AF_INET for IPv4
    hints.ai_socktype = SOCK_STREAM; // Use SOCK_STREAM for TCP

    // Resolve the network name (domain name) to IP address
    if ((status = getaddrinfo(seg1.data, NULL, &hints, &res)) != 0) {
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
    
    setResponse(ipstr); // set seg2
    if (send(client_fd, &seg2, sizeof(seg2), 0) < 0) {
            perror("send failed");
            close(client_fd);
            close(server_fd);
            exit(EXIT_FAILURE);
    }

    printf("\t(2)Send a packet : PCH-ACK => SEQ=%d : ACK=%d\n", seg2.sequence_num, seg2.acknowledgment);
    // receive seg3
    recv(client_fd, &seg3, sizeof(seg3), 0);
    if (seg3.flags & ACK_FLAG) {
            printf("\t(3)Receive packet : ACK => SEQ=%d : ACK=%d\n", seg3.sequence_num, seg3.acknowledgment);
        } else {
            printf("Unexpected packet flags: %d\n", seg3.flags);
            close(client_fd);
            close(server_fd);
            exit(EXIT_FAILURE);
        }
}

void handle_calculation(int client_fd, int server_fd) {
	if ((seg1.flags & PSH_FLAG) == 0) 
	{
		perror("receive failed, expecting PCH");
        close(client_fd);
        close(server_fd);
        exit(EXIT_FAILURE);
    }
	printf("\t(1)Receive packet : PCH => SEQ=%d : ACK=%d\n", seg1.sequence_num, seg1.acknowledgment);
    printf("Calculate %s\n", seg1.data);
    
    const char* expression = seg1.data;
    const char* expr_ptr = expression;  // Pointer to the expression for parsing
    double result = evaluate_expression(&expr_ptr);
    
    char result_str[50]; // to store result
    // turn double into string
    snprintf(result_str, sizeof(result_str), "%f", result);
    
    setResponse(result_str); // set seg2
    if (send(client_fd, &seg2, sizeof(seg2), 0) < 0) {
            perror("send failed");
            close(client_fd);
            close(server_fd);
            exit(EXIT_FAILURE);
    }
    printf("\t(2)Send a packet : PCH-ACK => SEQ=%d : ACK=%d\n", seg2.sequence_num, seg2.acknowledgment);
    // receive seg3
    recv(client_fd, &seg3, sizeof(seg3), 0);
    if (seg3.flags & ACK_FLAG) {
            printf("\t(3)Receive packet : ACK => SEQ=%d : ACK=%d\n", seg3.sequence_num, seg3.acknowledgment);
        } else {
            printf("Unexpected packet flags: %d\n", seg3.flags);
            close(client_fd);
            close(server_fd);
            exit(EXIT_FAILURE);
        }
	
    
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
    SERVER_PORT = atoi(argv[1]);
    printf("Server's port: %hu\n\n", SERVER_PORT);
    
    
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    
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
    server_addr.sin_port = htons(SERVER_PORT);
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
    printf("(Server is listening on port %d)\n", SERVER_PORT);
    
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
    printf("cwnd = %d, rwnd = %d, threshold = %d\n", cwnd, RBUFFER_SZIE, THRESHOLD);
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
            cwnd *= 2; // get an awk
        } else {
            printf("Unexpected packet flags: %d\n", seg3.flags);
            close(client_fd);
            close(server_fd);
            exit(EXIT_FAILURE);
        }
    }
    
	printf("(Three-way handshake completed.)\n");
    // Connection established, further communication can be done here
	printf("#########Slow start mode#########\n");
	while (1) {
		if(cwnd>32768) 
			cwnd=32768;
        printf("cwnd = %d, rwnd = %d, threshold = %d\n", cwnd, rwnd, THRESHOLD);
        int temp=cwnd;	//when cwnd > 1024(MSS), cut cwnd into segment, and every segment's size is 1 MSS
		if(cwnd > MSS)
		{
		
    	recv(client_fd, &seg1, sizeof(seg1), 0);
    	//printf("AAAname:%s\n", recv_command.data);
    	
    	if (strstr(seg1.data, ".txt") != NULL) {
		    //handle_file_transfer(client_socket);
		}
		else if(strstr(seg1.data, ".mp4") != NULL){
			//handle_file_transfer(client_socket);
		}
	   	else if(strstr(seg1.data, ".jpg") != NULL){
			//handle_math_calculation(client_socket);
		}
		else if(strstr(seg1.data, ".") != NULL){
			printf("(Start to handle query from %s : %hu.)\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
			handle_dns_query(client_fd, server_fd);
		}
		else if(seg1.data[strlen(seg1.data)-1] == 'c'){ // calculation
			printf("(Start to handle query from %s : %hu.)\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
			seg1.data[strlen(seg1.data)-1] = '\0'; // delete the 'c' in the end
			handle_calculation(client_fd, server_fd);
		}
    	
    	if (seg3.flags & ACK_FLAG) {// get an awk
    		if(cwnd < THRESHOLD)
            	cwnd *= 2; 
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
		
    }
	// Display the received result




    close(client_fd);
    close(server_fd);
    
    
    return 0;
}

