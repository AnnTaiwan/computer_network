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
uint16_t CLIENT_PORT = 0;
struct TCP_segment seg1, seg2, response;


//set a seg and response
void setSeg1(const char *command) {
    initialize_tcp_segment(&seg1);
    seg1.src_port = CLIENT_PORT;
    seg1.dst_port = SERVER_PORT;
    seg1.sequence_num = seg2.sequence_num;
    seg1.acknowledgment = seg2.acknowledgment;
    set_flag(&seg1, PSH_FLAG);
    strcpy(seg1.data, command);
}

void setSeg2() {
    initialize_tcp_segment(&seg2);
    seg2.src_port = CLIENT_PORT;
    seg2.dst_port = SERVER_PORT;
    seg2.sequence_num = response.acknowledgment;
    seg2.acknowledgment = response.sequence_num+1+strlen(response.data);
    set_flag(&seg2, ACK_FLAG);
}

void perform_file_transfer(char *name, int server_fd) {
	char buffer[BUFFER_SIZE*BUFFER_SIZE];
	memset(buffer, 0, sizeof(buffer));
	
    printf("Now, IN file_transfer: %s\n", name);
    setSeg1(name);
    // send seg1 PSH
	send(server_fd, &seg1, sizeof(seg1), 0);
	printf("\tSend packet : PSH => SEQ=%d : ACK=%d\n", seg1.sequence_num, seg1.acknowledgment);
	while(1)
	{
		// receive response
		recv(server_fd, &response, sizeof(response), 0);
		if (response.flags & PSH_FLAG && response.flags & ACK_FLAG) { // check the flags if ACK and PSH
		    //printf("(Received SYN-ACK packet...)\n");
		    printf("\tReceive packet : PSH-ACK => SEQ=%d : ACK=%d\n", response.sequence_num, response.acknowledgment);
		    if(strcmp(response.data, "FINISH") == 0) 
				break;
				
		    strcat(buffer, response.data);
		} else {
		    printf("Unexpected packet flags: %d\n", response.flags);
		    close(server_fd);
		    exit(EXIT_FAILURE);
		}
    
	
		// send seg2
		setSeg2();
		send(server_fd, &seg2, sizeof(seg2), 0);
		printf("\tSend packet : ACK => SEQ=%d : ACK=%d\n", seg2.sequence_num, seg2.acknowledgment);
		
	}
	// result
	printf("Result:\n");
	printf("%s\n", buffer);
}

void perform_dns_query(char *name, int server_fd){
	printf("Now, IN DNS query: %s\n", name);
	setSeg1(name);
	
	// send seg1 PSH
	send(server_fd, &seg1, sizeof(seg1), 0);
	printf("\t(1)Send packet : PSH => SEQ=%d : ACK=%d\n", seg1.sequence_num, seg1.acknowledgment);
	// receive response
	recv(server_fd, &response, sizeof(response), 0);
	
	if (response.flags & PSH_FLAG && response.flags & ACK_FLAG) { // check the flags if ACK and PSH
        //printf("(Received SYN-ACK packet...)\n");
        printf("\t(2)Receive packet : PSH-ACK => SEQ=%d : ACK=%d\n", response.sequence_num, response.acknowledgment);
        
    } else {
        printf("Unexpected packet flags: %d\n", response.flags);
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    
	
	// send seg2
	setSeg2();
	send(server_fd, &seg2, sizeof(seg2), 0);
	printf("\t(3)Send packet : ACK => SEQ=%d : ACK=%d\n", seg2.sequence_num, seg2.acknowledgment);
    
    // result
	printf("DNS result for %s: %s\n", name, response.data);
}
void perform_calculation(char *name, int server_fd){
	printf("\tNow, IN calculation: %s\n", name);
	setSeg1(name);
	// append a 'c' in the end of seg.data
	int len = strlen(seg1.data);
	seg1.data[len] = 'c';
	seg1.data[len+1] = '\0';
	
	
	// send seg1 PSH
	send(server_fd, &seg1, sizeof(seg1), 0);
	printf("\t(1)Send packet : PSH => SEQ=%d : ACK=%d\n", seg1.sequence_num, seg1.acknowledgment);
	// receive response
	recv(server_fd, &response, sizeof(response), 0);
	
	if (response.flags & PSH_FLAG && response.flags & ACK_FLAG) {
        //printf("(Received SYN-ACK packet...)\n");
        printf("\t(2)Receive packet : PSH-ACK => SEQ=%d : ACK=%d\n", response.sequence_num, response.acknowledgment);
        
    } else {
        printf("Unexpected packet flags: %d\n", response.flags);
        close(server_fd);
        exit(EXIT_FAILURE);
    }
	// result
	printf("Calculation result for %s =  %s\n", name, response.data);
	
	// send seg2
	setSeg2();
	send(server_fd, &seg2, sizeof(seg2), 0);
	printf("\t(3)Send packet : ACK => SEQ=%d : ACK=%d\n", seg2.sequence_num, seg2.acknowledgment);
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
    uint16_t CLIENT_PORT = (rand() % 1000) + 10000;
    
    initialize_tcp_segment(&seg1);
    initialize_tcp_segment(&seg2);
	initialize_tcp_segment(&response);
	
    // Send SYN
    seg1.src_port = CLIENT_PORT;
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
    seg2.src_port = CLIENT_PORT;
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
    int i, count_task = 1;
    for(i = 3; i < argc; i++)
    {
		
		printf("(task %d %s)\n", count_task, argv[i]);
		if (strstr(argv[i], ".txt") != NULL || strstr(argv[i], ".mp4") != NULL || strstr(argv[i], ".jpg") != NULL) {
		    perform_file_transfer(argv[i], sock);
		}
		else if(strstr(argv[i], ".") != NULL){
			perform_dns_query(argv[i], sock);
		}
		else if(strstr(argv[i], "cal") != NULL){
			if(i < argc-1)
			{
				i++;
				printf("(task %d %s)\n", count_task, argv[i]);
				perform_calculation(argv[i], sock);
			}
			else
			{
				perror("ARGUMENT IS LESS THAN REQUESTED. IT HAVE TO BE 'cal <EXPRESSION>'");
				close(sock);
				exit(EXIT_FAILURE);
			}
			
		}
		printf("(task %d end.)\n", count_task);
		count_task++;
   	}
   	printf("(Out of task.)\n");
   	// send seg1 PSH
 	setSeg1("NULL");
 	set_flag(&seg1, FIN_FLAG);
	send(sock, &seg1, sizeof(seg1), 0);
   	
   	
   	
	close(sock);

	return 0;
}
