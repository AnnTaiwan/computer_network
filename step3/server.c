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
#include <sys/wait.h>
#include <errno.h>
#define MAX_PENDING_CONNECTIONS 5
#define BUFFER_SIZE 1024
#define STRING_SIZE 256
#define PACKET_LOSS_MEAN 10e-2
int RTT = 30;       		// ms
int MSS = 1024; 		 	// 1 Kbytes
int THRESHOLD = 65536; 		// 64 Kbytes
int RBUFFER_SZIE = 524288; 	// 512 Kbytes
int cwnd = 1024, rwnd=32768;

uint16_t SERVER_PORT = 0;
struct TCP_segment seg1, seg2, seg3; // receive, send, receive

// Function to simulate packet loss
int simulate_packet_loss() {
    double rand_value = (double)rand() / RAND_MAX;
    return rand_value < PACKET_LOSS_MEAN;
}

int receive_ack(int client_fd, char *str)
{
	// Set a timeout for the acknowledgment 
	struct timeval tv; 
	tv.tv_sec = 0; 
	tv.tv_usec = RTT * 1000; // RTT in milliseconds 
	
	if (setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) { 
		perror("setsockopt failed"); 
		return -1;
	} 
	// receive seg3 
	if (recv(client_fd, &seg3, sizeof(seg3), 0) < 0) { 
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			// Timeout occurred, retransmit the segment
			printf("**Timeout: Retransmitting SEQ=%d\n", seg2.sequence_num);
			if (send(client_fd, &seg2, sizeof(seg2), 0) < 0) {
				perror("retransmit send failed");
				return -1;
			}
			printf("\t(#)Retransmitted a packet : %s => SEQ=%d : ACK=%d\n", str, seg2.sequence_num, seg2.acknowledgment);
									
			// Receive acknowledgment again
			if (recv(client_fd, &seg3, sizeof(seg3), 0) < 0) {
				perror("retransmit recv failed");
				return -1;
			}
		} 
		else {
			perror("recv failed");
			return -1;
		}
	}
	return 0;
}
void handle_client(int client_fd, int server_fd, struct sockaddr_in client_addr, struct sockaddr_in server_addr);
void transport_file(char* name, int client_fd, int server_fd);
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

void handle_file_transfer(int client_fd, int server_fd) {
    // Receive file name from client
    char *file_name = seg1.data;
    printf("Start to send the file %s\n", file_name);
    transport_file(file_name, client_fd, server_fd);
}


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
    
    // receive seg3 and retransmit if happening time_out situation
    int re = receive_ack(client_fd, "PCH-ACK");
    if(re < 0) {
    	perror("receive failed, expecting ACK");
        close(client_fd);
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    if (seg3.flags & ACK_FLAG) {
            printf("\t(3)Receive packet : ACK => SEQ=%d : ACK=%d\n", seg3.sequence_num, seg3.acknowledgment);
        } else {
            printf("Unexpected packet flags: %d\n", seg3.flags);
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
    // receive seg3 and retransmit if happening time_out situation
    int re = receive_ack(client_fd, "PCH-ACK");
    if(re < 0) {
    	perror("receive failed, expecting ACK");
        close(client_fd);
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    if (seg3.flags & ACK_FLAG) {
            printf("\t(3)Receive packet : ACK => SEQ=%d : ACK=%d\n", seg3.sequence_num, seg3.acknowledgment);
        } else {
            printf("Unexpected packet flags: %d\n", seg3.flags);
            
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
    
    // Create a socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
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
    
    while (1) {
        // Accept
        if ((client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len)) < 0) {
            perror("accept failed");
            close(server_fd);
            exit(EXIT_FAILURE);
        }

        // Fork to handle multiple clients
        pid_t pid = fork(); // create a new process for each client connection,
        if (pid < 0) {
            perror("fork failed");
            close(client_fd);
            close(server_fd);
            exit(EXIT_FAILURE);
        }

        if (pid == 0) { // Child process
            close(server_fd); // Close the listening socket in the child process because it does not need to accept new connections.
            handle_client(client_fd, server_fd, client_addr, server_addr);
            printf("(delete client)\n");
            exit(0);
        } else { // Parent process
            close(client_fd); // Close the client socket in the parent process
        }
    }

    close(server_fd);
    
    
    return 0;
}

void handle_client(int client_fd, int server_fd, struct sockaddr_in client_addr, struct sockaddr_in server_addr)
{
    // Print client's address information
    printf("=========================\n");
    printf("(Add new client)\n");
	printf("Info:\nClient's IP address: %s\n", inet_ntoa(client_addr.sin_addr));
	printf("Client's port: %d\n", ntohs(client_addr.sin_port));
	printf("=========================\n");

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
		// receive seg3 and retransmit if happening time_out situation
		int re = receive_ack(client_fd, "SYN-ACK");
		if(re < 0) {
			perror("recv failed");
		    close(client_fd);
		    close(server_fd);
		    exit(EXIT_FAILURE);
		}
        if (seg3.flags & ACK_FLAG) {
            printf("\t(3)Receive packet : ACK from %s : %hu : SYN => SEQ=%d : ACK=%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), seg3.sequence_num, seg3.acknowledgment);
            
        } else {
            printf("Unexpected packet flags: %d\n", seg3.flags);

        }
    }
    
	printf("(Three-way handshake completed.)\n");
    // Connection established, further communication can be done here
	
	while (1) {
    	recv(client_fd, &seg1, sizeof(seg1), 0);
    	if(seg1.flags & FIN_FLAG)
    	{
    		printf("(Disconnecting...)\n");
    		printf("\t(1)Receive packet : FIN => SEQ=%d : ACK=%d\n", seg1.sequence_num, seg1.acknowledgment);
    		printf("(Disconnected)\n");
    		break;
    	}
    	if (strstr(seg1.data, ".txt") != NULL || strstr(seg1.data, ".mp4") != NULL || strstr(seg1.data, ".jpg") != NULL) {
    		printf("(Start to handle query from %s : %hu.)\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
		    handle_file_transfer(client_fd, server_fd);
		}
		else if(strstr(seg1.data, ".") != NULL){ // dns query
			printf("(Start to handle query from %s : %hu.)\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
			handle_dns_query(client_fd, server_fd);
		}
		else if(seg1.data[strlen(seg1.data)-1] == 'c'){ // calculation
			printf("(Start to handle query from %s : %hu.)\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
			seg1.data[strlen(seg1.data)-1] = '\0'; // delete the 'c' in the end
			handle_calculation(client_fd, server_fd);
		}
    	
    	
		
    }
	
    // Close connection
    close(client_fd);
}
void transport_file(char* name, int client_fd, int server_fd)
{
	FILE *fp = fopen(name,"r");
	if(fp==NULL) 
		printf("File:%s Not Found.\n",name);
	else
	{
		printf("#######slow start#######\n");
    	int len=0,seq=1;
    	int count = 0;
    
		while(1)
		{
			
			if(cwnd>32768) 
				cwnd=32768;
        	printf("cwnd = %d, rwnd = %d, threshold = %d \n",cwnd, rwnd ,THRESHOLD);
        	int temp=cwnd;	
			if(cwnd>1024) //when cwnd > 1024, cut cwnd into segment, and every segment's size is 1 MSS
			{
				while (temp>0)
				{
					printf("\tSend a packet at %d byte\n",seq);
					memset(seg2.data, 0, sizeof(seg2.data));
					if((len = fread(seg2.data, sizeof(char), MSS, fp))>0)
					{
						
						seg2.src_port = SERVER_PORT;
						seg2.dst_port = seg3.src_port;
						if(count == 0)
						{
							seg2.sequence_num = seg1.acknowledgment;
							seg2.acknowledgment = seg1.sequence_num+1+strlen(seg1.data);
							count++;
						}
						else
						{
							seg2.sequence_num = seg3.acknowledgment;
							seg2.acknowledgment = seg3.sequence_num+1+strlen(seg3.data);
						}
						//strcpy(seg2.data, data);
						set_flag(&seg2, PSH_FLAG);
						set_flag(&seg2, ACK_FLAG);
						seq+=len;
						// Simulate packet loss
						if (simulate_packet_loss()) {
							printf("**Packet loss: SEQ=%d : ACK=%d\n", seg2.sequence_num, seg2.acknowledgment);
							seg2.checksum = 1; // indicate bad packet
						}
						else 
							seg2.checksum = 0;
        				// send packet
						if (send(client_fd, &seg2, sizeof(seg2), 0) < 0) {
							perror("send failed");
							close(client_fd);
							close(server_fd);
							exit(EXIT_FAILURE);
						}
						printf("\t(1)Send a packet : PCH-ACK => SEQ=%d : ACK=%d\n", seg2.sequence_num, seg2.acknowledgment);
						
						// receive seg3 and retransmit if happening time_out situation
						int re = receive_ack(client_fd, "PCH-ACK");
						if(re < 0) {
							perror("receive failed, expecting ACK");
							close(client_fd);
							close(server_fd);
							exit(EXIT_FAILURE);
						}

						if (seg3.flags & ACK_FLAG) {
							printf("\t(2)Receive packet : ACK => SEQ=%d : ACK=%d\n", seg3.sequence_num, seg3.acknowledgment);
							if(rwnd-MSS<0) 
			            		rwnd+=32768-MSS;
			            	else 
			            		rwnd-=MSS;
						} 
						else {
							printf("After receiving SEQ=%d : ACK=%d. Unexpected packet flags: %d\n", seg3.sequence_num, seg3.acknowledgment, seg3.flags);
						}
						
						temp-=MSS;
					}
					else
					{
		        			initialize_tcp_segment(&seg2);
							seg2.src_port = SERVER_PORT;
							seg2.dst_port = seg3.src_port;
							if(count == 0)
							{
								seg2.sequence_num = seg1.acknowledgment;
								seg2.acknowledgment = seg1.sequence_num+1+strlen(seg1.data);
								count++;
							}
							else
							{
								seg2.sequence_num = seg3.acknowledgment;
								seg2.acknowledgment = seg3.sequence_num+1+strlen(seg3.data);
							}
							strcpy(seg2.data, "FINISH");
							char temp[20];
 							sprintf(temp, "%d", seq - 1); // turn seq-1 into string and saved in temp
 							strcat(seg2.data, temp); // cat temp in the end of seg2.data
							set_flag(&seg2, PSH_FLAG);
							set_flag(&seg2, ACK_FLAG);
							send(client_fd, &seg2, sizeof(seg2), 0);
							printf("file successfully transmit\n");
		        			return;
					}
				}
				cwnd += MSS;
			}
			else if (cwnd<=1024)
			{
				printf("\tSend a packet at %d byte\n",seq);
				//initialize_tcp_segment(&seg2);
				memset(seg2.data, 0, sizeof(seg2.data));
				if((len = fread(seg2.data, sizeof(char), cwnd, fp))>0)
				{
						seg2.src_port = SERVER_PORT;
						seg2.dst_port = seg3.src_port;
						if(count == 0)
						{
							seg2.sequence_num = seg1.acknowledgment;
							seg2.acknowledgment = seg1.sequence_num+1+strlen(seg1.data);
							count++;
						}
						else
						{
							seg2.sequence_num = seg3.acknowledgment;
							seg2.acknowledgment = seg3.sequence_num+1+strlen(seg3.data);
						}
						//strcpy(seg2.data, data);
						set_flag(&seg2, PSH_FLAG);
						set_flag(&seg2, ACK_FLAG);
						seq+=len;
						// Simulate packet loss
						if (simulate_packet_loss()) {
							printf("**Packet loss: SEQ=%d : ACK=%d\n", seg2.sequence_num, seg2.acknowledgment);
							seg2.checksum = 1; // indicate bad packet
						}
						else 
							seg2.checksum = 0;
							
						if (send(client_fd, &seg2, sizeof(seg2), 0) < 0) {
							perror("send failed");
							close(client_fd);
							close(server_fd);
							exit(EXIT_FAILURE);
						}
						printf("\t(1)Send a packet : PCH-ACK => SEQ=%d : ACK=%d\n", seg2.sequence_num, seg2.acknowledgment);
						
						
						// receive seg3 and retransmit if happening time_out situation
						int re = receive_ack(client_fd, "PCH-ACK");
						if(re < 0) {
							perror("receive failed, expecting ACK");
							close(client_fd);
							close(server_fd);
							exit(EXIT_FAILURE);
						}

						if (seg3.flags & ACK_FLAG) {
							printf("\t(2)Receive packet : ACK => SEQ=%d : ACK=%d\n", seg3.sequence_num, seg3.acknowledgment);
							if(rwnd-cwnd<0) 
		            			rwnd+=32768-cwnd;
		            		else 
		            			rwnd-=cwnd;
						} 
						else {
							printf("After receiving SEQ=%d : ACK=%d. Unexpected packet flags: %d\n", seg3.sequence_num, seg3.acknowledgment, seg3.flags);
							
						}
					
					
					cwnd += MSS;
				}
	        	else
	        	{
		        	initialize_tcp_segment(&seg2);
					seg2.src_port = SERVER_PORT;
					seg2.dst_port = seg3.src_port;
					if(count == 0)
					{
						seg2.sequence_num = seg1.acknowledgment;
						seg2.acknowledgment = seg1.sequence_num+1+strlen(seg1.data);
						count++;
					}
					else
					{
						seg2.sequence_num = seg3.acknowledgment;
						seg2.acknowledgment = seg3.sequence_num+1+strlen(seg3.data);
					}
					strcpy(seg2.data, "FINISH");
					char temp[20];
					sprintf(temp, "%d", seq - 1); // turn seq-1 into string and saved in temp
					strcat(seg2.data, temp); // cat temp in the end of seg2.data
					set_flag(&seg2, PSH_FLAG);
					set_flag(&seg2, ACK_FLAG);
		        	send(client_fd, &seg2, sizeof(seg2), 0);
		        	printf("file successfully transmit\n");
		        	return;
		       	}
			}
	        	else
	        	{
	        		initialize_tcp_segment(&seg2);
					seg2.src_port = SERVER_PORT;
					seg2.dst_port = seg3.src_port;
					if(count == 0)
					{
						seg2.sequence_num = seg1.acknowledgment;
						seg2.acknowledgment = seg1.sequence_num+1+strlen(seg1.data);
						count++;
					}
					else
					{
						seg2.sequence_num = seg3.acknowledgment;
						seg2.acknowledgment = seg3.sequence_num+1+strlen(seg3.data);
					}
					strcpy(seg2.data, "FINISH");
					char temp[20];
 					sprintf(temp, "%d", seq - 1); // turn seq-1 into string and saved in temp
					strcat(seg2.data, temp); // cat temp in the end of seg2.data
					set_flag(&seg2, PSH_FLAG);
					set_flag(&seg2, ACK_FLAG);
		        	send(client_fd, &seg2, sizeof(seg2), 0);
		        	printf("file successfully transmit\n");
	        		fclose(fp);
	        		return;
	        	}
		}
	}
	
}
