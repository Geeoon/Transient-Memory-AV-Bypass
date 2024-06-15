#include <stdio.h>  // printf
#include <stdlib.h>  // malloc and free
#include <string.h>  // memcpy, memset
#include <sys/mman.h>  // mmap, mumap
#include <errno.h>  // erno
#include <inttypes.h>  // strtoumax
#include <math.h>  // fmin

#define REQUEST_BUFFER 1024
#define MAX_HEADER_BUFFER 64
#define MAX_BINARY_BUFFER 65536
#define MAX_RESPONSE_BUFFER 73728  //  extra 8192 bytes for headers

/**
 * Get the value of an HTTP header.
 * @param headers a string containing the entire http headers without the body.
 * @param header the header to look for (ex. "Content-Length").
 * 			Length cannot be greater than MAX_HEADER_BUFFER (64)
 * @param value where the result should be stored.
 * 			Buffer length shuold equal to the max parameter.
 * 			Will always be null terminated
 * @param max max number of characters to read, including the null terminator.
 * @return 0 indicating success, or -1 if failed
 */
int get_http_header(char* headers, char* header, char* value, size_t max) {
	max--;  // make room for the null terminator
	char delimeter[MAX_HEADER_BUFFER + 5];
	snprintf(delimeter, MAX_HEADER_BUFFER + 5, "\r\n%s: ", header);  // add newline and color space to header delim

	char* value_start = NULL;
	if ((value_start = strstr(headers, delimeter)) == NULL) return -1;  // get the start of the header, check if failed
	value_start += strlen(delimeter) * sizeof(char);  // modify to the start of the value
	
	int value_length = 0;
	if ((value_length = strcspn(value_start, "\r")) == strlen(value_start)) return -1;  // set value_length, and check if failed

	if (max > value_length) max = value_length;  // make sure only "max" characters are copied
	memcpy(value, value_start, max);
	value[max] = '\0';

	return 0;
}

/**
 * Execute the shellcode
 * @param shellcode the memory address of the shellcode to be executed
 * @param size the size of the shellcode to be executed in bytes
 * @return 0 indicating success, or -1 if failed 
 */
int execute_shellcode(void* shellcode, size_t size) {
	// allocate executable memory
	void* executable_memory = 
		mmap(0, size, PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,
			-1, 0);
	if (errno == -1) return -1;

	// ensure read/write/execute permissions on memory
	mprotect(executable_memory, size, PROT_READ|PROT_WRITE|PROT_EXEC);
	if (errno == -1) return -1;

	// copy shellcode to executable memory
	memcpy(executable_memory, shellcode, size);

	// create shellcode function pointer
	int (*shellcode_func)() = (int (*)())executable_memory;

	// show shellcode function instructions
	for (size_t i = 0; i < size; i++) {
		printf("%dth byte: 0x%x\n", i, ((unsigned char*)shellcode_func)[i]);
	}

	// run shellcode and store return
	int return_code = shellcode_func();

	// deallocate executable memory
	munmap(executable_memory, size);
	if (errno == -1) return -1;

	return 0;
}

/**
 * Get shellcode from a source
 * @param shellcode pointer which will point to the heap allocated shellcode.
 * 		Must be free'd once done.
 * @param path the path of the shellcode on the HTTP server,
 * 					including the root (ex. /directry/directory2/file.bin)
 * @param host the host of the HTTP server (ex. https://<host>/)
 * @param port the port to send the HTTP request to
 * @return the size of the shellcode, or -1 on error.
 */
size_t get_shellcode(void** shellcode,
					 const char* path,
					 const char* host,
					 int port) {
	char hello_code[] = 
    "\xe9\x1e\x00\x00\x00"  //          jmp    (relative) <MESSAGE>
    "\xb8\x04\x00\x00\x00"  //          mov    $0x4,%eax
    "\xbb\x01\x00\x00\x00"  //          mov    $0x1,%ebx
    "\x59"                  //          pop    %ecx
    "\xba\x0f\x00\x00\x00"  //          mov    $0xf,%edx
    "\xcd\x80"              //          int    $0x80
    "\xb8\x01\x00\x00\x00"  //          mov    $0x1,%eax
    "\xbb\x00\x00\x00\x00"  //          mov    $0x0,%ebx
    "\xcd\x80"              //          int    $0x80
    "\xe8\xdd\xff\xff\xff"  //          call   (relative) <GOBACK>
    "Hello wolrd!\r\n";     // OR       "\x48\x65\x6c\x6c\x6f\x2c\x20\x57"
                            //          "\x6f\x72\x6c\x64\x21\x0d\x0a"

	// construct get request
	char http_request[REQUEST_BUFFER];
	if (snprintf(http_request, REQUEST_BUFFER, "GET %s HTTP/1.0\r\nHost: %s\r\n\r\n", path, host) > REQUEST_BUFFER - 1) return -1;

	// response buffer
	// char http_response[MAX_RESPONSE_BUFFER];  // NOTE: maybe don't store it in a string, the binary data may contains null terminators
	// memset(http_response, '\0', MAX_RESPONSE_BUFFER);


	// TODO: actually fetch the binary here
	// http://localhost:3000/test.bin

	char http_response[] = "HTTP/1.1 200 OK\r\nServer: python\r\nContent-Length: 4\r\n\r\nrandom data.";  // just for testing


	char content_length_string[6];
	if (get_http_header(http_response, "Content-Length", content_length_string, 6) == -1) return -1;

	char* endptr = NULL;
	size_t content_length = strtoumax(content_length_string, &endptr, 10);
	if (errno == ERANGE) return -1;  // content-length too large to store in size_t
	if (content_length > MAX_BINARY_BUFFER) return -1;  // response too large to store in buffer

	char shellcode_http[MAX_BINARY_BUFFER];
	memset(shellcode_http, 0x00, MAX_BINARY_BUFFER);


	// results in out of bound reads if the content-length is greater than the actual body
	char* beginning_of_binary = NULL;
	printf("%s\n", http_response);
	if ((beginning_of_binary = strstr(http_response, "\r\n\r\n")) == NULL) return -1;  // misformatted
	beginning_of_binary += 4 * sizeof(char);
	printf("%s\n", beginning_of_binary);

	size_t size = sizeof(hello_code) - 1;  // content-length
	(*shellcode) = malloc(size);  // allocate memory to store shellcode

	// copy shellcode to allocated memory
	memcpy(*shellcode, hello_code, size);	
	// memset(*shellcode, 0xc3, size);
	// (*((char **)shellcode))[0] = '\x90';
	return size;
}

int main(int argc, const char** argv) {
	void* shellcode = NULL;
	size_t shellcode_size = 0;
	if ((shellcode_size = get_shellcode(&shellcode, "/test.bin", "localhost", 3000)) == -1) {
		printf("Erorr getting shellcode.");
		return -1;
	}

	// test to show shellcode:
	// for (size_t i = 0; i < shellcode_size; i++) {
	// 	printf("%dth byte: 0x%x\n", i, ((unsigned char*)shellcode)[i]);
	// }

	int status = execute_shellcode(shellcode, shellcode_size);
	printf("Shellcode exit status: %d\n", status);

	// free allocated shellcode
	free(shellcode);
	return 0;
}
