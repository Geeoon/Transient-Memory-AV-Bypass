#include <stdio.h>  // printf
#include <stdlib.h>  // malloc and free
#include <string.h>  // memcpy, memset
#include <sys/mman.h>  // mmap, mumap
#include <errno.h>  // erno

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
 * @param url the URL of the shellcode
 * @return the size of the shellcode
 */
size_t get_shellcode(void** shellcode, const char* url) {
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

	size_t size = sizeof(hello_code) - 1;  // content-length;
	(*shellcode) = malloc(size);  // allocate memory to store shellcode

	// copy shellcode to allocated memory
	memcpy(*shellcode, hello_code, size);	
	// memset(*shellcode, 0xc3, size);
	// (*((char **)shellcode))[0] = '\x90';
	return size;
}

int main(int argc, const char** argv) {
	void* shellcode = NULL;
	size_t shellcode_size = get_shellcode(&shellcode, "http://localhost:3000/test.bin");

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
