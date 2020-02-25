#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/aes.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>

AES_KEY *expanded;
uint8_t secret[16] = {
    0xb2, 0x01, 0x12, 0x93,
    0xe9, 0x55, 0x26, 0xa7,
    0xea, 0x69, 0x3a, 0xcb,
    0xfc, 0x7d, 0x0e, 0x1f};
uint64_t buf[1000000], timearray[1000000]; 

static __inline__ uint64_t timer_start(void)
{
  unsigned cycles_low, cycles_high;
  asm volatile("CPUID\n\t"
               "RDTSC\n\t"
               "mov %%edx, %0\n\t"
               "mov %%eax, %1\n\t"
               : "=r"(cycles_high), "=r"(cycles_low)::"%rax", "%rbx", "%rcx", "%rdx");
  return ((uint64_t)cycles_high << 32) | cycles_low;
}

static __inline__ uint64_t timer_stop(void)
{
  unsigned cycles_low, cycles_high;
  asm volatile("RDTSCP\n\t"
               "mov %%edx, %0\n\t"
               "mov %%eax, %1\n\t"
               "CPUID\n\t"
               : "=r"(cycles_high), "=r"(cycles_low)::"%rax",
                 "%rbx", "%rcx", "%rdx");
  return ((uint64_t)cycles_high << 32) | cycles_low;
}

int main()
{
	uint64_t t1, t2;
	expanded = (AES_KEY *)malloc(sizeof(AES_KEY));
	AES_set_encrypt_key(secret, 128, expanded);

	for(int i = 0; i < 1000000; i++) {
		t1 = timer_start();
		AES_encrypt(secret, buf, expanded);
		t2 = timer_stop();
		timearray[i] = t2 - t1;
	}

	FILE *f = fopen("aes.txt", "w");
	for (int i = 0; i < 1000000; i++) {
		fprintf(f, "%ld \n", timearray[i]);
	}
	close(f);
}
