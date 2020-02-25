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

int padding = RSA_PKCS1_PADDING;
uint64_t buf[1000000], timearray[1000000]; 

char publicKey[] = "-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAroyB+A4W/acwRq9gthl0\n"
"jb81nPHQ/s9lZNq0AEUnkWnOK+Rae+JoupsSeUehKYJQJkFYjnBc2aV8gSqxtY+b\n"
"r/XcIRSgk9ULUdELaak1WaYfjVEhyUgiQSXBa/QVsnSLMe4Hn6Mdx9J31y3/TLNp\n"
"AaB3Q37e9nfi3xT8K05govYbgV+j9z0zqJeJhS0D7aRzCc+MYDGlVuLpA0UDtjmA\n"
"KM0xD4e0U845qeUMqq7CdXt5mIiqFr7BL28F7zD9b5tqr407UEhsTESnkP9jfFJM\n"
"+t9+EKVUGmNTJMQPimRFot0ZGaTz4J4Jcnl3y0UhwwNqSVpnrOhAkzV+MhHmNOoc\n"
"wwIDAQAB\n"
                   "-----END PUBLIC KEY-----\n";

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

RSA *createRSA(unsigned char *key, int public)
{
  RSA *rsa = NULL;
  BIO *keybio;
  keybio = BIO_new_mem_buf(key, -1);
  if (keybio == NULL)
  {
    printf("Failed to create key BIO");
    return 0;
  }
  if (public)
  {
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
  }
  else
  {
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
  }
  if (rsa == NULL)
  {
    printf("Failed to create RSA");
  }

  return rsa;
}

int main()
{
	uint64_t t1, t2;
	RSA *rsa = createRSA(publicKey, 1);

	for(int i = 0; i < 1000000; i++) {
		t1 = timer_start();
		RSA_public_encrypt(16, "abcdefhijklmnop6", buf, rsa, padding);
		t2 = timer_stop();
		timearray[i] = t2 - t1;
	}
	
	FILE *f = fopen("rsa.txt", "w");
	for (int i = 0; i < 1000000; i++) {
		fprintf(f, "%ld\n", timearray[i]);
	}
	close(f);
}

