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

#define PORT 12000 
 
int padding = RSA_PKCS1_PADDING;
AES_KEY *expanded;

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

int public_encrypt(unsigned char *data, int data_len, unsigned char *key,
                   unsigned char *encrypted)
{
  RSA *rsa = createRSA(key, 1);
  int result = RSA_public_encrypt(data_len, data, encrypted, rsa, padding);
  return result;
}

/**
 * Set a read timeout.
 *
 * @param sk Socket.
 * @return True if successful.
 */
static bool SetReadTimeout(const int sk)
{
  struct timeval tv;
  tv.tv_sec = 5;
  tv.tv_usec = 0;
  if (setsockopt(sk, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
  {
    printf("unable to set read timeout\n");
    return false;
  }

  return true;
}

/**
 * Read n bytes.
 *
 * @param sk Socket.
 * @param buf Buffer.
 * @param n Number of bytes to read.
 * @return True if successful.
 */
static bool ReadBytes(const int sk, char *buf, const size_t n)
{
  char *ptr = buf;
  while (ptr < buf + n)
  {
    if (!SetReadTimeout(sk))
    {
      return false;
    }

    int ret = recv(sk, ptr, ptr - buf + n, 0);
    if (ret <= 0)
    {
      //LOG(ERROR) << "unable to receive on socket";
      return false;
    }

    ptr += ret;
  }

  return true;
}

/**
 * Write n bytes.
 *
 * @param sk Socket.
 * @param buf Buffer.
 * @param n Number of bytes to write.
 * @return True if successful.
 */
static bool WriteBytes(const int sk, const char *buf, const size_t n)
{
  char *ptr = buf;
  while (ptr < buf + n)
  {
    int ret = send(sk, ptr, n - (ptr - buf), 0);
    if (ret <= 0)
    {
      printf("unable to send on socket\n");
      return false;
    }

    ptr += ret;
  }

  return true;
}

int main(int argc, char const *argv[]) 
{ 
    int sock = 0; 
    struct sockaddr_in serv_addr;  
    char message[1024] = {0}; 
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    { 
        printf("\n Socket creation error \n"); 
        return -1; 
    } 
   
    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_port = htons(PORT); 
       
    // Convert IPv4 and IPv6 addresses from text to binary form 
    if(inet_pton(AF_INET, "129.10.61.129", &serv_addr.sin_addr)<=0)  
    { 
        printf("\nInvalid address/ Address not supported \n"); 
        return -1; 
    } 
   
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
    { 
        printf("\nConnection Failed \n"); 
        return -1; 
    } 

    int messageSize;

    if (!ReadBytes(sock, &messageSize, 4))
    {
    printf("unable to read response message size\n");
    return -1;
    }
    
    printf("message size: %d\n", messageSize);
    
    if (!ReadBytes(sock, message, messageSize))
    {
    printf("unable to read data from server\n");
    return -1;
    }
 
    printf("message %s\n", message); 

    unsigned char key[16];
    for (int i = 0; i < 16; i++)
    {
	    key[i] = "w";
    }

    unsigned char aesEncryptedKey[512]; 
    public_encrypt(key, sizeof(key), message, aesEncryptedKey);

    printf("KEY ");
    for (int i = 0; i < 512; i++) {
        printf("%d ", key[i]);
    }
    printf("\n");

    printf("ENCRYPTED KEY ");
    for (int i = 0; i < 512; i++) {
        printf("%d ", aesEncryptedKey[i]);
    }
    printf("\n");

    int sizeOfAesEncrypted = 512;
    WriteBytes(sock, &sizeOfAesEncrypted, sizeof(sizeOfAesEncrypted));
    WriteBytes(sock, &aesEncryptedKey, sizeOfAesEncrypted);

    unsigned char serverData[16];
    if(!ReadBytes(sock, serverData, sizeof(serverData))) {
        printf("ERROR reading data from server");
        return -1;
    }

    unsigned char decryptedServerData[16];
    expanded = (AES_KEY *)malloc(sizeof(AES_KEY));
    AES_set_decrypt_key(key, 128, expanded);
    AES_decrypt(serverData, decryptedServerData, expanded);

    printf("decrypted server data: "); 
    for (int i = 0; i < 16; i++) {
    printf("%c ", decryptedServerData[i]);
    }
    printf("\n");

    FILE *f = fopen("secret.txt", "w");
    for (int i = 0; i < 16; i++) {
    	fprintf(f, "%d ", decryptedServerData[i]);
    }
    close(f);
    free(expanded);   
    return 0; 
} 
