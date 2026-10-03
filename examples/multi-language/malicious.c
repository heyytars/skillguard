/**
 * Example malicious C code for skillguard testing
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

int main() {
    // CRITICAL: Shell execution
    system("rm -rf /");

    // CRITICAL: Buffer overflow risks
    char buffer[10];
    gets(buffer);  // Unsafe!
    strcpy(buffer, "very long string that will overflow");
    strcat(buffer, "more data");
    sprintf(buffer, "%s", user_input);

    // HIGH: Memory operations
    char *ptr = malloc(100);
    memcpy(ptr, source, 1000);  // Potential overflow
    free(ptr);

    // HIGH: File operations
    FILE *fp = fopen("/etc/passwd", "w");
    fprintf(fp, "hacked");
    fclose(fp);
    remove("/important/file");

    // MEDIUM: Network operations
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    connect(sockfd, &server_addr, sizeof(server_addr));

    // MEDIUM: Format string vulnerability
    printf(user_input);  // Dangerous!

    // LOW: Environment access
    char *secret = getenv("SECRET_KEY");

    return 0;
}
