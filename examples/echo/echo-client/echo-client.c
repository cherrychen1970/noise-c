/*
 * Copyright (C) 2016 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <noise/protocol.h>
#include "echo-common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <unistd.h>
//#include <getopt.h>
#include <fcntl.h>
#if defined(__WIN32__) || defined(WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
typedef int socklen_t;
typedef BOOL sockopt_type;
#define MSG_NOSIGNAL 0
#undef HAVE_POLL
#endif

/* Parsed command-line options */
static const char *client_private_key = "234D30626FA21534A56A7DDF825357DD3637E1BFBB8C4FB714BE935C8795655D";
static const char *server_public_key = "704A34B610576F037D44E53DF80D52B40307ECC04523DA06BE8599DB111B6523";
//Noise_KK_25519_ChaChaPoly_BLAKE2b
static const char *protocol = "Noise_KK_25519_ChaChaPoly_BLAKE2b";
static const char *hostname = "127.0.0.1";
static int port = 7001;
static int padding = 0;

/* Message buffer for send/receive */
#define MAX_MESSAGE_LEN 4096
static uint8_t message[MAX_MESSAGE_LEN + 2];

typedef struct
{
    NoiseHandshakeState *handshake;
    NoiseCipherState *send_cipher;
    NoiseCipherState *recv_cipher;
    EchoProtocolId id;
    NoiseBuffer mbuf;
} NoiseContext;

void hex2bytes(char *hexstring, char *bytearray, int length)
{
    for (size_t i = 0, j = 0; i < (length); i++, j += 2)
        bytearray[i] = (hexstring[j] % 32 + 9) % 25 * 16 + (hexstring[j + 1] % 32 + 9) % 25;
}

/* Initialize the handshake using command-line options */
static int initialize_handshake(NoiseHandshakeState *handshake, const void *prologue, size_t prologue_len)
{
    NoiseDHState *dh;
    uint8_t *key = 0;
    size_t key_len = 0;
    int err = NOISE_ERROR_NONE;

#if 0
    /* Set the prologue first */
    err = noise_handshakestate_set_prologue(handshake, prologue, prologue_len);
    if (err != NOISE_ERROR_NONE)
    {
        noise_perror("prologue", err);
        return 0;
    }
#endif
    /* Set the local keypair for the client */
    dh = noise_handshakestate_get_local_keypair_dh(handshake);
    key_len = noise_dhstate_get_private_key_length(dh);
    key = (uint8_t *)malloc(key_len);
    if (!key)
        return 0;

    hex2bytes(client_private_key, key, key_len);
    noise_dhstate_set_keypair_private(dh, key, key_len);
    noise_free(key, key_len);

    /* Set the remote public key for the server */
    dh = noise_handshakestate_get_remote_public_key_dh(handshake);
    key_len = noise_dhstate_get_public_key_length(dh);
    key = (uint8_t *)malloc(key_len);
    if (!key)
        return 0;

    hex2bytes(server_public_key, key, key_len);
    err = noise_dhstate_set_public_key(dh, key, key_len);
    noise_free(key, key_len);

    /* Ready to go */
    return 1;
}

int do_handshake(int fd, NoiseContext *ctx)
{
    //NoiseHandshakeState *handshake = ctx->handshake;
    //NoiseCipherState *send_cipher = 0;
    //NoiseCipherState *recv_cipher = 0;
    //NoiseRandState *rand = 0;
    NoiseBuffer mbuf;
    ;
    int err, ok;
    int action;
    ;
    size_t message_size;
    size_t max_line_len;

    /* Check that the echo protocol supports the handshake protocol.
       One-way handshake patterns and XXfallback are not yet supported. */
    if (!echo_get_protocol_id(&ctx->id, protocol))
    {
        fprintf(stderr, "%s: not supported by the echo protocol\n", protocol);
        return -1;
    }

    /* Create a HandshakeState object for the protocol */
    err = noise_handshakestate_new_by_name(&ctx->handshake, protocol, NOISE_ROLE_INITIATOR);
    if (err != NOISE_ERROR_NONE)
    {
        noise_perror(protocol, err);
        return err;
    }

    /* Set the handshake options and verify that everything we need
       has been supplied on the command-line. */
    if (!initialize_handshake(ctx->handshake, &ctx->id, sizeof(ctx->id)))
    {
        noise_handshakestate_free(ctx->handshake);
        return -1;
    }
    ok = 1;
#if 0
    /* Send the echo protocol identifier to the server */

    if (!echo_send(fd, (const uint8_t *)&ctx->id, sizeof(ctx->id)))
        ok = 0;
#endif
    /* Start the handshake */
    if (ok)
    {
        err = noise_handshakestate_start(ctx->handshake);
        if (err != NOISE_ERROR_NONE)
        {
            noise_perror("start handshake", err);
            ok = 0;
        }
    }

    /* Run the handshake until we run out of things to read or write */
    while (ok)
    {
        action = noise_handshakestate_get_action(ctx->handshake);
        if (action == NOISE_ACTION_WRITE_MESSAGE)
        {
#if 1
            /* Write the next handshake message with a zero-length payload */
            noise_buffer_set_output(mbuf, message, sizeof(message));
            err = noise_handshakestate_write_message(ctx->handshake, &mbuf, NULL);
            if (err != NOISE_ERROR_NONE)
            {
                noise_perror("write handshake", err);
                ok = 0;
                break;
            }

            if (!echo_send(fd, message, mbuf.size))
            {
                ok = 0;
                break;
            }
#else
            /* Write the next handshake message with a zero-length payload */
            noise_buffer_set_output(mbuf, message, sizeof(message));
            err = noise_handshakestate_write_message(ctx->handshake, &mbuf, NULL);
            if (err != NOISE_ERROR_NONE)
            {
                noise_perror("write handshake", err);
                ok = 0;
                break;
            }
            if (!tcp_send(fd, message, mbuf.size))
            {
                ok = 0;
                break;
            }
#endif
        }
        else if (action == NOISE_ACTION_READ_MESSAGE)
        {
            /* Read the next handshake message and discard the payload */
            message_size = echo_recv(fd, message, sizeof(message));
            printf("here %d",message_size);
            if (!message_size)
            {
                ok = 0;
                break;
            }
            noise_buffer_set_input(mbuf, message + 2, message_size - 2);
            err = noise_handshakestate_read_message(ctx->handshake, &mbuf, NULL);
            if (err != NOISE_ERROR_NONE)
            {
                noise_perror("read handshake", err);
                ok = 0;
                break;
            }
        }
        else
        {
            /* Either the handshake has finished or it has failed */
            break;
        }
    }

    /* If the action is not "split", then the handshake has failed */
    if (ok && noise_handshakestate_get_action(ctx->handshake) != NOISE_ACTION_SPLIT)
    {
        fprintf(stderr, "protocol handshake failed\n");
        ok = 0;
    }

    /* Split out the two CipherState objects for send and receive */
    if (ok)
    {
        err = noise_handshakestate_split(ctx->handshake, &ctx->send_cipher, &ctx->recv_cipher);
        if (err != NOISE_ERROR_NONE)
        {
            noise_perror("split to start data transfer", err);
            ok = 0;
        }
    }

    /* We no longer need the HandshakeState */
    noise_handshakestate_free(ctx->handshake);
    ctx->handshake = 0;

    /* If we will be padding messages, we will need a random number generator */
    if (ok && padding)
    {
        err = noise_randstate_new(&rand);
        if (err != NOISE_ERROR_NONE)
        {
            noise_perror("random number generator", err);
            ok = 0;
        }
    }

    /* Tell the user that the handshake has been successful */
    if (ok)
    {
        printf("%s handshake complete.  Enter text to be echoed ...\n", protocol);
    }
}

// socketFd
void echoService(int fd, NoiseContext *ctx)
{
    //NoiseHandshakeState *handshake;
    //NoiseCipherState *send_cipher = ctx->send_cipher;
    //NoiseCipherState *recv_cipher = ctx->recv_cipher;
    //NoiseRandState *rand = 0;
    NoiseBuffer mbuf;
    //EchoProtocolId id;
    int err, ok = 1;
    //int action;
    //int fd;
    size_t message_size;
    size_t max_line_len;

    /* Read lines from stdin, send to the server, and wait for echoes */
    max_line_len = sizeof(message) - 2 - noise_cipherstate_get_mac_length(ctx->send_cipher);
    while (ok && fgets((char *)(message + 2), max_line_len, stdin))
    {
        /* Pad the message to a uniform size */
        message_size = strlen((const char *)(message + 2));
        if (padding)
        {
            err = noise_randstate_pad(rand, message + 2, message_size, max_line_len,
                                      NOISE_PADDING_RANDOM);
            if (err != NOISE_ERROR_NONE)
            {
                noise_perror("pad", err);
                ok = 0;
                break;
            }
            message_size = max_line_len;
        }

        /* Encrypt the message and send it */
        noise_buffer_set_inout(mbuf, message + 2, message_size, sizeof(message) - 2);
        err = noise_cipherstate_encrypt(ctx->send_cipher, &mbuf);
        if (err != NOISE_ERROR_NONE)
        {
            noise_perror("write", err);
            ok = 0;
            break;
        }
        message[0] = (uint8_t)(mbuf.size >> 8);
        message[1] = (uint8_t)mbuf.size;
        if (!echo_send(fd, message, mbuf.size + 2))
        {
            ok = 0;
            break;
        }

        /* Wait for a message from the server */
        message_size = echo_recv(fd, message, sizeof(message));
        if (!message_size)
        {
            fprintf(stderr, "Remote side terminated the connection\n");
            ok = 0;
            break;
        }

        /* Decrypt the incoming message */
        noise_buffer_set_input(mbuf, message + 2, message_size - 2);
        err = noise_cipherstate_decrypt(ctx->recv_cipher, &mbuf);
        if (err != NOISE_ERROR_NONE)
        {
            noise_perror("read", err);
            ok = 0;
            break;
        }

        /* Remove padding from the message if necessary */
        if (padding)
        {
            /* Find the first '\n' and strip everything after it */
            const uint8_t *end = (const uint8_t *)
                memchr(mbuf.data, '\n', mbuf.size);
            if (end)
                mbuf.size = end + 1 - mbuf.data;
        }

        /* Write the echo to standard output */
        fputs("Received: ", stdout);
        fwrite(mbuf.data, 1, mbuf.size, stdout);
    }
}

void noise_send(int fd, NoiseContext *ctx, char *data, size_t size)
{
    //NoiseHandshakeState *handshake;
    //NoiseCipherState *send_cipher = ctx->send_cipher;
    //NoiseCipherState *recv_cipher = ctx->recv_cipher;
    //NoiseRandState *rand = 0;
    NoiseBuffer mbuf;
    //EchoProtocolId id;
    int err, ok = 1;
    //int action;
    //int fd;
    size_t message_size;
    size_t max_line_len;

    /* Read lines from stdin, send to the server, and wait for echoes */
    max_line_len = sizeof(message) - 2 - noise_cipherstate_get_mac_length(ctx->send_cipher);
    //while (ok && fgets((char *)(message + 2), max_line_len, stdin))
    // TODO
    memcpy(message + 2, data, size);

    do
    {
        /* Pad the message to a uniform size */
        //message_size = strlen((const char *)(message + 2));
        message_size = size + 2;

        /* Encrypt the message and send it */
        noise_buffer_set_inout(mbuf, message + 2, message_size, sizeof(message) - 2);
        err = noise_cipherstate_encrypt(ctx->send_cipher, &mbuf);
        if (err != NOISE_ERROR_NONE)
        {
            noise_perror("write", err);
            ok = 0;
            break;
        }
        message[0] = (uint8_t)(mbuf.size >> 8);
        message[1] = (uint8_t)mbuf.size;
        if (!echo_send(fd, message, mbuf.size + 2))
        {
            ok = 0;
            break;
        }

        /* Wait for a message from the server */
        message_size = echo_recv(fd, message, sizeof(message));
        if (!message_size)
        {
            fprintf(stderr, "Remote side terminated the connection\n");
            ok = 0;
            break;
        }

        /* Decrypt the incoming message */
        noise_buffer_set_input(mbuf, message + 2, message_size - 2);
        err = noise_cipherstate_decrypt(ctx->recv_cipher, &mbuf);
        if (err != NOISE_ERROR_NONE)
        {
            noise_perror("read", err);
            ok = 0;
            break;
        }

        /* Remove padding from the message if necessary */
        if (padding)
        {
            /* Find the first '\n' and strip everything after it */
            const uint8_t *end = (const uint8_t *)
                memchr(mbuf.data, '\n', mbuf.size);
            if (end)
                mbuf.size = end + 1 - mbuf.data;
        }

        /* Write the echo to standard output */
        fputs("Received: ", stdout);
        fwrite(mbuf.data, 1, mbuf.size, stdout);
        break;
    } while (1);
}

int noise_recv(int fd, NoiseContext *ctx, char data[], size_t size)
{
    NoiseBuffer mbuf;
    int err, ok = 1;
    size_t message_size;

    do
    {
        /* Wait for a message from the server */
        message_size = echo_recv(fd, message, sizeof(message));
        if (!message_size)
        {
            fprintf(stderr, "Remote side terminated the connection\n");
            ok = 0;
            break;
        }

        /* Decrypt the incoming message */
        noise_buffer_set_input(mbuf, message + 2, message_size - 2);
        err = noise_cipherstate_decrypt(ctx->recv_cipher, &mbuf);
        if (err != NOISE_ERROR_NONE)
        {
            noise_perror("read", err);
            ok = 0;
            break;
        }

        /* Write the echo to standard output */
        fputs("Received: ", stdout);
        fwrite(mbuf.data, 1, mbuf.size, stdout);
        memcpy(data, mbuf.data, mbuf.size);
        break;
    } while (1);

    return mbuf.size;
}

void echoService_new(int fd, NoiseContext *ctx)
{
    char buf[1024];
    while (fgets(buf, 1024, stdin))
    {
        /* Encrypt the message and send it */
        noise_send(fd, ctx, buf, strlen(buf));

        noise_recv(fd, ctx, buf, strlen(buf));
    }
}

void noise_context_free(NoiseContext *ctx)
{
    noise_cipherstate_free(ctx->send_cipher);
    noise_cipherstate_free(ctx->recv_cipher);
}

int main(int argc, char *argv[])
{
    //NoiseHandshakeState *handshake;
    //NoiseCipherState *send_cipher = 0;
    //NoiseCipherState *recv_cipher = 0;
    //NoiseRandState *rand = 0;
    //NoiseBuffer mbuf;
    //EchoProtocolId id;
    int err, ok;
    //int action;
    int fd;
    NoiseContext ctx;
    ctx.send_cipher = 0;
    ctx.recv_cipher = 0;
    //size_t message_size;
    //size_t max_line_len;

    if (noise_init() != NOISE_ERROR_NONE)
    {
        fprintf(stderr, "Noise initialization failed\n");
        return 1;
    }
#if (defined(__WIN32__) || defined(WIN32))
    WORD wVersionRequested;
    WSADATA wsaData;
    int sock_err;
    
    wVersionRequested = MAKEWORD( 2, 2 );
    
    sock_err = WSAStartup( wVersionRequested, &wsaData );
    if ( sock_err != 0 ) {
        /* Tell the user that we could not find a usable */
        /* WinSock DLL.                                  */
        return;
    }
#endif
    /* Attempt to connect to the remote party */
    fd = echo_connect(hostname,port);
    if (fd < 0)
    {
        return 1;
    }

    do_handshake(fd, &ctx);
    echoService(fd, &ctx);

    /* Clean up and exit */
    noise_context_free(&ctx);
    //noise_randstate_free(rand);
    echo_close(fd);
    return ok ? 0 : 1;
}

#include "echo-common.c"
