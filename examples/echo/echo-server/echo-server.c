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
#include <unistd.h>
#include <getopt.h>
#if defined(__WIN32__) || defined(WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
typedef int socklen_t;
typedef BOOL sockopt_type;
#define MSG_NOSIGNAL 0
#undef HAVE_POLL
#endif

#define short_options "k:vf"

static const char *protocol = "Noise_KK_25519_ChaChaPoly_BLAKE2b";
static const char *server_private_key = "B321CA343B77CFF728F6F5346F360E54CE4C3CB50ACDE0C4D7EF88CC288C14C6";
static const char *client_public_key = "FA0DBBF96EE194CD49325A7AEFD52EABE6D638A17A60CA4796C4F08A92221F6C";

static struct option const long_options[] = {
    {"key-dir", required_argument, NULL, 'k'},
    {"verbose", no_argument, NULL, 'v'},
    {"fixed-ephemeral", no_argument, NULL, 'f'},
    {NULL, 0, NULL, 0}};

/* Parsed command-line options */
static const char *key_dir = ".";
static int port = 7000;
static int fixed_ephemeral = 0;

/* Loaded keys */
#define CURVE25519_KEY_LEN 32
#define CURVE448_KEY_LEN 56
static uint8_t client_key_25519[CURVE25519_KEY_LEN];
static uint8_t server_key_25519[CURVE25519_KEY_LEN];
static uint8_t client_key_448[CURVE448_KEY_LEN];
static uint8_t server_key_448[CURVE448_KEY_LEN];
static uint8_t psk[32];

/* Message buffer for send/receive */
#define MAX_MESSAGE_LEN 65535
static uint8_t message[MAX_MESSAGE_LEN + 2];

void hex2bytes(char *hexstring, char *bytearray, int length)
{
    for (size_t i = 0, j = 0; i < (length); i++, j += 2)
        bytearray[i] = (hexstring[j] % 32 + 9) % 25 * 16 + (hexstring[j + 1] % 32 + 9) % 25;
}

/* Initializes the handshake with all necessary keys */
static int initialize_handshake(NoiseHandshakeState *handshake,
                                //const NoiseProtocolId *nid,
                                const void *prologue, size_t prologue_len)
{
    NoiseDHState *dh;
    int dh_id;
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
    /* Set the local keypair for the server based on the DH algorithm */
    dh = noise_handshakestate_get_local_keypair_dh(handshake);

    int key_len = noise_dhstate_get_private_key_length(dh);
    char *key = (uint8_t *)malloc(key_len);

    hex2bytes(server_private_key, key, key_len);
    noise_dhstate_set_keypair_private(dh, key, key_len);
    //noise_free(key, key_len);

    /* Set the remote public key for the client */
    dh = noise_handshakestate_get_remote_public_key_dh(handshake);
    dh_id = noise_dhstate_get_dh_id(dh);
    hex2bytes(client_public_key, key, key_len);
    err = noise_dhstate_set_public_key(dh, key, key_len);
    noise_free(key, key_len);

    /* Ready to go */
    return 1;
}

int main(int argc, char *argv[])
{
    NoiseHandshakeState *handshake = 0;
    NoiseCipherState *send_cipher = 0;
    NoiseCipherState *recv_cipher = 0;
    EchoProtocolId id;
    NoiseProtocolId nid;
    NoiseBuffer mbuf;
    size_t message_size;
    int fd;
    int err;
    int ok = 1;
    int action;

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
    /* Accept an incoming connection */
    fd = echo_accept(port);

    if (!echo_get_protocol_id(&id, protocol))
    {
        fprintf(stderr, "%s: not supported by the echo protocol\n", protocol);
        return -1;
    }

    /* Create a HandshakeState object for the protocol */
    err = noise_handshakestate_new_by_name(&handshake, protocol, NOISE_ROLE_RESPONDER);
    if (err != NOISE_ERROR_NONE)
    {
        noise_perror(protocol, err);
        return err;
    }

    /* Set all keys that are needed by the client's requested echo protocol */
    if (ok)
    {
        if (!initialize_handshake(handshake, &id, sizeof(id)))
        {
            ok = 0;
        }
    }

    /* Start the handshake */
    if (ok)
    {
        err = noise_handshakestate_start(handshake);
        if (err != NOISE_ERROR_NONE)
        {
            noise_perror("start handshake", err);
            ok = 0;
        }
    }

    /* Run the handshake until we run out of things to read or write */
    while (ok)
    {
        action = noise_handshakestate_get_action(handshake);
        if (action == NOISE_ACTION_WRITE_MESSAGE)
        {
            fprintf(stderr, "write");
            /* Write the next handshake message with a zero-length payload */
            noise_buffer_set_output(mbuf, message + 2, sizeof(message) - 2);
            err = noise_handshakestate_write_message(handshake, &mbuf, NULL);
            if (err != NOISE_ERROR_NONE)
            {
                noise_perror("write handshake", err);
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
        }
        else if (action == NOISE_ACTION_READ_MESSAGE)
        {

            /* Read the next handshake message and discard the payload */
            message_size = echo_recv(fd, message, sizeof(message));
            fprintf(stderr,"read %d",message_size);
            if (!message_size)
            {
                ok = 0;
                break;
            }
            noise_buffer_set_input(mbuf, message + 2, message_size - 2);
            err = noise_handshakestate_read_message(handshake, &mbuf, NULL);
            if (err != NOISE_ERROR_NONE)
            {
                noise_perror("read handshake", err);
                ok = 0;
                break;
            }
        }
        else
        {
            fprintf(stderr, "break");
            /* Either the handshake has finished or it has failed */
            break;
        }
    }

    /* If the action is not "split", then the handshake has failed */
    if (ok && noise_handshakestate_get_action(handshake) != NOISE_ACTION_SPLIT)
    {
        fprintf(stderr, "protocol handshake failed\n");
        ok = 0;
    }

    /* Split out the two CipherState objects for send and receive */
    if (ok)
    {
        err = noise_handshakestate_split(handshake, &send_cipher, &recv_cipher);
        if (err != NOISE_ERROR_NONE)
        {
            noise_perror("split to start data transfer", err);
            ok = 0;
        }
    }

    /* We no longer need the HandshakeState */
    noise_handshakestate_free(handshake);
    handshake = 0;
    fprintf(stderr, "handshake done");
    /* Process all incoming data packets and echo them back to the client */
    while (ok)
    {
        /* Read the next message, including the two byte length prefix */
        message_size = echo_recv(fd, message, sizeof(message));
        if (!message_size)
            break;

        /* Decrypt the message */
        noise_buffer_set_inout(mbuf, message + 2, message_size - 2, sizeof(message) - 2);
        err = noise_cipherstate_decrypt(recv_cipher, &mbuf);
        if (err != NOISE_ERROR_NONE)
        {
            noise_perror("read", err);
            ok = 0;
            break;
        }

        /* Re-encrypt it with the sending cipher and send back to the client */
        err = noise_cipherstate_encrypt(send_cipher, &mbuf);
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
    }

    /* Clean up and exit */
    noise_cipherstate_free(send_cipher);
    noise_cipherstate_free(recv_cipher);
    echo_close(fd);
    return ok ? 0 : 1;
}
