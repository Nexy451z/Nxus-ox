#include "nxus_net.h"
#include "nxus_log.h"

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

static int             g_ListenFd = -1;
static int             g_ClientFd = -1;
static Thread          g_ServerThread;
static bool            g_Running = false;
static Mutex           g_SendMutex;
static Mutex           g_ClientMutex;
static NxusNetHandler  g_Handler = NULL;
static void           *g_HandlerUser = NULL;
static u16             g_Port = NXUS_DEFAULT_PORT;
static u8             *g_RxBuffer = NULL;

static int setClientFd(int fd) {
    mutexLock(&g_ClientMutex);
    g_ClientFd = fd;
    mutexUnlock(&g_ClientMutex);
    return fd;
}

int nxusNetClientFd(void) {
    mutexLock(&g_ClientMutex);
    int fd = g_ClientFd;
    mutexUnlock(&g_ClientMutex);
    return fd;
}

static bool recvAll(int fd, void *buffer, u32 length) {
    u8 *out = (u8 *)buffer;
    u32 got = 0;
    while (got < length) {
        int n = recv(fd, out + got, length - got, 0);
        if (n > 0) { got += (u32)n; continue; }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
            if (!g_Running) return false;
            continue;   /* receive timeout: re-check the stop flag */
        }
        return false;
    }
    return true;
}

/* Write exactly `length` bytes. Returns false on a hard error or when the socket's
   SO_SNDTIMEO expires (a PC that stops reading a large reply). `*out_sent` always
   receives the number of bytes actually written, so the caller can tell a clean
   failure (nothing on the wire) from a partial send that desynced the stream. */
static bool sendAll(int fd, const void *buffer, u32 length, u32 *out_sent) {
    const u8 *out = (const u8 *)buffer;
    u32 sent = 0;
    while (sent < length) {
        const int n = send(fd, out + sent, (int)(length - sent), 0);
        if (n > 0) { sent += (u32)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        break;
    }
    if (out_sent != NULL) *out_sent = sent;
    return sent == length;
}

Result nxusNetSendFd(int fd, u16 type, u16 flags, u32 seq, const void *payload, u32 length) {
    if (fd < 0) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    if (length > NXUS_NET_BUF_SIZE) return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    if (length > 0 && payload == NULL) return MAKERESULT(Module_Libnx, LibnxError_BadInput);

    NxusPacketHeader header;
    nxusHeaderInit(&header, type, flags, length, seq);

    mutexLock(&g_SendMutex);

    /* Zero-copy write: the 16-byte header goes straight from the stack and the
       payload straight from the caller's buffer.  Copying both into one scratch
       malloc added a ~1 MiB allocation plus a ~1 MiB memcpy to every large reply
       (notably the 1 MiB Read response) - exactly the spike that ran the shared
       8 MB heap out of memory in the middle of a scan.  The two send loops cost
       no extra round trip: TCP never waits for an ACK between them, and the
       peer's recvAll loop reassembles header + payload from the same stream. */
    u32 sent_header = 0;
    u32 sent_total  = 0;
    bool failed = !sendAll(fd, &header, (u32)sizeof(header), &sent_header);
    sent_total += sent_header;

    if (!failed && length > 0) {
        u32 sent_payload = 0;
        failed = !sendAll(fd, payload, length, &sent_payload);
        sent_total += sent_payload;
    }

    Result rc = 0;
    if (failed) {
        /* Once part of a packet is on the wire the peer's framing is lost for
           good: it will parse payload bytes as the next header.  Tear the
           connection down (the server loop then reconnects cleanly) instead of
           returning an error that leaves the stream permanently desynced. */
        if (sent_total > 0) shutdown(fd, SHUT_RDWR);
        rc = MAKERESULT(Module_Libnx, LibnxError_ShouldNotHappen);
    }

    mutexUnlock(&g_SendMutex);
    return rc;
}

Result nxusNetSend(u16 type, u16 flags, u32 seq, const void *payload, u32 length) {
    int fd = nxusNetClientFd();
    if (fd < 0) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    return nxusNetSendFd(fd, type, flags, seq, payload, length);
}

Result nxusNetSendAck(u32 seq)   { return nxusNetSend(seq, 0, seq, NULL, 0); }
Result nxusNetSendError(u32 seq, Result rc) {
    s32 value = (s32)rc;
    return nxusNetSend(seq, NXUS_FLAG_ERROR, seq, &value, sizeof(value));
}
Result nxusNetSendEvent(u16 type, const void *payload, u32 length) {
    return nxusNetSend(type, NXUS_FLAG_ASYNC, 0, payload, length);
}
Result nxusNetRespond(u32 seq, const void *payload, u32 length) {
    u16 type = NxusCmd_Nop;
    /* The caller passes the response type through the payload buffer convention:
       we keep it simple and let callers use nxusNetSend for typed replies. */
    return nxusNetSend(type, 0, seq, payload, length);
}

static void serveClient(int fd) {
    NXUS_LOG("client connected (fd=%d)", fd);

    /* 1s receive timeout so the thread notices shutdown / disconnect */
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* ...and the same for sending: a PC that stops reading a large reply (or a
       dropped link) would otherwise block this thread inside send() for good,
       which also keeps the watchdog disabled (see g_CommandActive). */
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    while (g_Running && nxusNetClientFd() == fd) {
        NxusPacketHeader header;
        if (!recvAll(fd, &header, sizeof(header))) break;

        if (header.magic != NXUS_MAGIC) {
            NXUS_LOG("bad magic 0x%08X - closing", (unsigned)header.magic);
            break;
        }
        if (header.length > NXUS_NET_BUF_SIZE) {
            NXUS_LOG("payload too large (%u) - closing", (unsigned)header.length);
            break;
        }

        u32 length = header.length;
        if (length > 0) {
            if (g_RxBuffer == NULL) g_RxBuffer = (u8 *)malloc(NXUS_NET_BUF_SIZE);
            if (g_RxBuffer == NULL || !recvAll(fd, g_RxBuffer, length)) break;
        }

        if (g_Handler != NULL) {
            g_Handler(fd, &header, g_RxBuffer, length, g_HandlerUser);
        }
    }

    NXUS_LOG("client disconnected (fd=%d)", fd);
    mutexLock(&g_ClientMutex);
    if (g_ClientFd == fd) g_ClientFd = -1;
    mutexUnlock(&g_ClientMutex);
    close(fd);
}

static void serverThread(void *arg) {
    (void)arg;
    while (g_Running) {
        int fd = accept(g_ListenFd, NULL, NULL);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
            svcSleepThread(50000000ull);
            continue;
        }
        if (nxusNetClientFd() >= 0) {
            NXUS_LOG("second client rejected (only one session supported)");
            close(fd);
            continue;
        }
        setClientFd(fd);
        serveClient(fd);
    }
}

Result nxusNetInit(u16 port, NxusNetHandler handler, void *user) {
    if (g_Running) return 0;

    mutexInit(&g_SendMutex);
    mutexInit(&g_ClientMutex);
    g_Handler = handler;
    g_HandlerUser = user;
    g_Port = port;

#ifdef SIGPIPE
    signal(SIGPIPE, SIG_IGN);
#endif

    Result rc = socketInitializeDefault();
    if (R_FAILED(rc)) {
        NXUS_RESULT("socketInitializeDefault", rc);
        return rc;
    }
    NXUS_LOG("socketInitializeDefault ok");

    g_ListenFd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_ListenFd < 0) {
        NXUS_LOG("socket() failed errno=%d", errno);
        socketExit();
        return MAKERESULT(Module_Libnx, LibnxError_ShouldNotHappen);
    }

    int one = 1;
    setsockopt(g_ListenFd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_Port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(g_ListenFd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        NXUS_LOG("bind(%u) failed errno=%d", (unsigned)g_Port, errno);
        close(g_ListenFd);
        g_ListenFd = -1;
        socketExit();
        return MAKERESULT(Module_Libnx, LibnxError_ShouldNotHappen);
    }

    if (listen(g_ListenFd, 1) != 0) {
        NXUS_LOG("listen() failed errno=%d", errno);
        close(g_ListenFd);
        g_ListenFd = -1;
        socketExit();
        return MAKERESULT(Module_Libnx, LibnxError_ShouldNotHappen);
    }

    g_Running = true;
    alignas(0x1000) static u8 serverStack[0x8000];
    rc = threadCreate(&g_ServerThread, serverThread, NULL, serverStack, sizeof(serverStack), 0x2C, -2);
    NXUS_RESULT("threadCreate(core -2)", rc);
    if (R_FAILED(rc)) {
        /* libnx wants -2 (default) or 0..3; anything else is an invalid core id */
        rc = threadCreate(&g_ServerThread, serverThread, NULL, serverStack, sizeof(serverStack), 0x2C, 3);
        NXUS_RESULT("threadCreate(core 3)", rc);
    }
    if (R_FAILED(rc)) {
        g_Running = false;
        socketExit();
        return rc;
    }
    threadStart(&g_ServerThread);

    NXUS_LOG("listening on 0.0.0.0:%u", (unsigned)g_Port);
    return 0;
}

void nxusNetExit(void) {
    if (!g_Running) return;
    g_Running = false;

    int fd = nxusNetClientFd();
    if (fd >= 0) shutdown(fd, SHUT_RDWR);
    if (g_ListenFd >= 0) shutdown(g_ListenFd, SHUT_RDWR);

    threadWaitForExit(&g_ServerThread);
    threadClose(&g_ServerThread);

    if (g_ListenFd >= 0) close(g_ListenFd);
    g_ListenFd = -1;
    free(g_RxBuffer);
    g_RxBuffer = NULL;
    socketExit();
}

bool nxusNetIsRunning(void) { return g_Running; }
