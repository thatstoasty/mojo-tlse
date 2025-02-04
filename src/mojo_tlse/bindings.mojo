from sys import ffi
from memory import UnsafePointer

alias c_void = UInt8
alias c_char = UInt8
alias c_schar = Int8
alias c_uchar = UInt8
alias c_short = Int16
alias c_ushort = UInt16
alias c_int = Int32
alias c_uint = UInt32
alias c_long = Int64
alias c_ulong = UInt64
alias c_float = Float32
alias c_double = Float64

# `Int` is known to be machine's width
alias c_size_t = Int
alias c_ssize_t = Int

alias ptrdiff_t = Int64
alias intptr_t = Int64
alias uintptr_t = UInt64

var _tlse = ffi.DLHandle("/Users/mikhailtavarez/Git/mojo/mojo-tlse/external/libtlse.dylib", ffi.RTLD.LAZY)

struct TLSContext():
    ...


fn tls_create_context(
    is_server: c_uchar,
    version: c_ushort,
) -> UnsafePointer[TLSContext]:
    """struct TLSContext *tls_create_context(unsigned char is_server, unsigned short version);"""
    return _tlse.get_function[
        fn (c_char, c_ushort) -> UnsafePointer[TLSContext]
    ]("tls_create_context")(is_server, version)


fn tls_make_exportable(
    context: UnsafePointer[TLSContext],
    exportable_flag: c_uchar,
):
    """void tls_make_exportable(struct TLSContext *context, unsigned char exportable_flag)"""
    return _tlse.get_function[
        fn (UnsafePointer[TLSContext], c_uchar)
    ]("tls_make_exportable")(context, exportable_flag)


fn tls_sni_set(
    context: UnsafePointer[TLSContext],
    sni: UnsafePointer[c_char],
) -> c_int:
    """int tls_sni_set(struct TLSContext *context, const char *sni);"""
    return _tlse.get_function[
        fn (UnsafePointer[TLSContext], UnsafePointer[c_char]) -> c_int
    ]("tls_sni_set")(context, sni)


fn tls_client_connect(
    context: UnsafePointer[TLSContext],
) -> c_int:
    return _tlse.get_function[
        fn (UnsafePointer[TLSContext]) -> c_int
    ]("tls_client_connect")(context)


fn tls_get_write_buffer(
    context: UnsafePointer[TLSContext],
    outlen: UnsafePointer[c_uint],
) -> UnsafePointer[c_uchar]:
    """const unsigned char *tls_get_write_buffer(struct TLSContext *context, unsigned int *outlen);"""
    return _tlse.get_function[
        fn (UnsafePointer[TLSContext], UnsafePointer[c_uint]) -> UnsafePointer[c_uchar]
    ]("tls_get_write_buffer")(context, outlen)


fn tls_buffer_clear(
    context: UnsafePointer[TLSContext]
):
    """void tls_buffer_clear(struct TLSContext *context);"""
    return _tlse.get_function[
        fn (UnsafePointer[TLSContext])
    ]("tls_buffer_clear")(context)


fn tls_established(
    context: UnsafePointer[TLSContext]
) -> c_int:
    """Returns 1 for established, 0 for not established yet, and -1 for a critical error.
    int tls_established(struct TLSContext *context)."""
    return _tlse.get_function[
        fn (UnsafePointer[TLSContext]) -> c_int
    ]("tls_established")(context)

struct TLSCertificate():
    ...

alias TLSValidationFn = fn (UnsafePointer[TLSContext], UnsafePointer[UnsafePointer[TLSCertificate]], c_int) -> c_int

fn tls_consume_stream(
    context: UnsafePointer[TLSContext],
    buf: UnsafePointer[c_uchar],
    buf_len: c_int,
    certificate_verify: TLSValidationFn,
) -> c_int:
    """/*
  Process a given number of input bytes from a socket. If the other side just
  presented a certificate and certificate_verify is not NULL, it will be called.

  Returns 0 if there's no data ready yet, a negative value (see
  TLS_GENERIC_ERROR etc.) for an error, or a positive value (the number of bytes
  used from buf) if one or more complete TLS messages were received. The data
  is copied into an internal buffer even if not all of it was consumed,
  so you should not re-send it the next time.

  Decrypted data, if any, should be read back with tls_read(). Can change the
  status of tls_established(). If the library has anything to send back on the
  socket (e.g. as part of the handshake), tls_get_write_buffer() will return
  non-NULL.
 */
int tls_consume_stream(struct TLSContext *context, const unsigned char *buf, int buf_len, tls_validation_function certificate_verify);
"""
    return _tlse.get_function[
        fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar], c_int, TLSValidationFn) -> c_int
    ]("tls_consume_stream")(context, buf, buf_len, certificate_verify)


fn tls_make_ktls(
    context: UnsafePointer[TLSContext],
    socket: c_int,
) -> c_int:
    """int tls_make_ktls(struct TLSContext *context, int socket);"""
    return _tlse.get_function[
        fn (UnsafePointer[TLSContext], c_int) -> c_int
    ]("tls_make_ktls")(context, socket)


fn tls_read(
    context: UnsafePointer[TLSContext],
    buf: UnsafePointer[c_uchar],
    size: c_uint,
) -> c_int:
    """Reads any unread decrypted data (see tls_consume_stream). If you don't read all of it,
    the remainder will be left in the internal buffers for next tls_read(). Returns -1 for
    fatal error, 0 for no more data, or otherwise the number of bytes copied into the buffer
    (up to a maximum of the given size).
    int tls_read(struct TLSContext *context, unsigned char *buf, unsigned int size);"""
    return _tlse.get_function[
        fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar], c_uint) -> c_int
    ]("tls_read")(context, buf, size)


fn tls_write(
    context: UnsafePointer[TLSContext],
    data: UnsafePointer[c_uchar],
    len: c_uint,
) -> c_int:
    """Writes data to the TLS connection. Returns -1 for fatal error, 0 for no more data, or
    otherwise the number of bytes written (up to a maximum of the given size).
    int tls_write(struct TLSContext *context, const unsigned char *data, unsigned int len);"""
    return _tlse.get_function[
        fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar], c_uint) -> c_int
    ]("tls_write")(context, data, len)


fn tls_certificate_is_valid(
    cert: UnsafePointer[TLSCertificate]
) -> c_int:
    """int tls_certificate_is_valid(struct TLSCertificate *cert);"""
    return _tlse.get_function[
        fn (UnsafePointer[TLSCertificate]) -> c_int
    ]("tls_certificate_is_valid")(cert)


fn tls_certificate_chain_is_valid(
    certificates: UnsafePointer[UnsafePointer[TLSCertificate]],
    len: c_int,
) -> c_int:
    """int tls_certificate_chain_is_valid(struct TLSCertificate **certificates, int len);"""
    return _tlse.get_function[
        fn (UnsafePointer[UnsafePointer[TLSCertificate]], c_int) -> c_int
    ]("tls_certificate_chain_is_valid")(certificates, len)


fn tls_certificate_valid_subject(
    cert: UnsafePointer[TLSCertificate],
    subject: UnsafePointer[c_char],
) -> c_int:
    """int tls_certificate_valid_subject(struct TLSCertificate *cert, const char *subject);"""
    return _tlse.get_function[
        fn (UnsafePointer[TLSCertificate], UnsafePointer[c_char]) -> c_int
    ]("tls_certificate_valid_subject")(cert, subject)


fn tls_sni(
    context: UnsafePointer[TLSContext]
) -> UnsafePointer[c_char]:
    """const char *tls_sni(struct TLSContext *context);"""
    return _tlse.get_function[
        fn (UnsafePointer[TLSContext]) -> UnsafePointer[c_char]
    ]("tls_sni")(context)

# tls_make_exportable
# tls_sni_set
# tls_client_connect
# send_pending
# client_message
# tls_consume_stream
# send_pending
# tls_established
# tls_make_ktls
# tls_write
# read_buffer
# tls_read

alias todo = ""
    """
    ```c
    int main(int argc, char *argv[]) {
        struct TLSContext *context = tls_create_context(0, TLS_V13);
        // the next line is needed only if you want to serialize the connection context or kTLS is used
        tls_make_exportable(context, 1);
        tls_sni_set(context, argv[1]);
        tls_client_connect(context);
        send_pending(sockfd, context);
        unsigned char client_message[0xFFFF];
        int read_size;
        int sent = 0;
        while ((read_size = recv(sockfd, client_message, sizeof(client_message) , 0)) > 0) {
            tls_consume_stream(context, client_message, read_size, validate_certificate);
            send_pending(sockfd, context);
            if (tls_established(context) == 1) {
                if (!sent) {
                    const char *request = "GET / HTTP/1.1\r\nConnection: close\r\n\r\n";
                    // try kTLS (kernel TLS implementation in linux >= 4.13)
                    // note that you can use send on a ktls socket
                    // recv must be handled by TLSe
                    if (!tls_make_ktls(context, sockfd)) {
                        // call send as on regular TCP sockets
                        // TLS record layer is handled by the kernel
                        send(sockfd, request, strlen(request), 0);
                    } else {
                        tls_write(context, (unsigned char *)request, strlen(request));
                        send_pending(sockfd, context);
                    }
                    sent = 1;
                }

                unsigned char read_buffer[0xFFFF];
                int read_size = tls_read(context, read_buffer, 0xFFFF - 1);
                if (read_size > 0)
                    fwrite(read_buffer, read_size, 1, stdout);
            }
        }
        fflush(stdout);
        return 0;
    }
    ```
    """