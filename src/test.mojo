from lightbug_http.address import TCPAddr
from lightbug_http.socket import Socket
from lightbug_http.connection import create_connection
from mojo_tlse.bindings import c_int, c_char, c_uchar, TLSContext, TLSCertificate, _tlse, tls_create_context, tls_make_exportable, tls_sni_set, tls_client_connect, tls_get_write_buffer, tls_buffer_clear, tls_established, tls_consume_stream, tls_make_ktls, tls_write, tls_read
from memory import UnsafePointer, Span
from utils import StringSlice

# int send_pending(int client_sock, struct TLSContext *context) {
#     unsigned int out_buffer_len = 0;
#     const unsigned char *out_buffer = tls_get_write_buffer(context, &out_buffer_len);
#     unsigned int out_buffer_index = 0;
#     int send_res = 0;
#     while ((out_buffer) && (out_buffer_len > 0)) {
#         int res = send(client_sock, (char *)&out_buffer[out_buffer_index], out_buffer_len, 0);
#         if (res <= 0) {
#             send_res = res;
#             break;
#         }
#         out_buffer_len -= res;
#         out_buffer_index += res;
#     }
#     tls_buffer_clear(context);
#     return send_res;
# }

# int validate_certificate(struct TLSContext *context, struct TLSCertificate **certificate_chain, int len) {
#     int i;
#     int err;
#     if (certificate_chain) {
#         for (i = 0; i < len; i++) {
#             struct TLSCertificate *certificate = certificate_chain[i];
#             # check validity date
#             err = tls_certificate_is_valid(certificate);
#             if (err)
#                 return err;
#             # check certificate in certificate->bytes of length certificate->len
#             # the certificate is in ASN.1 DER format
#         }
#     }
#     # check if chain is valid
#     err = tls_certificate_chain_is_valid(certificate_chain, len);
#     if (err)
#         return err;

#     const char *sni = tls_sni(context);
#     if ((len > 0) && (sni)) {
#         err = tls_certificate_valid_subject(certificate_chain[0], sni);
#         if (err)
#             return err;
#     }

#     fprintf(stderr, "Certificate OK\n");

#     #return certificate_expired;
#     #return certificate_revoked;
#     #return certificate_unknown;
#     return no_error;
# }

# Convert the above C function to Mojo
fn validate_certificate(context: UnsafePointer[TLSContext], certificate_chain: UnsafePointer[UnsafePointer[TLSCertificate]], len: c_int) -> c_int:
    # var err: c_int
    # if certificate_chain:
    #     for i in 0..len:
    #         var certificate = certificate_chain[i]
    #         # check validity date
    #         err = tls_certificate_is_valid(certificate)
    #         if err:
    #             return err
    #         # check certificate in certificate->bytes of length certificate->len
    #         # the certificate is in ASN.1 DER format
    # # check if chain is valid
    # err = tls_certificate_chain_is_valid(certificate_chain, len)
    # if err:
    #     return err

    # var sni = tls_sni(context)
    # if len > 0 and sni:
    #     err = tls_certificate_valid_subject(certificate_chain[0], sni)
    #     if err:
    #         return err

    print("Certificate OK")

    # # return certificate_expired
    # # return certificate_revoked
    # # return certificate_unknown
    # return no_error
    return 255


fn send_pending(socket: Socket, context: UnsafePointer[TLSContext]) raises -> Int:
    var out_buffer_len: UInt32 = 0
    var out_buffer: UnsafePointer[c_uchar] = tls_get_write_buffer(context, UnsafePointer.address_of(out_buffer_len))
    var out_buffer_index: UInt32 = 0
    var send_res = 0
    while out_buffer and out_buffer_len > 0:
        var len: UInt = int(out_buffer_len)
        var msg: Span[Byte, origin=__origin_of(out_buffer)] = Span[Byte, origin=__origin_of(out_buffer)] (ptr=out_buffer, length=len)

        var res = socket.send(buffer=msg)
        if res <= 0:
            send_res = res
            break
        out_buffer_len -= res
        out_buffer_index += res
    tls_buffer_clear(context)
    return send_res

fn main() raises:
    var host = "www.google.com"
    var port: UInt16 = 443

    with Socket[TCPAddr]() as socket:
        # Bind client to port 8082
        # socket.bind("127.0.0.1", 8082)

        # Send 10 test messages
        socket.connect(host, port)
        var context = tls_create_context(0, 0x0304)
        tls_make_exportable(context, 1)
        _ = tls_sni_set(context, host.unsafe_ptr())
        _ = tls_client_connect(context)
        _ = send_pending(socket, context)

        var read_size: c_int
        var sent = 0
        var buffer = List[Byte, True](capacity=0xFFFF)
        while socket.receive(buffer) > 0:
            print("")
            print("bytes received:", buffer.size)
            var consume_stream_res = tls_consume_stream(context, buffer.unsafe_ptr(), len(buffer), validate_certificate)
            print("tls_consume_stream:", consume_stream_res)
            if consume_stream_res < 0:
                break
            print("from initial send pending", send_pending(socket, context))

            var tls_est = tls_established(context)
            print("tls_est", tls_est)
            if (tls_est == 1):
                if sent == 0:
                    var msg = "GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n"
                    # try kTLS (kernel TLS implementation in linux >= 4.13)
                    # note that you can use send on a ktls socket
                    # recv must be handled by TLSe
                    if not tls_make_ktls(context, socket.fd):
                        # call send as on regular TCP sockets
                        # TLS record layer is handled by the kernel
                        print("bytes sent via tcp", socket.send(msg.as_bytes()))
                    else:
                        print("sending request:", msg)
                        print("bytes sent via tls write", tls_write(context, msg.unsafe_ptr(), msg.byte_length()))
                        print("bytes sent via pending", send_pending(socket, context))
                    sent = 1
                
                var read_buffer = List[Byte, True](capacity=0xFFFF)
                var bytes_read = tls_read(context, read_buffer.unsafe_ptr(), read_buffer.capacity - 1)
                print("bytes read from tls read:", bytes_read)
                if (bytes_read > 0):
                    print(StringSlice(unsafe_from_utf8=read_buffer))


