from lightbug_http.address import TCPAddr
from lightbug_http.socket import Socket
from lightbug_http.connection import create_connection
from mojo_tlse.bindings import c_int, c_char, c_uchar, TLSContext, TLSCertificate, TLSE
from mojo_tlse.enums import Result
from memory import UnsafePointer, Span


fn validate_certificate(
    context: UnsafePointer[TLSContext], certificate_chain: UnsafePointer[UnsafePointer[TLSCertificate]], len: c_int
) -> c_int:
    try:
        var tlse = TLSE()

        if certificate_chain:
            for i in range(len):
                var certificate = certificate_chain[i]
                # check validity date
                var err = tlse.tls_certificate_is_valid(certificate)
                if err < 0:
                    print(err)
                    return err
                # check certificate in certificate->bytes of length certificate->len
                # the certificate is in ASN.1 DER format
        # check if chain is valid
        var err = tlse.tls_certificate_chain_is_valid(certificate_chain, len)
        if err < 0:
            print(err)
            return err

        var sni = tlse.tls_sni(context)
        if len > 0 and sni:
            err = tlse.tls_certificate_valid_subject(certificate_chain[0], sni)
            if err < 0:
                print(err)
                return err

        print("Certificate OK")

        return Result.NO_ERROR.value
    except:
        return Result.NO_ERROR.value


fn send_pending(tlse: TLSE, socket: Socket, context: UnsafePointer[TLSContext]) raises -> Int:
    var out_buffer_len: UInt32 = 0
    var out_buffer = tlse.tls_get_write_buffer(context, UnsafePointer.address_of(out_buffer_len))
    var out_buffer_index: UInt32 = 0
    var send_res = 0
    while out_buffer and out_buffer_len > 0:
        var len: UInt = Int(out_buffer_len)
        var msg = Span[Byte, origin = __origin_of(out_buffer)](ptr=out_buffer, length=len)

        var res = socket.send(buffer=msg)
        if res <= 0:
            send_res = res
            break
        out_buffer_len -= res
        out_buffer_index += res
    tlse.tls_buffer_clear(context)
    return send_res


fn main() raises:
    var tlse = TLSE()
    var host = "google.com"
    var port: UInt16 = 443

    with Socket[TCPAddr]() as socket:
        # Bind client to port 8082
        # socket.bind("127.0.0.1", 8082)

        socket.connect(host, port)
        var context = tlse.tls_create_context(0, 0x0304)
        tlse.tls_make_exportable(context, 1)
        _ = tlse.tls_sni_set(context, host.unsafe_cstr_ptr())
        _ = tlse.tls_client_connect(context)
        _ = send_pending(tlse, socket, context)

        var sent = 0
        var buffer = List[Byte, True](capacity=65535)
        while True:
            # Read the next chunk of encrypted data from the connection.
            try:
                _ = socket.receive(buffer)
            except e:
                # If EOF is reached, the connection is closed and we can break out of the loop.
                if String(e) == "EOF":
                    break
                else:
                    raise e

            try:
                if tlse.tls_consume_stream(context, buffer.unsafe_ptr(), len(buffer), validate_certificate) <= 0:
                    break

                if tlse.tls_established(context) == 1:
                    if sent == 0:
                        var msg = "GET / HTTP/1.1\r\nConnection: close\r\n\r\n"
                        # try kTLS (kernel TLS implementation in linux >= 4.13)
                        # note that you can use send on a ktls socket
                        # recv must be handled by TLSe
                        var make_tls = tlse.tls_make_ktls(context, socket.fd)
                        if make_tls != 0:
                            print("sending request:", msg)
                            print(
                                "bytes sent via tls write:",
                                tlse.tls_write(context, msg.unsafe_ptr(), msg.byte_length()),
                            )
                            print("bytes sent via pending:", send_pending(tlse, socket, context))
                        else:
                            # call send as on regular TCP sockets
                            # TLS record layer is handled by the kernel
                            print("bytes sent via tcp", socket.send(msg.as_bytes()))

                        sent = 1

                    var read_buffer = List[Byte, True](capacity=65535)
                    var bytes_read = tlse.tls_read(context, read_buffer.unsafe_ptr(), read_buffer.capacity)
                    read_buffer._len += Int(bytes_read)
                    print("bytes read:", bytes_read)
                    if bytes_read > 0:
                        print(StringSlice(unsafe_from_utf8=read_buffer))
            finally:
                buffer.clear()
