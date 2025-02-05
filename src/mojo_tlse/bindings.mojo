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


struct TLSContext:
    """Read only, the TLSContext struct is defined in C and is opaque to Mojo.

    Pointers to `TLSContext` should never be dereferenced.
    """

    pass


struct TLSCertificate:
    """Read only, the TLSCertificate struct is defined in C and is opaque to Mojo.

    Pointers to `TLSCertificate` should never be dereferenced.
    """

    pass


alias TLSValidationFn = fn (UnsafePointer[TLSContext], UnsafePointer[UnsafePointer[TLSCertificate]], c_int) -> c_int


struct TLSE:
    var _handle: ffi.DLHandle

    fn __init__(out self):
        self._handle = ffi.DLHandle("/Users/mikhailtavarez/Git/mojo/mojo-tlse/external/libtlse.dylib", ffi.RTLD.LAZY)

    fn tls_create_context(
        self,
        is_server: c_uchar,
        version: c_ushort,
    ) -> UnsafePointer[TLSContext]:
        """struct TLSContext *tls_create_context(unsigned char is_server, unsigned short version);"""
        return self._handle.get_function[fn (c_char, c_ushort) -> UnsafePointer[TLSContext]]("tls_create_context")(
            is_server, version
        )

    fn tls_make_exportable(
        self,
        context: UnsafePointer[TLSContext],
        exportable_flag: c_uchar,
    ):
        """void tls_make_exportable(struct TLSContext *context, unsigned char exportable_flag)"""
        return self._handle.get_function[fn (UnsafePointer[TLSContext], c_uchar)]("tls_make_exportable")(
            context, exportable_flag
        )

    fn tls_sni_set(
        self,
        context: UnsafePointer[TLSContext],
        sni: UnsafePointer[c_char],
    ) -> c_int:
        """int tls_sni_set(struct TLSContext *context, const char *sni);"""
        return self._handle.get_function[fn (UnsafePointer[TLSContext], UnsafePointer[c_char]) -> c_int]("tls_sni_set")(
            context, sni
        )

    fn tls_client_connect(
        self,
        context: UnsafePointer[TLSContext],
    ) -> c_int:
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> c_int]("tls_client_connect")(context)

    fn tls_get_write_buffer(
        self,
        context: UnsafePointer[TLSContext],
        outlen: UnsafePointer[c_uint],
    ) -> UnsafePointer[c_uchar]:
        """const unsigned char *tls_get_write_buffer(struct TLSContext *context, unsigned int *outlen);"""
        return self._handle.get_function[
            fn (UnsafePointer[TLSContext], UnsafePointer[c_uint]) -> UnsafePointer[c_uchar]
        ]("tls_get_write_buffer")(context, outlen)

    fn tls_buffer_clear(self, context: UnsafePointer[TLSContext]):
        """void tls_buffer_clear(struct TLSContext *context);"""
        return self._handle.get_function[fn (UnsafePointer[TLSContext])]("tls_buffer_clear")(context)

    fn tls_established(self, context: UnsafePointer[TLSContext]) -> c_int:
        """Returns 1 for established, 0 for not established yet, and -1 for a critical error.
        int tls_established(struct TLSContext *context)."""
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> c_int]("tls_established")(context)

    fn tls_consume_stream(
        self,
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
        return self._handle.get_function[
            fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar], c_int, TLSValidationFn) -> c_int
        ]("tls_consume_stream")(context, buf, buf_len, certificate_verify)

    fn tls_make_ktls(
        self,
        context: UnsafePointer[TLSContext],
        socket: c_int,
    ) -> c_int:
        """int tls_make_ktls(struct TLSContext *context, int socket);"""
        return self._handle.get_function[fn (UnsafePointer[TLSContext], c_int) -> c_int]("tls_make_ktls")(
            context, socket
        )

    fn tls_read(
        self,
        context: UnsafePointer[TLSContext],
        buf: UnsafePointer[c_uchar],
        size: c_uint,
    ) -> c_int:
        """Reads any unread decrypted data (see tls_consume_stream). If you don't read all of it,
        the remainder will be left in the internal buffers for next tls_read(). Returns -1 for
        fatal error, 0 for no more data, or otherwise the number of bytes copied into the buffer
        (up to a maximum of the given size).
        int tls_read(struct TLSContext *context, unsigned char *buf, unsigned int size);"""
        return self._handle.get_function[fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar], c_uint) -> c_int](
            "tls_read"
        )(context, buf, size)

    fn tls_write(
        self,
        context: UnsafePointer[TLSContext],
        data: UnsafePointer[c_uchar],
        len: c_uint,
    ) -> c_int:
        """Writes data to the TLS connection. Returns -1 for fatal error, 0 for no more data, or
        otherwise the number of bytes written (up to a maximum of the given size).
        int tls_write(struct TLSContext *context, const unsigned char *data, unsigned int len);"""
        return self._handle.get_function[fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar], c_uint) -> c_int](
            "tls_write"
        )(context, data, len)

    fn tls_certificate_is_valid(self, cert: UnsafePointer[TLSCertificate]) -> c_int:
        """int tls_certificate_is_valid(struct TLSCertificate *cert);"""
        return self._handle.get_function[fn (UnsafePointer[TLSCertificate]) -> c_int]("tls_certificate_is_valid")(cert)

    fn tls_certificate_chain_is_valid(
        self,
        certificates: UnsafePointer[UnsafePointer[TLSCertificate]],
        len: c_int,
    ) -> c_int:
        """int tls_certificate_chain_is_valid(struct TLSCertificate **certificates, int len);"""
        return self._handle.get_function[fn (UnsafePointer[UnsafePointer[TLSCertificate]], c_int) -> c_int](
            "tls_certificate_chain_is_valid"
        )(certificates, len)

    fn tls_certificate_valid_subject(
        self,
        cert: UnsafePointer[TLSCertificate],
        subject: UnsafePointer[c_char],
    ) -> c_int:
        """int tls_certificate_valid_subject(struct TLSCertificate *cert, const char *subject);"""
        return self._handle.get_function[fn (UnsafePointer[TLSCertificate], UnsafePointer[c_char]) -> c_int](
            "tls_certificate_valid_subject"
        )(cert, subject)

    fn tls_sni(self, context: UnsafePointer[TLSContext]) -> UnsafePointer[c_char]:
        """const char *tls_sni(struct TLSContext *context);"""
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> UnsafePointer[c_char]]("tls_sni")(context)

    fn tls_choose_cipher(
        self,
        context: UnsafePointer[TLSContext],
        buf: UnsafePointer[c_uchar],
        buf_len: c_int,
        scsv_set: UnsafePointer[c_int],
    ) -> c_int:
        """int tls_choose_cipher(struct TLSContext *context, const unsigned char *buf, int buf_len, int *scsv_set);"""
        return self._handle.get_function[
            fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar], c_int, UnsafePointer[c_int]) -> c_int
        ]("tls_choose_cipher")(context, buf, buf_len, scsv_set)
