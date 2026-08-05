# import os
# # Waiting for asysocks 0.2.18
# from asysocks.unicomm.common.unissl import UniSSL
# def pfx_to_pem(self, pfx_path, pfx_password):
#     #https://gist.github.com/erikbern/756b1d8df2d1487497d29b90e81f8068
#     from pathlib import Path
#     from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
#     from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
    

#     ''' Decrypts the .pfx file to be used with requests. '''
#     pfx = Path(pfx_path).read_bytes()
#     if isinstance(pfx_password, str):
#         pfx_password = pfx_password.encode('utf-8')
#     private_key, main_cert, add_certs = load_key_and_certificates(pfx, pfx_password, None)
#     suffix = '%s.pem' % os.urandom(4).hex()
#     self._UniSSL__keyfilename = 'key_%s' % suffix
#     self._UniSSL__certfilename = 'cert_%s' % suffix
#     with open(self._UniSSL__keyfilename, 'wb') as f:
#         f.write(private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
#     with open(self._UniSSL__certfilename, 'wb') as f:
#         f.write(main_cert.public_bytes(Encoding.PEM))
#     if len(add_certs) > 0:
#         self._UniSSL__cacertfilename = 'cacert_%s' % suffix
#         with open(self._UniSSL__cacertfilename, 'wb') as f:
#             for ca in add_certs:
#                 f.write(ca.public_bytes(Encoding.PEM))

# UniSSL.pfx_to_pem = pfx_to_pem


# --- Relax OpenSSL security level for weak-digest client certificates ---
import ssl as _ssl

try:
    from asysocks.unicomm.common.unissl import UniSSL as _UniSSL
except ImportError:  # pragma: no cover - asysocks is a hard dep of bloodyAD
    _UniSSL = None


if _UniSSL is not None:
    def _bloodyad_get_ssl_context(self, protocol=_ssl.PROTOCOL_TLS_CLIENT):
        self._UniSSL__startup()
        try:
            ctx = _ssl.SSLContext(protocol)
            try:
                ctx.set_ciphers("DEFAULT:@SECLEVEL=0")  # allow SHA1/MD5 CA digests
            except _ssl.SSLError:
                pass  # some protocols don't support cipher strings
            if self._UniSSL__certfilename is not None:
                ctx.load_cert_chain(
                    certfile=self._UniSSL__certfilename,
                    keyfile=self._UniSSL__keyfilename,
                    password=self.password,
                )
            if self.verify is False:
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE
            else:
                if self.cacert is not None:
                    ctx.load_verify_locations(cafile=self._UniSSL__cacertfilename)
                else:
                    ctx.load_default_certs(purpose=_ssl.Purpose.SERVER_AUTH)
            return ctx
        finally:
            self._UniSSL__cleanup()

    _UniSSL.get_ssl_context = _bloodyad_get_ssl_context
