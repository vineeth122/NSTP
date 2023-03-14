from collections import defaultdict
import sys
import pickle
import struct
import time
import hashlib
import asyncio
from typing import Optional
import socket
import tomlkit
from nstp_pb2 import *
from nacl.bindings import \
    crypto_box_keypair, \
    crypto_sign_keypair, crypto_sign_ed25519ph_state, crypto_sign_ed25519ph_update, crypto_sign_ed25519ph_final_create, \
    crypto_kx_server_session_keys, crypto_sign_ed25519ph_final_verify,crypto_secretbox_open as dec_mt, crypto_secretbox as enc_mt
from nacl.utils import random


VALID_LENGTH_SEC = 60 * 60 * 24 * 14


def hash_certificate(h, cert: Certificate) -> bytes:
    for x in cert.subjects:
        h.update(x.encode())
    h.update(struct.pack(">Q", cert.valid_from))
    h.update(struct.pack(">I", cert.valid_length))
    for x in cert.usages:
        if x == CertificateUsage.CERTIFICATE_SIGNING:
            h.update(struct.pack("B", 0))
        elif x == CertificateUsage.CLIENT_AUTHENTICATION:
            h.update(struct.pack("B", 1))
        elif x == CertificateUsage.SERVER_AUTHENTICATION:
            h.update(struct.pack("B", 2))
        elif x == CertificateUsage.STATUS_SIGNING:
            h.update(struct.pack("B", 3))
        else:
            raise Exception("invalid usage")
    h.update(cert.encryption_public_key)
    h.update(cert.signing_public_key)

    if cert.HasField("issuer"):
        h.update(cert.issuer.value)
        if cert.issuer.algorithm == HashAlgorithm.SHA256:
            h.update(struct.pack("B", 1))
        elif cert.issuer.algorithm == HashAlgorithm.SHA512:
            h.update(struct.pack("B", 2))
        else:
            raise Exception("invalid issuer algorithm")

    h.update(cert.issuer_signature)
    return h.digest()


def hash_certificate_sha256(cert: Certificate) -> bytes:
    return hash_certificate(hashlib.sha256(), cert)


def hash_certificate_sha512(cert: Certificate) -> bytes:
    return hash_certificate(hashlib.sha512(), cert)


def certificate_signing_state(state, cert: Certificate, include_signature: bool):
    for x in cert.subjects:
        crypto_sign_ed25519ph_update(state, x.encode())
    crypto_sign_ed25519ph_update(state, struct.pack(">Q", cert.valid_from))
    crypto_sign_ed25519ph_update(state, struct.pack(">I", cert.valid_length))
    for x in cert.usages:
        if x == CertificateUsage.CERTIFICATE_SIGNING:
            crypto_sign_ed25519ph_update(state, struct.pack("B", 0))
        elif x == CertificateUsage.CLIENT_AUTHENTICATION:
            crypto_sign_ed25519ph_update(state, struct.pack("B", 1))
        elif x == CertificateUsage.SERVER_AUTHENTICATION:
            crypto_sign_ed25519ph_update(state, struct.pack("B", 2))
        elif x == CertificateUsage.STATUS_SIGNING:
            crypto_sign_ed25519ph_update(state, struct.pack("B", 3))
    crypto_sign_ed25519ph_update(state, cert.encryption_public_key)
    crypto_sign_ed25519ph_update(state, cert.signing_public_key)
    if cert.HasField("issuer"):
        crypto_sign_ed25519ph_update(state, cert.issuer.value)
        if cert.issuer.algorithm == HashAlgorithm.IDENTITY:
            crypto_sign_ed25519ph_update(state, struct.pack("B", 0))
        elif cert.issuer.algorithm == HashAlgorithm.SHA256:
            crypto_sign_ed25519ph_update(state, struct.pack("B", 1))
        elif cert.issuer.algorithm == HashAlgorithm.SHA512:
            crypto_sign_ed25519ph_update(state, struct.pack("B", 2))
    if include_signature:
        crypto_sign_ed25519ph_update(state, cert.issuer_signature)
    return state


def status_signing_state(state, status: CertificateStatus):
    crypto_sign_ed25519ph_update(state, status.certificate.value)
    if status.certificate.algorithm == HashAlgorithm.IDENTITY:
        crypto_sign_ed25519ph_update(state, struct.pack("B", 0))
    elif status.certificate.algorithm == HashAlgorithm.SHA256:
        crypto_sign_ed25519ph_update(state, struct.pack("B", 1))
    elif status.certificate.algorithm == HashAlgorithm.SHA512:
        crypto_sign_ed25519ph_update(state, struct.pack("B", 2))
    if status.status == CertificateStatus.UNKNOWN:
        crypto_sign_ed25519ph_update(state, struct.pack("B", 0))
    elif status.status == CertificateStatus.VALID:
        crypto_sign_ed25519ph_update(state, struct.pack("B", 1))
    elif status.status == CertificateStatus.INVALID:
        crypto_sign_ed25519ph_update(state, struct.pack("B", 2))
    crypto_sign_ed25519ph_update(state, struct.pack(">Q", status.valid_from))
    crypto_sign_ed25519ph_update(state, struct.pack(">I", status.valid_length))
    state = certificate_signing_state(state, status.status_certificate, True)
    return state


def create_certificate(subjects: list[str],
                       valid_length: int,
                       usages: list[CertificateUsage],
                       encryption_key: bytes,
                       signing_key: bytes,
                       issuer: Optional[CertificateHash],
                       issuer_signing_key: bytes) -> Certificate:
    cert = Certificate()
    for x in subjects:
        cert.subjects.append(x)
    cert.valid_from = int(time.time())
    cert.valid_length = valid_length
    for x in usages:
        cert.usages.append(x)
    cert.encryption_public_key = encryption_key
    cert.signing_public_key = signing_key
    if issuer is not None:
        cert.issuer.CopyFrom(issuer)
    state = crypto_sign_ed25519ph_state()
    state = certificate_signing_state(state, cert, False)
    cert.issuer_signature = crypto_sign_ed25519ph_final_create(state, issuer_signing_key)
    return cert


def create_private_key(cert, encryption_key, signing_key):
    key = PrivateKey()
    key.certificate.value = hash_certificate_sha512(cert)
    key.certificate.algorithm = HashAlgorithm.SHA512
    key.encryption_private_key = encryption_key
    key.signing_private_key = signing_key
    return key


def init_pki():
    e_pub_key, e_sec_key = crypto_box_keypair()
    s_pub_key, s_sec_key = crypto_sign_keypair()

    ca_cert = create_certificate(["CA"],
                                 VALID_LENGTH_SEC,
                                 [CertificateUsage.CERTIFICATE_SIGNING],
                                 e_pub_key,
                                 s_pub_key,
                                 None,
                                 s_sec_key)
    trust_store = CertificateStore()
    with open("pki/ca.crt", "wb") as fd:
        fd.write(trust_store.SerializeToString())

    trust_store.certificates.append(ca_cert)
    with open("pki/ca_store", "wb") as fd:
        fd.write(trust_store.SerializeToString())

    ca_key = create_private_key(ca_cert, e_sec_key, s_sec_key)
    with open("pki/ca.key", "wb") as fd:
        fd.write(ca_key.SerializeToString())

    issuer_hash = CertificateHash()
    issuer_hash.value = hash_certificate_sha256(ca_cert)
    issuer_hash.algorithm = HashAlgorithm.SHA256

    e_pub_key, e_sec_key = crypto_box_keypair()
    s_pub_key, s_sec_key = crypto_sign_keypair()
    server_cert = create_certificate(["localhost", "127.0.0.1", "::1","10.0.0.154","10.110.89.127"],
                                     VALID_LENGTH_SEC,
                                     [CertificateUsage.SERVER_AUTHENTICATION],
                                     e_pub_key,
                                     s_pub_key,
                                     issuer_hash,
                                     ca_key.signing_private_key)
    with open("pki/server.crt", "wb") as fd:
        fd.write(server_cert.SerializeToString())

    server_key = create_private_key(server_cert, e_sec_key, s_sec_key)
    with open("pki/server.key", "wb") as fd:
        fd.write(server_key.SerializeToString())

    e_pub_key, e_sec_key = crypto_box_keypair()
    s_pub_key, s_sec_key = crypto_sign_keypair()
    client_cert = create_certificate(["mario"],
                                     VALID_LENGTH_SEC,
                                     [CertificateUsage.CLIENT_AUTHENTICATION],
                                     e_pub_key,
                                     s_pub_key,
                                     issuer_hash,
                                     ca_key.signing_private_key)
    with open("pki/client.crt", "wb") as fd:
        fd.write(client_cert.SerializeToString())

    client_key = create_private_key(client_cert, e_sec_key, s_sec_key)
    with open("pki/client.key", "wb") as fd:
        fd.write(client_key.SerializeToString())
    
    pin_cert=PinnedCertificate()
    pin_cert2=PinnedCertificate()
    pin_cert.subject= client_cert.subjects[0]
    pin_cert2.subject= client_cert.subjects[0]
    pin_cert.certificate.value = hash_certificate_sha256(client_cert)
    pin_cert2.certificate.value = hash_certificate_sha512(client_cert)
    pin_cert.certificate.algorithm = HashAlgorithm.SHA256
    pin_cert2.certificate.algorithm = HashAlgorithm.SHA512
    pin_cert_store=PinnedCertificateStore()
    pin_cert_store.pinned_certificates.append(pin_cert)
    pin_cert_store.pinned_certificates.append(pin_cert2)
    #print(len(pin_cert_store.pinned_certificates))

    with open("pki/pinned_certs", "wb") as fd:
        fd.write(pin_cert_store.SerializeToString())

    e_pub_key, e_sec_key = crypto_box_keypair()
    s_pub_key, s_sec_key = crypto_sign_keypair()
    status_cert = create_certificate(["CA Status Server"],
                                     VALID_LENGTH_SEC,
                                     [CertificateUsage.STATUS_SIGNING],
                                     e_pub_key,
                                     s_pub_key,
                                     issuer_hash,
                                     ca_key.signing_private_key)
    with open("pki/status.crt", "wb") as fd:
        fd.write(status_cert.SerializeToString())

    status_key = create_private_key(status_cert, e_sec_key, s_sec_key)
    with open("pki/status.key", "wb") as fd:
        fd.write(status_key.SerializeToString())

    server_hash = CertificateHash()
    server_hash.value = hash_certificate_sha512(server_cert)
    server_hash.algorithm = HashAlgorithm.SHA512
    status_response = CertificateStatusResponse()
    status_response.certificate.CopyFrom(server_hash)
    status_response.status = CertificateStatus.VALID
    status_response.valid_from = int(time.time())
    status_response.valid_length = 60 * 60
    status_response.status_certificate.CopyFrom(status_cert)
    state = crypto_sign_ed25519ph_state()
    state = status_signing_state(state, status_response)
    status_response.status_signature = crypto_sign_ed25519ph_final_create(state, status_key.signing_private_key)
    with open("pki/server_status", "wb") as fd:
        fd.write(status_response.SerializeToString())


def validate_certificate(cert, signing_public_key):
    # What other checks should be performed on a certificate?
    state = crypto_sign_ed25519ph_state()
    state = certificate_signing_state(state, cert, False)
    
    return crypto_sign_ed25519ph_final_verify(state, cert.issuer_signature, signing_public_key)

def sg_ca_pub_key(h,cl_cert_iss_val):
    for i in ca_store_list:
            if hash_certificate(h,i) ==  cl_cert_iss_val:
                cl_pub_key=i.signing_public_key
                break    
    return cl_pub_key

def validate_st_resp(client_st_resp):
    status=client_st_resp.status
    cert_resp_from = client_st_resp.valid_from
    cert_resp_len = client_st_resp.valid_length
    st_resp_from = client_st_resp.status_certificate.valid_from
    st_resp_len =  client_st_resp.status_certificate.valid_length
    st_resp_usg =  client_st_resp.status_certificate.usages
    st_resp_sigpub= client_st_resp.status_certificate.signing_public_key
    st_resp_iss_val = client_st_resp.status_certificate.issuer.value
    st_resp_iss_alg = client_st_resp.status_certificate.issuer.algorithm
    st_resp_iss_sig = client_st_resp.status_certificate.issuer_signature
    st_resp_st_sig = client_st_resp.status_signature
    
    state = crypto_sign_ed25519ph_state()
    state = status_signing_state(state, client_st_resp)
    if st_resp_iss_alg == HashAlgorithm.SHA256:
        cl_sg_pub_key=sg_ca_pub_key(hashlib.sha256(),st_resp_iss_val)
    elif st_resp_iss_alg == HashAlgorithm.SHA512:
        cl_sg_pub_key=sg_ca_pub_key(hashlib.sha512(),st_resp_iss_val)
    if status == VALID and int(time.time()) >= cert_resp_from and int(time.time()) <= (cert_resp_len+cert_resp_from):
        if int(time.time()) >= st_resp_from and int(time.time()) <= (st_resp_from+st_resp_len):
            if CertificateUsage.STATUS_SIGNING in st_resp_usg:
                if validate_certificate(client_st_resp.status_certificate,cl_sg_pub_key):
                    if(crypto_sign_ed25519ph_final_verify(state, st_resp_st_sig, st_resp_sigpub)):
                        return True
                    else:
                        raise Exception("Validation Failed")
                        return False
                else:
                    raise Exception("Validation Failed")
                    return False
            else:
                raise Exception("Validation Failed")
                return False
        else:
            raise Exception("Validation Failed")
            return False
    else:
        raise Exception("Validation Failed")
        return False
                
def val_client_cert(hello):
    #client_cert = Certificate()
    #client_cert.ParseFromString(hello.client_hello.certificate)
    client_cert= hello.client_hello.certificate
    client_st_resp=hello.client_hello.certificate_status
    cl_subjects=client_cert.subjects
    cl_valid_from=client_cert.valid_from
    cl_valid_length=client_cert.valid_length
    cl_cert_usg=client_cert.usages
    cl_cert_enc_pub=client_cert.encryption_public_key
    cl_cert_sigpub=client_cert.signing_public_key
    cl_cert_iss_val = client_cert.issuer.value
    cl_cert_iss_alg = client_cert.issuer.algorithm
    cl_cert_iss_sig = client_cert.issuer_signature
    if cl_cert_iss_alg == HashAlgorithm.SHA256:
        cl_sg_pub_key=sg_ca_pub_key(hashlib.sha256(),cl_cert_iss_val)
    elif cl_cert_iss_alg == HashAlgorithm.SHA512:
        cl_sg_pub_key=sg_ca_pub_key(hashlib.sha512(),cl_cert_iss_val)
    try:   
        if  (hash_certificate_sha256(client_cert) in cert_pin_dict[cl_subjects[0]]) or (hash_certificate_sha512(client_cert) in cert_pin_dict[cl_subjects[0]]):
            if len(cl_subjects) == 1 and int(time.time()) > cl_valid_from and int(time.time()) < (cl_valid_length+cl_valid_from):
                if  CertificateUsage.CLIENT_AUTHENTICATION in cl_cert_usg:
                    if validate_certificate(client_cert,cl_sg_pub_key):
                        if validate_st_resp(client_st_resp):
                            return True
                    else:
                        raise Exception("Validation Failed")
                        return False
                else:
                    raise Exception("Validation Failed")
                    return False
            else:
                raise Exception("Validation Failed")
                return False
        else:
            raise Exception("Validation Failed")
            return False
    except Exception as e:
        return False

def str_request_mt(client_sub,dec_msg):
    str_req_key=dec_msg.store_request.key
    str_req_value=dec_msg.store_request.value
    str_req_public=dec_msg.store_request.public
    if len(str_req_key) == 0:
        str_req_key="empty"
    if str_req_public:
        with open("p"+f"{str_req_key}", "wb") as f:
            pickle.dump(str_req_value,f)
    else:
        with open(f"{client_sub}"+"_"+f"{str_req_key}","wb") as f:
            
            pickle.dump(str_req_value,f)
    str_resp=StoreResponse()
    #print(dec_msg.store_request.SerializeToString())
    str_resp.hash=hashlib.sha256(dec_msg.store_request.SerializeToString()).digest()
    str_resp.hash_algorithm = HashAlgorithm.SHA256
    return str_resp

def ld_req(client_sub,dec_msg):
    ld_req_key=dec_msg.load_request.key
    ld_req_public=dec_msg.load_request.public
    ld_resp=LoadResponse()
    if len(ld_req_key) == 0:
        ld_req_key="empty"
    if ld_req_public:
        with open("p"+f"{ld_req_key}", "rb") as f:
            ld_resp.value=pickle.load(f)
    else:
        try:
            with open(f"{client_sub}"+"_"+f"{ld_req_key}","rb") as f:
                ld_resp.value=pickle.load(f)
        except:
            ld_resp.value=b""
    return ld_resp

def pg_req(dec_msg):
    pg_req_data=dec_msg.ping_request.data
    pg_req_alg=dec_msg.ping_request.hash_algorithm
    pg_resp=PingResponse()
    if pg_req_alg == HashAlgorithm.SHA256:
        pg_resp.hash=hashlib.sha256(pg_req_data).digest()
    elif pg_req_alg == HashAlgorithm.SHA512:
        pg_resp.hash=hashlib.sha512(pg_req_data).digest()
    return pg_resp


def enc_resp(fin_resp,w_key,req_type):
    dec_str_resp=DecryptedMessage()
    if req_type == StoreResponse:
        dec_str_resp.store_response.CopyFrom(fin_resp)
    elif req_type == LoadResponse:
        dec_str_resp.load_response.CopyFrom(fin_resp)
    elif req_type == PingResponse:
        dec_str_resp.ping_response.CopyFrom(fin_resp)
    enc_dec_msg=EncryptedMessage()
    #print(str_resp.SerializeToString())
    enc_dec_msg_nonce = random(24)
    enc_dec_msg.ciphertext=enc_mt(dec_str_resp.SerializeToString(),enc_dec_msg_nonce,w_key)
    enc_dec_msg.nonce=enc_dec_msg_nonce
    final_nstp_msg=NSTPMessage()
    final_nstp_msg.encrypted_message.CopyFrom(enc_dec_msg)
    #print(final_nstp_msg)
    final_nstp_msg_dat=final_nstp_msg.SerializeToString()
    return final_nstp_msg_dat

async def on_client(r: asyncio.StreamReader, w: asyncio.StreamWriter):
    # These paths should be read from your configuration file
    ca_store = CertificateStore()
    #ca_store.ParseFromString(open("pki/ca_store", "rb").read())
    ca_store.ParseFromString(open(trusted_ca_store, "rb").read())
    assert (len(ca_store.certificates) > 0)
    server_cert = Certificate()
    #server_cert.ParseFromString(open("pki/server.crt", "rb").read())
    server_cert.ParseFromString(open(server_crt_conf, "rb").read())
    server_key = PrivateKey()
    server_key.ParseFromString(open(server_pvt_key_conf, "rb").read())

    # We will staple a status here, but this is not the only case to handle
    # status_response = CertificateStatusResponse()
    # status_response.ParseFromString(open("pki/server_status", "rb").read())

    # Read in a hello and do some basic checks
    hello = NSTPMessage()
    hello_size = struct.unpack(">H", await r.readexactly(2))[0]
    hello.ParseFromString(await r.readexactly(hello_size))
    try:
        if hello.HasField("client_hello"):
            cert_st_req=CertificateStatusRequest()
            #print(cert_st_req)
            cert_hash=CertificateHash()
            cert_hash.value=hash_certificate_sha256(hello.client_hello.certificate)
            cert_hash.algorithm = HashAlgorithm.SHA256
            cert_st_req.certificate.CopyFrom(cert_hash)
            client_sub=hello.client_hello.certificate.subjects[0]
            if not hello.client_hello.HasField("certificate_status"):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
                sock.sendto(cert_st_req.SerializeToString(), (status_server_address,int(status_server_port)))
                crt_st_dat=CertificateStatusResponse()
                crt_st_dat.ParseFromString(sock.recvfrom(1500)[0])
                hello.client_hello.certificate_status.CopyFrom(crt_st_dat)
            if hello.client_hello.certificate_status.status == UNKNOWN:
                raise Exception("ocsp certificate invalid")
            cl_val_check=val_client_cert(hello)
        if not hello.HasField("client_hello"):
            raise Exception("expected client hello")
        if hello.client_hello.major_version != 4:
            raise Exception("unexpected major version")

        # Create our own hello
        if cl_val_check:
            sr_cert_st_req=CertificateStatusRequest()
            #print(cert_st_req)
            sr_cert_hash=CertificateHash()
            sr_cert_hash.value=hash_certificate_sha256(server_cert)
            sr_cert_hash.algorithm = HashAlgorithm.SHA256
            sr_cert_st_req.certificate.CopyFrom(sr_cert_hash)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
            sock.sendto(sr_cert_st_req.SerializeToString(), (status_server_address,int(status_server_port)))
            sr_crt_st_dat=CertificateStatusResponse()
            sr_crt_st_dat.ParseFromString(sock.recvfrom(2048)[0])
            m = NSTPMessage()
            m.server_hello.major_version = 4
            m.server_hello.minor_version = 4
            m.server_hello.user_agent = "hi"
            m.server_hello.certificate.CopyFrom(server_cert)
            m.server_hello.certificate_status.CopyFrom(sr_crt_st_dat)
            m_data = m.SerializeToString()
            w.write(struct.pack(">H", len(m_data)))
            w.write(m_data)
            await w.drain()
            r_key, w_key = crypto_kx_server_session_keys(server_cert.encryption_public_key,
                                                        server_key.encryption_private_key,
                                                        hello.client_hello.certificate.encryption_public_key)
            while True:
                try:
                    m = NSTPMessage()
                    await asyncio.wait_for(r.readexactly(size), timeout=5)
                    m_size = struct.unpack(">H", await asyncio.wait_for(r.readexactly(2),timeout=5))[0]
                    
                    m.ParseFromString(await asyncio.wait_for(r.readexactly(m_size),timeout=5))
                    if not m.HasField("encrypted_message"):
                        raise Exception("expected encrypted message")
                    else:
                        enc_msg=m.encrypted_message.ciphertext
                        enc_nonce=m.encrypted_message.nonce
                        dec_msg=DecryptedMessage()
                        dec_msg.ParseFromString(dec_mt(enc_msg,enc_nonce,r_key))
                        if dec_msg.HasField("store_request"):                    
                            str_resp=str_request_mt(client_sub,dec_msg)                    
                            final_nstp_msg_dat=enc_resp(str_resp,w_key,type(str_resp))
                        elif dec_msg.HasField("load_request"):
                            ld_resp=ld_req(client_sub,dec_msg)
                            final_nstp_msg_dat=enc_resp(ld_resp,w_key,type(ld_resp))
                        elif dec_msg.HasField("ping_request"):
                            pg_resp=pg_req(dec_msg)
                            final_nstp_msg_dat=enc_resp(pg_resp,w_key,type(pg_resp))
                        else:
                            raise Exception("Error Message")
                        w.write(struct.pack(">H", len(final_nstp_msg_dat)))
                        w.write(final_nstp_msg_dat)
                        await w.drain()
                except Exception as e:
                    w.close()
                    break
        else:
            raise Exception("validation failed")
            w.close()
    except Exception as e:
        w.close()


async def nstpd():
    server = await asyncio.start_server(on_client, nstp_server_address, int(nstp_server_port))
    async with server:
        await server.serve_forever()

cert_pin_dict=defaultdict(list)
ca_store_list=[]
nstp_config=tomlkit.load(open(sys.argv[1],"r"))
nstp_server_address,nstp_server_port=nstp_config['nstp_server_address'].split(":")
status_server_address,status_server_port=nstp_config['status_server_address'].split(":")
trusted_ca_store=nstp_config['trusted_certificate_store']
pinned_ca_store=nstp_config['pinned_certificate_store']
server_crt_conf = nstp_config['server_certificate']
server_pvt_key_conf= nstp_config['server_private_key']
def main():
    
    val_cert_pin = PinnedCertificateStore()
    #val_cert_pin.ParseFromString(open("pki/pinned_certs", "rb").read())
    val_cert_pin.ParseFromString(open(pinned_ca_store, "rb").read())
    for i in val_cert_pin.pinned_certificates:
        cert_pin_dict[i.subject].append(i.certificate.value)
    ca_store_f = CertificateStore()
    #ca_store_f.ParseFromString(open("pki/ca_store", "rb").read())
    ca_store_f.ParseFromString(open(trusted_ca_store, "rb").read())
    for i in ca_store_f.certificates:
        if int(time.time()) > i.valid_from and int(time.time()) < (i.valid_from+i.valid_length):
            ca_store_list.append(i)
            #ca_store_list.append(i.signing_public_key)
    asyncio.run(nstpd())


if __name__ == "__main__":
    main()