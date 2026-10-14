"""
Signed chat demo: shows how private/public keys and digital signatures work.

Install once:   pip install cryptography

Person A (host):    python signed_chat.py host
Person B (joiner):  python signed_chat.py join <A's WiFi IP>

Find A's IP:  Windows: ipconfig | Mac/Linux: ifconfig or ip a  (look for 192.168.x.x)
Commands while chatting:
  /tamper   toggle "attacker mode": your message is altered AFTER signing,
            so your friend's verification should FAIL
  /quit     exit
"""
import hashlib
import json
import socket
import sys
import threading

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

PORT = 5050
tamper = False


def send(sock, obj):
    sock.sendall((json.dumps(obj) + "\n").encode())


def recv_loop(sock, peer_pub):
    buf = b""
    while True:
        data = sock.recv(4096)
        if not data:
            print("\n[friend disconnected]")
            break
        buf += data
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            msg = json.loads(line)
            text = msg["text"]
            sig = bytes.fromhex(msg["sig"])
            print(f"\n--- received: {text!r}")
            print(f"  1. I hash the message myself (SHA-256): "
                  f"{hashlib.sha256(text.encode()).hexdigest()[:32]}...")
            print(f"  2. Signature from friend (hex):        {sig.hex()[:32]}...")
            try:
                peer_pub.verify(
                    sig, text.encode(),
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256())
                print("  3. Verify with friend's PUBLIC key: VALID "
                      "(authentic + unchanged)")
            except InvalidSignature:
                print("  3. Verify with friend's PUBLIC key: INVALID "
                      "(message changed or not signed by them!)")
            print("you> ", end="", flush=True)


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("host", "join"):
        print(__doc__)
        return

    print("Generating your key pair (private + public)...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    my_pub_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    if sys.argv[1] == "host":
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", PORT))
        server.listen(1)
        print(f"Waiting for your friend on port {PORT}...")
        sock, addr = server.accept()
        print(f"Friend connected from {addr[0]}")
    else:
        sock = socket.socket()
        sock.connect((sys.argv[2], PORT))
        print("Connected to host")

    # Step 0: exchange PUBLIC keys only. Private keys never leave this machine.
    send(sock, {"pub": my_pub_pem})
    line = b""
    while not line.endswith(b"\n"):
        line += sock.recv(1)
    peer_pem = json.loads(line)["pub"]
    peer_pub = serialization.load_pem_public_key(peer_pem.encode())
    print("Exchanged public keys. Friend's public key fingerprint:",
          hashlib.sha256(peer_pem.encode()).hexdigest()[:16])
    print("Type a message. /tamper toggles attacker mode, /quit exits.\n")

    threading.Thread(target=recv_loop, args=(sock, peer_pub), daemon=True).start()

    global tamper
    while True:
        text = input("you> ")
        if text == "/quit":
            break
        if text == "/tamper":
            tamper = not tamper
            print(f"[tamper mode {'ON' if tamper else 'OFF'}]")
            continue
        digest = hashlib.sha256(text.encode()).hexdigest()
        sig = private_key.sign(
            text.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
        print(f"  1. Hash of my message (SHA-256): {digest[:32]}...")
        print(f"  2. Signed with my PRIVATE key:   {sig.hex()[:32]}...")
        out_text = text + " (altered!)" if tamper else text
        if tamper:
            print("  ! Message altered after signing, as an attacker would")
        send(sock, {"text": out_text, "sig": sig.hex()})
    sock.close()


if __name__ == "__main__":
    main()