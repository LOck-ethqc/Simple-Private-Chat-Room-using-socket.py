# Simple Private Chat Room using socket.py
TL;DR Private chat room implemented with Vigenère &amp; AES cryptographic security measure && supports Authenticated Encryption via MD5 Hashing.

Simple chat server I built 3 days before my Graduation Project Presentation, to demonstrate and back up the main project's idea.
Feel free to use it as a resource to fulfill your needs.

Description:
Programming Language: Python
Cryptographic System: Cascade Ciphering(Vigenère + AES)
AES Operation Mode: ECB(Electronic CodeBook)
AE(Authentication Encryption): EtM(Encrypt-then-MAC)
MAC(Message Authentication Code): MD5 Hash

Limitations:
- Messages sent & received are limited to 128 bits(16 characters), larger bits will lead to the termination of the communication channel.
- Only English Alphabet characters are eligible to be used(special characters are excluded).
- AES Encryption is processed once(1-Round).
- Communication between the two parties is in static turns(Alpha first, then Bravo, then again Alpha, etc...)

How To Use:
1) Save both source codes--Client.py & Server.py--to your machine.
2) Run CMD and execute Server.py first.
   - py Server.py
3) Run another CMD and execute Client.py.
   - py Client.py
