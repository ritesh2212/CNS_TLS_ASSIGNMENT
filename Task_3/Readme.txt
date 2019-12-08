Peer-to-peer Chat Application
--
The following is an implementation of Peer to Peer Chat Application using SSL sockets implemeted using OpenSSL in C. It doesn't require any other libraries and the compilation and execution step are listed below.

About the code
--
The source code for Peer to Peer Chat Application is given in "peer.c".

The file ‘mycert.pem’ act as the both peer's certificate file. All the packets are transferred using them. Both instances of program, peerA and peerB, read the 'mycert.pem' to encrypted and transfer the message packets among them.

For compiling the code,
--
$ gcc -Wall -o peerA peer.c -L/usr/lib -lssl -lcrypto -lpthread
$ gcc -Wall -o peerB peer.c -L/usr/lib -lssl -lcrypto -lpthread

To run the code,

$ ./peerA <Host IP> <Port for Server> <Port for Client>
$ ./peerB <Host IP> <Port for Server> <Port for Client>

After running the code, wait for 10 seconds and you can start the chat. The code needs to executed once and shall be closed using “Ctrl + C”.
