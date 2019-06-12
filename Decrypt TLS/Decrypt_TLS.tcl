when CLIENTSSL_HANDSHAKE {
    log local0. "# Client-Side TCP Connection info: [IP::client_addr]:[TCP::client_port] <-> [IP::local_addr]:[TCP::local_port]"
    log local0. "RSA Session-ID:[SSL::sessionid] Master-Key:[SSL::sessionsecret]"
}
when SERVERSSL_HANDSHAKE {
    log local0. "# Server-Side TCP Connection info: ([IP::local_addr]:[TCP::local_port] <-> [IP::server_addr]:[TCP::server_port]"
    log local0. "RSA Session-ID:[SSL::sessionid] Master-Key:[SSL::sessionsecret]"
}
