#ifndef MAIN_H
#define MAIN_H



#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <cerrno>
#include <csignal>
#include <iostream>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <cstdint>
#include <string>
#include <cstring>
#include <chrono>
#include <thread>

class Ping
{
  private:
    int Sockfd = -1;
    struct sockaddr_in Target_addr;
    uint16_t Sequence = 0;
    uint16_t Identifier = 0;

    struct Icmp_Packet
    {
      struct icmphdr Header;
      char data[56];
    };


    uint16_t Caluclate_checksum(uint16_t * buffer, size_t length) const;

    bool Sen_ping(uint32_t target_ip);

    bool Receive_ping() const;

    std::string Get_mac_address(const std::string & ip_address) const;

    std::string Read_proc_arp(const std::string & ip_address) const;

    std::string Execute_arp_command(const std::string & ip_address) const;

    std::string Extract_mac_from_line(const std::string & line) const;

    bool Is_valid_mac(const std::string & mac) const;

    std::string Format_mac_address(const std::string & mac) const;

    bool Resolve_and_ping(const std::string & target);


  public:
    Ping();

    ~Ping();


    bool Initialize();

    void Do_ping(const std::string & target);
};


void Signal_handler(int signal);

int main(int argc, char * argv[]);



#endif //MAIN_H