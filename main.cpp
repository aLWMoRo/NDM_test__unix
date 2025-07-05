#include "main.h"



uint16_t Ping::Caluclate_checksum(uint16_t * buffer, size_t length) const
{
  uint32_t sum = 0;

  while (length > 1) {
    sum += *buffer++;
    length -= 2;
  };

  if (length == 1) {
    sum += *reinterpret_cast <uint8_t *> (buffer) << 8;
  };

  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  };

  return static_cast <uint16_t> (~sum);
};


bool Ping::Sen_ping(uint32_t target_ip)
{
  Icmp_Packet packet;
  std::memset(&packet, 0, sizeof(packet));

  packet.Header.type = ICMP_ECHO;
  packet.Header.code = 0;
  packet.Header.checksum = 0;
  packet.Header.un.echo.id = Identifier;
  packet.Header.un.echo.sequence = ++Sequence;

  const char * data_msg = "Ping ping ping ...";
  std::strncpy(packet.data, data_msg, sizeof(packet.data) - 1);

  const auto Tv = reinterpret_cast <struct timeval *> (packet.data);
  gettimeofday(Tv, nullptr);

  packet.Header.checksum = Caluclate_checksum(
    reinterpret_cast <uint16_t *>(&packet), sizeof(packet)
  );

  const ssize_t bytes_sent = sendto(Sockfd, &packet, sizeof(packet), 0,
    reinterpret_cast <struct sockaddr *>(&Target_addr), sizeof(Target_addr)
  );

  if (bytes_sent < 0) {
    std::cerr << "sendto() failed: " << strerror(errno) << std::endl;

    return false;
  };

  std::cout << "Send ICMP packet, Size = " << bytes_sent
    << " bytes, Sequence = " << Sequence
  << std::endl;

  return true;
};


bool Ping::Receive_ping() const
{
  char buffer[1024];
  struct sockaddr_in From_Addr;
  socklen_t from_len = sizeof(From_Addr);

  const ssize_t bytes_received = recvfrom(Sockfd, &buffer, sizeof(buffer), 0,
    reinterpret_cast <struct sockaddr *>(&From_Addr), &from_len
  );

  if (bytes_received < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      std::cout << "Response timeout" << std::endl;
    }
    else {
      std::cerr << "recvfrom() failed: " << strerror(errno) << std::endl;
    };

    return false;
  };

  const auto Ip_Header = reinterpret_cast <struct iphdr *>(buffer);

  if (const auto Icmp_Header =
    reinterpret_cast <struct icmphdr *>(buffer + (Ip_Header->ihl * 4));

    Icmp_Header->type != ICMP_ECHOREPLY
    && Icmp_Header->un.echo.id == Identifier
    && From_Addr.sin_addr.s_addr == Target_addr.sin_addr.s_addr
  ) {
    std:: cout << "Response received from "
      << inet_ntoa(From_Addr.sin_addr)
      << ": Bytes = " << bytes_received
      << ". Sequence = " << Icmp_Header->un.echo.sequence
    << std::endl;

    return true;
  };

  return false;
};


std::string Ping::Get_mac_address(const std::string & ip_address) const
{
  if (std::string mac = Read_proc_arp(ip_address);
    !mac.empty()
  ) {
    return mac;
  };

  return Execute_arp_command(ip_address);
};


std::string Ping::Read_proc_arp(const std::string & ip_address) const
{
  std::ifstream arp_file("/proc/net/arp");
  if (!arp_file.is_open()) {
    return "";
  };

  std::string line;
  while (std::getline(arp_file, line)) {
    std::istringstream iss(line);

    if (std::string ip, hw_type, flags, mac, mask, device;
      iss >> ip >> hw_type >> flags >> mac >> mask >> device
    ) {
      if (const std::string standart_mac = "00:00:00:00:00:00";
        ip == ip_address && mac != standart_mac && flags != "0x0"
      ) {
        return Format_mac_address(mac);
      };
    };
  };

  return "";
};


std::string Ping::Execute_arp_command(const std::string & ip_address) const
{
  const std::string command = "arp -n" + ip_address + " 2>/dev/null";
  FILE * pipe = popen(command.c_str(), "r");

  if (!pipe) {
    return "";
  };

  char buffer[256];
  std::string result;

  while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
    result += buffer;
  };

  if (const int exit_code = pclose(pipe);
    exit_code != 0
  ) {
    return "";
  };

  std::istringstream iss(result);
  std::string line;

  while (std::getline(iss, line)) {
    if (line.find(ip_address) != std::string::npos
      && line.find("incomplete") != std::string::npos
    ) {
      return Extract_mac_from_line(line);
    };
  };

  return "";
};


std::string Ping::Extract_mac_from_line(const std::string & line) const
{
  for (size_t i = 0; i < line.size() - 16; ++i) {
    if (std::isxdigit(line[i])
      && std::isxdigit(line[i + 1])
      && line[i + 2] == ':'
    ) {
      if (const std::string candidate = line.substr(i, 17);
        Is_valid_mac(candidate)
      ) {
        return Format_mac_address(candidate);
      };
    };
  };

  return "";
};


bool Ping::Is_valid_mac(const std::string & mac) const
{
  if (mac.size() != 17) {
    return false;
  };

  for (size_t i = 0; i < mac.size(); ++i) {
    if (i % 3 == 2) {
      if (mac[i] != ':') {
        return false;
      };
    }
    else {
      if (!std::isxdigit(mac[i])) {
        return false;
      };
    };
  };

  return true;
};


std::string Ping::Format_mac_address(const std::string & mac) const
{
  std::string formatted = mac;
  for (char & c : formatted) {
    c = static_cast<char> (std::toupper(c));
  };

  return formatted;
};


bool Ping::Resolve_and_ping(const std::string & target)
{
  std::memset(&Target_addr, 0, sizeof(Target_addr));
  Target_addr.sin_family = AF_INET;

  if (
    inet_pton(AF_INET, target.c_str(), &Target_addr.sin_addr) == 1
  ) {
    return true;
  };

  struct addrinfo Hints = {};
  struct addrinfo * Result = nullptr;

  Hints.ai_family = AF_INET;
  Hints.ai_socktype = SOCK_RAW;

  if (const int result =
    getaddrinfo(target.c_str(), nullptr, &Hints, &Result);

    result != 0 || !Result
  ) {
    std::cerr << "getaddrinfo() failed: "
      << gai_strerror(result) << "(" << target << ")"
    << std::endl;

    return false;
  };

  const auto Ipv4 = reinterpret_cast <struct sockaddr_in *>(Result->ai_addr);
  Target_addr.sin_addr = Ipv4->sin_addr;

  freeaddrinfo(Result);

  return true;
};


Ping::Ping()
{
  Identifier = getpid() & 0xFFFF;
};


Ping::~Ping()
{
  if (Sockfd != -1) {
    close(Sockfd);
  };
};


bool Ping::Initialize()
{
  Sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (Sockfd < 0) {
    std::cerr << "socket() failed" << strerror(errno) << std::endl;
    std::cerr << "Start with root" << std::endl;

    return false;
  };

  struct timeval Timeout;
  Timeout.tv_sec = 3;
  Timeout.tv_usec = 0;

  if (setsockopt(Sockfd, SOL_SOCKET,SO_RCVTIMEO,
      &Timeout, sizeof(Timeout)
    ) < 0
  ) {
    std::cerr << "setsockopt() failed" << strerror(errno) << std::endl;

    return false;
  };

  return true;
};


void Ping::Do_ping(const std::string & target)
{
  if (!Initialize()) {
    return;
  };

  if (!Resolve_and_ping(target)) {
    return;
  }

  std::cout << "Ping " << target << "("
    << inet_ntoa(Target_addr.sin_addr) << ")"
  << std::endl;

  for (int i = 0; i < 3; ++i) {
    if (Sen_ping(Target_addr.sin_addr.s_addr)) {
      if (Receive_ping()) {
        if (std::string mac = Get_mac_address(inet_ntoa(Target_addr.sin_addr));
          !mac.empty()
        ) {
          std::cout << "MAC address: " << mac << std::endl;
        }
        else {
          std::cout << "MAC address not found" << std::endl;
        };
      };
    };

    std::cout << std::endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
  };
};


void Signal_handler(int signal)
{
  if (signal == SIGINT) {
    std::cout << std::endl << "Programme interruption..." << std::endl;

    exit(0);
  };
};


int main(int argc, char * argv[])
{
  if (argc != 2) {
    std::cout << "Usage: " << argv[0] << " <IP address>" << std::endl;

    return 1;
  };

  signal(SIGINT, Signal_handler);

  try {
    Ping ping;
    ping.Do_ping(argv[1]);
  }
  catch (const std::exception & e) {
    std::cerr << "Error: " << e.what() << std::endl;

    return 1;
  };

  return 0;
};