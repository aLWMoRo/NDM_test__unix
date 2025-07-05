cmake_minimum_required(VERSION 3.31)
project(NDM_test__unix)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (WIN32)
  message(FATAL_ERROR "Only for Linux")
endif()

include(CheckIncludeFileCXX)
check_include_file_cxx("sys/socket.h" HAVE_SYS_SOCKET_H)
check_include_file_cxx("netinet/ip.h" HAVE_NETINET_IP_H)
check_include_file_cxx("netinet/ip_icmp.h" HAVE_NETINET_IP_ICMP_H)

if (NOT HAVE_SYS_SOCKET_H OR
  NOT HAVE_NETINET_IP_H   OR
  NOT HAVE_NETINET_IP_ICMP_H
)
  message(FATAL_ERROR "Not found includes")
endif()

add_executable(NDM_test__unix main.cpp)

install(TARGETS NDM_test__unix DESTINATION bin)

add_custom_command(TARGET NDM_test__unix POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E echo "Warning: Start only with root"
  COMMAND ${CMAKE_COMMAND} -E echo "sudo ./NDM_test__unix <IP>"
  VERBATIM
)