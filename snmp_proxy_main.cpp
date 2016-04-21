/*
 * Copyright 2016 Boris Kochergin. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <boost/program_options.hpp>

#include "snmp_proxy.h"

int main(int argc, char* argv[]) {
  uint16_t port;
  std::string backend_community;
  std::time_t backend_timeout_sec;
  unsigned int num_backend_retries;
  std::time_t cache_ttl_sec;
  boost::program_options::options_description description("Available options");
  description.add_options()
      ("help", "print available options")
      ("port",
       boost::program_options::value<uint16_t>(&port)->default_value(161),
       "set port to listen on")
      ("backend_community",
       boost::program_options::value<std::string>(&backend_community),
       "set community to query on backend devices")
      ("backend_timeout_sec",
       boost::program_options::value<std::time_t>(&backend_timeout_sec)->
           default_value(2),
       "set timeout, in seconds, for querying backends")
      ("num_backend_retries",
       boost::program_options::value<unsigned int>(&num_backend_retries)->
           default_value(2),
       "set number of retries for querying backends")
      ("cache_ttl_sec",
       boost::program_options::value<std::time_t>(&cache_ttl_sec)->
           default_value(300),
       "set time-to-live, in seconds, for cache entries");
  boost::program_options::variables_map variables_map;
  boost::program_options::store(
      boost::program_options::parse_command_line(argc, argv, description),
      variables_map);
  boost::program_options::notify(variables_map);

  if (variables_map.count("help")) {
    std::cout << description << std::endl;
    return 1;
  }

  SNMPProxy snmp_proxy(port, backend_community, backend_timeout_sec,
                       num_backend_retries, cache_ttl_sec);
  if (!snmp_proxy.Start()) {
    return 1;
  }
  return 0;
}
