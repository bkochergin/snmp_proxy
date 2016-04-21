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

#include <condition_variable>
#include <cstdint>
#include <ctime>
#include <mutex>
#include <string>
#include <unordered_map>

#include <boost/array.hpp>
#include <boost/asio.hpp>

using boost::asio::ip::udp;

class SNMPProxy {
 public:
  SNMPProxy(uint16_t port, const std::string& backend_community,
            std::time_t backend_timeout_sec, unsigned int num_backend_retries,
            std::time_t cache_ttl_sec);
  bool Start();

 private:
  class SNMPSequence {
   public:
    // Parses a Layer-4 payload into an SNMP sequence.
    SNMPSequence(const char* start, const char* end);

    bool initialized() const;
    const std::string& community() const;
    const std::string& community_index() const;
    uint8_t pdu_type() const;
    uint32_t request_id() const;
    const std::string& data() const;

    void set_community(const std::string& community);
    void set_pdu_type(uint8_t pdu_type);
    void set_error(uint8_t error);
    void set_data(const std::string& data);

    // Serializes the sequence into a Layer-4 payload suitable for sending over 
    // the network.
    std::string Serialize() const;

   private:
    bool initialized_;
    uint64_t length_;
    std::string community_;
    std::string community_index_;
    uint8_t pdu_type_;
    uint64_t pdu_length_;
    uint32_t request_id_;

    // All data after the request ID.
    std::string data_;

    // Decodes an ASN.1 BER-encoded short-form or long-form integer.
    static uint8_t DecodeASN1Int(const char* start, const char* end,
                                 uint64_t* result);

    // Encodes an integer into an ASN.1 BER-encoded short-form or long-form
    // integer.
    static std::string EncodeASN1Int(uint64_t input);
  };

  class CacheKey {
   public:
    CacheKey(const std::string& backend_host,
             const std::string& community, const std::string& community_index,
             uint8_t request_type, const std::string& request_data);

    bool operator==(const CacheKey& other) const;

    struct Hash {
      size_t operator()(const CacheKey& cache_key) const;
    };

   private:
    const std::string backend_host_;
    const std::string community_;
    const std::string community_index_;
    const uint8_t request_type_;
    const std::string request_data_;
  };

  class CacheValue {
   public:
    CacheValue();
    CacheValue(const std::string& response_data);
    const std::string& response_data() const;
    std::time_t time() const;

   private:
    std::string response_data_;
    std::time_t time_;
  };

  const uint16_t port_;
  const std::string backend_community_;
  const std::time_t backend_timeout_sec_;
  const unsigned int num_backend_retries_;
  const std::time_t cache_ttl_sec_;
  boost::asio::io_service io_service_;
  std::unordered_map<CacheKey, CacheValue, CacheKey::Hash> cache_;
  std::mutex mutex_;

  std::string GetResponse(const std::string& backend_host,
                          const SNMPSequence& snmp_request);

  void TimeoutRead(boost::asio::ip::udp::socket& socket,
                   std::condition_variable* cv);
                            
  void Read(size_t bytes_transferred, size_t* response_size,
            std::condition_variable* cv);

  void EvictStaleCacheEntries();
};
