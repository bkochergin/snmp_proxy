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

#include <chrono>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <thread>

#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <boost/bind.hpp>

#include "snmp_proxy.h"

static const uint8_t kSequenceType = 0x30;
static const uint8_t kIntegerType = 0x02;
static const uint8_t kStringType = 0x04;
static const std::string kSNMPv2cVersion = "\x02\x01\x01";
static const uint8_t kGetRequestPDUType = 0xa0;
static const uint8_t kGetNextRequestPDUType = 0xa1;
static const uint8_t kGetResponsePDUType = 0xa2;
static const uint8_t kGetBulkRequestPDUType = 0xa5;
static const uint8_t kResourceUnavailableError = 0xd;

SNMPProxy::SNMPProxy(uint16_t port, const std::string& backend_community,
                     std::time_t backend_timeout_sec,
                     unsigned int num_backend_retries,
                     std::time_t cache_ttl_sec) :
    port_(port), backend_community_(backend_community),
    backend_timeout_sec_(backend_timeout_sec),
    num_backend_retries_(num_backend_retries), cache_ttl_sec_(cache_ttl_sec) {}

bool SNMPProxy::Start() {
  udp::socket socket(io_service_);
  socket.open(udp::v4());
  boost::system::error_code error;
  socket.bind(udp::endpoint(udp::v4(), port_), error);
  if (error) {
    std::cerr << "Could not bind to port " << port_ << ": " << error.message()
              << std::endl;
    return false;
  }
  std::thread eviction_thread(&SNMPProxy::EvictStaleCacheEntries, this);
  eviction_thread.detach();
  while (true) {
    boost::array<char, 65536> packet;
    udp::endpoint remote_endpoint;
    boost::system::error_code error;
    const size_t packet_size =
        socket.receive_from(boost::asio::buffer(packet), remote_endpoint, 0,
                             error);
    SNMPSequence snmp_sequence(packet.data(), packet.data() + packet_size);

    if (!snmp_sequence.initialized() ||
        (snmp_sequence.pdu_type() != kGetRequestPDUType &&
         snmp_sequence.pdu_type() != kGetNextRequestPDUType &&
         snmp_sequence.pdu_type() != kGetBulkRequestPDUType)) {
      continue;
    }

    std::cout << "Got SNMPv2c request from " << remote_endpoint
              << " (community=" << snmp_sequence.community()
              << snmp_sequence.community_index() << ")." << std::endl;

    if (error && error != boost::asio::error::message_size) {
      throw boost::system::system_error(error);
    }

    boost::system::error_code ignored_error;
    const std::string backend_host = snmp_sequence.community();
    snmp_sequence.set_community(backend_community_ +
                                snmp_sequence.community_index());
    socket.send_to(
        boost::asio::buffer(GetResponse(backend_host, snmp_sequence)),
        remote_endpoint, 0, ignored_error);
  }
  return true;
}

SNMPProxy::SNMPSequence::SNMPSequence(const char* start, const char* end) :
    initialized_(false) {
  if (end - start < 7) {
    return;
  }

  // SNMP message type (sequence).
  if (*start != kSequenceType) {
    return;
  }

  // Sequence length.
  ++start;
  start += DecodeASN1Int(start, end, &length_);
  if (length_ == 0) {
    return;
  }

  // SNMP version (v2c).
  if (memcmp(start, kSNMPv2cVersion.c_str(), kSNMPv2cVersion.size()) != 0) {
    return;
  }

  // Community string type.
  start += kSNMPv2cVersion.size();
  if (*start != kStringType) {
    return;
  }

  // Community string length.
  ++start;
  uint64_t community_length;
  start += DecodeASN1Int(start, end, &community_length);
  if (community_length == 0) {
    return;
  }

  // Community string.
  if (start + community_length > end) {
    return;
  }
  community_.assign(start, community_length);

  // Parse out community index.
  const size_t community_index_pos_ = community_.find('@');
  if (community_index_pos_ != std::string::npos) {
    community_index_ = community_.substr(community_index_pos_);
    community_.resize(community_index_pos_);
    length_ -= community_index_.size();
  }

  // PDU type (GetRequest, GetNextRequest, GetResponse, or GetBulkRequest).
  start += community_length;
  if (start + 5 > end) {
    return;
  }
  pdu_type_ = *start;
  if (pdu_type_ != kGetRequestPDUType && pdu_type_ != kGetNextRequestPDUType &&
      pdu_type_ != kGetResponsePDUType && pdu_type_ != kGetBulkRequestPDUType) {
    return;
  }

  // PDU length.
  ++start;
  start += DecodeASN1Int(start, end, &pdu_length_);

  // Request ID type (integer).
  if (*start != kIntegerType) {
    return;
  }

  // Request ID length (four bytes).
  ++start;
  if (*start != 0x04) {
    return;
  }

  // Request ID.
  ++start;
  request_id_ = *(uint32_t*)(start);

  start += sizeof(request_id_);
  data_.assign(start, end - start);

  initialized_ = true;
}

bool SNMPProxy::SNMPSequence::initialized() const {
  return initialized_;
}

const std::string& SNMPProxy::SNMPSequence::community() const {
  return community_;
}

const std::string& SNMPProxy::SNMPSequence::community_index() const {
  return community_index_;
}

uint8_t SNMPProxy::SNMPSequence::pdu_type() const {
  return pdu_type_;
}

uint32_t SNMPProxy::SNMPSequence::request_id() const {
  return request_id_;
}

const std::string& SNMPProxy::SNMPSequence::data() const {
  return data_;
}

void SNMPProxy::SNMPSequence::set_community(const std::string& community) {
  length_ -= (community_.size() + EncodeASN1Int(community_.size()).size() - 1);
  length_ += (community.size() + EncodeASN1Int(community.size()).size() - 1);
  community_ = community;
}

void SNMPProxy::SNMPSequence::set_pdu_type(uint8_t pdu_type) {
  pdu_type_ = pdu_type;
}

void SNMPProxy::SNMPSequence::set_error(uint8_t error) {
  data_[2] = error;
}

void SNMPProxy::SNMPSequence::set_data(const std::string& data) {
  length_ -= (data_.size() + EncodeASN1Int(pdu_length_).size() - 1);
  length_ += data.size();
  pdu_length_ -= data_.size();
  pdu_length_ += data.size();
  length_ += (EncodeASN1Int(pdu_length_).size() - 1);
  data_ = data;
}

std::string SNMPProxy::SNMPSequence::Serialize() const {
  std::string sequence;
  sequence += kSequenceType;
  sequence += EncodeASN1Int(length_);
  sequence += kSNMPv2cVersion;
  sequence += kStringType;
  sequence += EncodeASN1Int(community_.size());
  sequence += community_;
  sequence += pdu_type_;
  sequence += EncodeASN1Int(pdu_length_);
  sequence += kIntegerType;
  sequence += uint8_t(sizeof(request_id_));
  sequence.append((const char*)&request_id_, sizeof(request_id_));
  sequence += data_;
  return sequence;
}

uint8_t SNMPProxy::SNMPSequence::DecodeASN1Int(
    const char* start, const char* end, uint64_t* result){
  if (!(*start & 0x80)) {
    *result = *start;
    return 1;
  }
  uint8_t size = (*start & ~(0x80));
  if (size > sizeof(result) || start + size > end) {
    *result = 0;
    return 0;
  }
  *result = 0;
  for (uint8_t i = 0; i < size; ++i) {
    ++start;
    *result = *result << 8;
    *result += *start;
  }
  return size + 1;
}

std::string SNMPProxy::SNMPSequence::EncodeASN1Int(uint64_t input) {
  std::string result;
  if (input < 0x80) {
    result = uint8_t(input);
    return result;
  }
  for (uint8_t i = sizeof(input); i > 0; --i) {
    const uint8_t& byte = *((uint8_t*)&input + i - 1);
    if (result.empty() && byte > 0) {
      result = (i | 0x80); 
    }       
    if (!result.empty()) {
      result += byte;
    }
  }
  return result;
}

SNMPProxy::CacheKey::CacheKey(const std::string& backend_host,
                              const std::string& community,
                              const std::string& community_index,
                              uint8_t request_type,
                              const std::string& request_data) :
    backend_host_(backend_host), community_(community),
    community_index_(community_index), request_type_(request_type),
    request_data_(request_data) {}

bool SNMPProxy::CacheKey::operator==(const CacheKey& other) const {
  return (backend_host_ == other.backend_host_ &&
          community_ == other.community_ &&
          community_index_ == other.community_index_ &&
          request_type_ == other.request_type_ &&
          request_data_ == other.request_data_);
}

size_t SNMPProxy::CacheKey::Hash::operator()(const CacheKey& key) const {
  return (std::hash<std::string>()(key.backend_host_) ^ 
          std::hash<std::string>()(key.community_) ^
          std::hash<std::string>()(key.community_index_) ^
          std::hash<uint8_t>()(key.request_type_) ^
          std::hash<std::string>()(key.request_data_));
}

SNMPProxy::CacheValue::CacheValue() {}

SNMPProxy::CacheValue::CacheValue(const std::string& response_data) :
    response_data_(response_data), time_(std::time(nullptr)) {}

std::time_t SNMPProxy::CacheValue::time() const {
  return time_;
}

const std::string& SNMPProxy::CacheValue::response_data() const {
  return response_data_;
}

void SNMPProxy::TimeoutRead(boost::asio::ip::udp::socket& socket,
                            std::condition_variable* cv) {
  std::unique_lock<std::mutex> lock(mutex_);
  if (cv->wait_for(lock, std::chrono::seconds(backend_timeout_sec_))) {
    socket.cancel();
  }
}

void SNMPProxy::Read(size_t bytes_transferred, size_t* response_size,
                     std::condition_variable* cv) {
  *response_size = bytes_transferred;
  std::unique_lock<std::mutex> lock(mutex_);
  cv->notify_all();
}

std::string SNMPProxy::GetResponse(const std::string& backend_host,
                                   const SNMPSequence& snmp_request) {
  CacheKey key(backend_host, snmp_request.community(),
               snmp_request.community_index(), snmp_request.pdu_type(),
               snmp_request.data());
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto cache_entry = cache_.find(key);
    if (cache_entry != cache_.end()) {
      // Stale cache entry. Evict it and fall through to the backend.
      if (std::time(nullptr) > cache_entry->second.time() + cache_ttl_sec_) {
        cache_.erase(cache_entry);
      } else {
        // Fresh cache entry. Serve it.
        SNMPSequence snmp_response(snmp_request);
        snmp_response.set_community(backend_host);
        snmp_response.set_pdu_type(kGetResponsePDUType);
        snmp_response.set_data(cache_entry->second.response_data());
        return snmp_response.Serialize();
      }
    }
  }
  udp::resolver resolver(io_service_);
  udp::resolver::query query(udp::v4(), backend_host, "snmp");
  udp::endpoint remote_endpoint = *resolver.resolve(query);
  udp::socket socket(io_service_);
  socket.open(udp::v4());

  unsigned int num_retries = 0;
  boost::array<char, 65536> response;
  udp::endpoint local_endpoint;
  size_t response_size = 0;
  do {
    io_service_.reset();
    socket.send_to(boost::asio::buffer(snmp_request.Serialize()),
                                       remote_endpoint);
    std::condition_variable cv;
    std::thread read_timeout_thread(
        std::bind(&SNMPProxy::TimeoutRead, this, boost::ref(socket), &cv));
    socket.async_receive_from(
        boost::asio::buffer(response), local_endpoint,
        boost::bind(&SNMPProxy::Read, this,
                    boost::asio::placeholders::bytes_transferred,
                    &response_size, &cv));
    io_service_.run();
    read_timeout_thread.join();
    ++num_retries;
  } while (num_retries <= num_backend_retries_ && response_size == 0);

  // We didn't get a response. Cache and serve an unavailable error.
  if (response_size == 0) {
    std::cerr << "Timeout while querying " << backend_host << "." << std::endl;
    SNMPSequence snmp_response(snmp_request);
    snmp_response.set_community(backend_host);
    snmp_response.set_pdu_type(kGetResponsePDUType);
    snmp_response.set_error(kResourceUnavailableError);
    std::lock_guard<std::mutex> lock(mutex_);
    cache_[key] = CacheValue(snmp_response.data());
    snmp_response.set_community(backend_host);
    return snmp_response.Serialize();
  } else {
    // We got a response we could parse. Cache it and serve it.
    SNMPSequence snmp_response(response.data(),
                               response.data() + response_size);
    if (snmp_response.initialized()) {
      std::lock_guard<std::mutex> lock(mutex_);
      cache_[key] = CacheValue(snmp_response.data());
      snmp_response.set_community(backend_host);
      return snmp_response.Serialize();
    }
  }
  // We got a response we couldn't parse. Serve it.
  return std::string(response.data(), response_size);
}

void SNMPProxy::EvictStaleCacheEntries() {
  while (true) {
    size_t num_evicted_entries = 0;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      const std::time_t current_time = std::time(nullptr);
      for (auto entry = cache_.begin(); entry != cache_.end();) {
        if (current_time > entry->second.time() + cache_ttl_sec_) {
          entry = cache_.erase(entry);
          ++num_evicted_entries;
        } else {
          ++entry;
        }
      }
    }
    if (num_evicted_entries > 0) {
      std::cout << "Evicted " << num_evicted_entries << " stale cache entries."
                << std::endl;
    }
    std::this_thread::sleep_for(std::chrono::seconds(cache_ttl_sec_));
  }
}
