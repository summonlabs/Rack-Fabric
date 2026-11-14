// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Regression tests for authority, lifecycle, persistence and session defects.
// Every test names the guarantee it protects. The coordinator cases run a real
// coordinator in this process and talk to it over a real loopback socket.

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

#include <process.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "rack_fabric/agent.hpp"
#include "rack_fabric/coordinator.hpp"
#include "rack_fabric/persistence.hpp"
#include "rack_fabric/protocol.hpp"
#include "rack_fabric/rack_fabric.hpp"
#include "test_framework.hpp"
#include "test_support.hpp"

namespace {

using namespace rack_fabric;
using rf_test::member;
using rf_test::observed;

constexpr std::chrono::milliseconds kOneHour{3'600'000};

class TempDir {
 public:
  TempDir() {
    static std::atomic<std::uint64_t> counter{0};
    path_ = std::filesystem::temp_directory_path() /
            ("rack_fabric_regression_" + std::to_string(_getpid()) + "_" +
             std::to_string(counter.fetch_add(1) + 1));
    std::filesystem::create_directories(path_);
  }
  ~TempDir() {
    std::error_code error;
    std::filesystem::remove_all(path_, error);
  }
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;
  [[nodiscard]] std::filesystem::path file(const std::string& name) const { return path_ / name; }

 private:
  std::filesystem::path path_;
};

[[nodiscard]] MutationResult publish(RackFabric& fabric, const AuthorityToken& token,
                                     const MemberRecord& record) {
  PublishMemberRequest request;
  request.authority = token;
  request.record = record;
  return fabric.publish_member(request);
}

[[nodiscard]] Quantity quantity(double value, QuantityUnit unit,
                                Durability durability = Durability::Durable,
                                std::chrono::milliseconds ttl = std::chrono::milliseconds{0}) {
  Quantity out;
  out.value = value;
  out.unit = unit;
  out.provenance = EvidenceProvenance::Measured;
  out.observed_at = observed();
  out.ttl = ttl;
  out.durability = durability;
  return out;
}

[[nodiscard]] RelationshipRecord relationship(RelationshipClass cls, const MemberKey& from,
                                              const MemberKey& to) {
  RelationshipRecord record;
  record.key = RelationshipKey{cls, from, to};
  record.provenance = EvidenceProvenance::Measured;
  record.observed_at = observed();
  record.ttl = std::chrono::milliseconds{0};
  record.durability = Durability::Durable;
  return record;
}

[[nodiscard]] PowerEnvelopeRecord power_envelope(double limit) {
  PowerEnvelopeRecord record;
  record.rack_limit = quantity(limit, QuantityUnit::Watts);
  record.provenance = EvidenceProvenance::Measured;
  record.observed_at = observed();
  record.ttl = std::chrono::milliseconds{0};
  record.durability = Durability::Durable;
  return record;
}

[[nodiscard]] CoolingEnvelopeRecord cooling_envelope() {
  CoolingEnvelopeRecord record;
  record.provenance = EvidenceProvenance::Measured;
  record.observed_at = observed();
  record.ttl = std::chrono::milliseconds{0};
  record.durability = Durability::Durable;
  return record;
}

/// A durable zone whose live observations are ephemeral.
[[nodiscard]] CoolingZoneRecord live_zone(const std::string& zone) {
  CoolingZoneRecord record{CoolingDomainId{zone}};
  record.observed_temperature = quantity(31.0, QuantityUnit::Celsius, Durability::Ephemeral, kOneHour);
  EvidenceValue<ThrottleState> throttling;
  throttling.value = ThrottleState::None;
  throttling.provenance = EvidenceProvenance::Measured;
  throttling.observed_at = observed();
  throttling.ttl = kOneHour;
  throttling.durability = Durability::Ephemeral;
  record.throttling = throttling;
  return record;
}

/// A durable NIC whose link speed is a live, ephemeral observation.
[[nodiscard]] MemberRecord nic_with_live_speed(const std::string& id) {
  MemberRecord record = member(MemberKind::Nic, id);
  NicDetails details = std::get<NicDetails>(record.details);
  details.link_speed = quantity(100.0, QuantityUnit::GigabitsPerSecond, Durability::Ephemeral, kOneHour);
  record.details = details;
  return record;
}

[[nodiscard]] bool quantity_current(const std::optional<Quantity>& value, Timestamp now) {
  return value.has_value() && value->is_current_at(now);
}

void fence(RackFabric& fabric, const AgentBootId& boot) {
  FencePublisherRequest request;
  request.coordinator_epoch = fabric.coordinator_epoch();
  request.boot = boot;
  request.reason = RevalidationReason::OwnerProcessLost;
  RF_REQUIRE(fabric.fence_publisher(request).accepted());
}

[[nodiscard]] MutationResult register_boot(RackFabric& fabric, const std::string& worker,
                                           const std::string& boot) {
  RegisterPublisherRequest request;
  request.rack = RackId{"rack-a"};
  request.worker = WorkerId{worker};
  request.boot = AgentBootId{boot};
  request.coordinator_epoch = fabric.coordinator_epoch();
  return fabric.register_publisher(request);
}

const MemberKey kNode1{MemberKind::Node, "node-1"};
const MemberKey kNode2{MemberKind::Node, "node-2"};

// ---------------------------------------------------------------------------
// A minimal wire client built from the public protocol API.
// ---------------------------------------------------------------------------

struct Winsock {
  Winsock() {
    WSADATA data{};
    ok = WSAStartup(MAKEWORD(2, 2), &data) == 0;
  }
  ~Winsock() {
    if (ok) {
      WSACleanup();
    }
  }
  Winsock(const Winsock&) = delete;
  Winsock& operator=(const Winsock&) = delete;
  bool ok = false;
};

struct Wire {
  SOCKET socket = INVALID_SOCKET;
  std::uint64_t correlation = 0;

  Wire() = default;
  Wire(const Wire&) = delete;
  Wire& operator=(const Wire&) = delete;
  ~Wire() { close(); }

  // A socket receive timeout turns a reply that never comes into a failed
  // check with a diagnostic; it never terminates anything.
  bool open(std::uint16_t port, DWORD receive_timeout_ms) {
    socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket == INVALID_SOCKET) {
      return false;
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (::inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1) {
      return false;
    }
    if (::connect(socket, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) ==
        SOCKET_ERROR) {
      return false;
    }
    ::setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&receive_timeout_ms),
                 sizeof(receive_timeout_ms));
    return true;
  }
  void close() {
    if (socket != INVALID_SOCKET) {
      ::shutdown(socket, SD_BOTH);
      ::closesocket(socket);
      socket = INVALID_SOCKET;
    }
  }
  bool send_bytes(const std::byte* data, std::size_t size) {
    std::size_t sent = 0;
    while (sent < size) {
      const int written = ::send(socket, reinterpret_cast<const char*>(data + sent),
                                 static_cast<int>(size - sent), 0);
      if (written <= 0) {
        return false;
      }
      sent += static_cast<std::size_t>(written);
    }
    return true;
  }
  [[nodiscard]] std::optional<std::vector<std::byte>> frame_bytes(MessageType type,
                                                                  const std::vector<std::byte>& payload) {
    Frame frame;
    frame.type = type;
    frame.correlation = ++correlation;
    frame.payload = payload;
    return encode_frame(frame, ResourceLimits{});
  }
  bool send(MessageType type, const std::vector<std::byte>& payload) {
    const auto bytes = frame_bytes(type, payload);
    return bytes.has_value() && send_bytes(bytes->data(), bytes->size());
  }
  bool receive_exact(std::byte* data, std::size_t size) {
    std::size_t received = 0;
    while (received < size) {
      const int read = ::recv(socket, reinterpret_cast<char*>(data + received),
                              static_cast<int>(size - received), 0);
      if (read <= 0) {
        return false;
      }
      received += static_cast<std::size_t>(read);
    }
    return true;
  }
  bool receive(Frame& frame) {
    std::vector<std::byte> buffer(kFrameHeaderBytes);
    if (!receive_exact(buffer.data(), buffer.size())) {
      return false;
    }
    std::uint32_t payload_length = 0;
    std::memcpy(&payload_length, buffer.data() + 20, sizeof(payload_length));
    if (payload_length > ResourceLimits{}.max_payload_bytes) {
      return false;
    }
    buffer.resize(kFrameHeaderBytes + payload_length + kFrameTrailerBytes);
    if (!receive_exact(buffer.data() + kFrameHeaderBytes, payload_length + kFrameTrailerBytes)) {
      return false;
    }
    const DecodeResult decoded = decode_frame(buffer.data(), buffer.size(), ResourceLimits{});
    if (!decoded.ok()) {
      return false;
    }
    frame = decoded.frame;
    return true;
  }
};

template <class Message>
[[nodiscard]] std::vector<std::byte> encoded(const Message& message) {
  const auto payload = MessageCodec::encode(message, ResourceLimits{});
  return payload.has_value() ? *payload : std::vector<std::byte>{};
}

[[nodiscard]] std::unique_ptr<CoordinatorServer> start_server(CoordinatorOptions options) {
  options.rack = RackId{"rack-a"};
  options.rack_epoch = RackEpochId{"epoch-1"};
  std::string error;
  auto server = CoordinatorServer::start(options, error);
  if (!server.has_value()) {
    rftest::record_failure(__FILE__, __LINE__, "the coordinator did not start: " + error);
    return nullptr;
  }
  return std::move(*server);
}

[[nodiscard]] bool say_hello(Wire& wire) {
  HelloMessage hello;
  hello.agent_version = "regression";
  Frame reply;
  return wire.send(MessageType::Hello, encoded(hello)) && wire.receive(reply) &&
         reply.type == MessageType::HelloAck;
}

/// HELLO plus REGISTER; returns the publication generation the coordinator
/// granted, or nothing when the session could not be established.
[[nodiscard]] std::optional<PublicationGeneration> open_session(Wire& wire,
                                                                const CoordinatorServer& server,
                                                                const std::string& boot) {
  if (!say_hello(wire)) {
    return std::nullopt;
  }
  RegisterMessage message;
  message.rack = RackId{"rack-a"};
  message.worker = WorkerId{"worker-" + boot};
  message.boot = AgentBootId{boot};
  message.coordinator_epoch = server.epoch();
  Frame reply;
  if (!wire.send(MessageType::Register, encoded(message)) || !wire.receive(reply) ||
      reply.type != MessageType::RegisterAck) {
    return std::nullopt;
  }
  RegisterAckMessage ack;
  if (MessageCodec::decode(reply.payload.data(), reply.payload.size(), ack) != DecodeStatus::Ok ||
      !ack.accepted) {
    return std::nullopt;
  }
  return ack.publication_generation;
}

[[nodiscard]] AuthorityToken wire_token(const CoordinatorServer& server, const std::string& boot,
                                        PublicationGeneration publication) {
  AuthorityToken token;
  token.coordinator_epoch = server.epoch();
  token.boot = AgentBootId{boot};
  token.rack = RackId{"rack-a"};
  token.publication_generation = publication;
  return token;
}

[[nodiscard]] std::optional<ResultMessage> receive_result(Wire& wire, std::uint64_t correlation) {
  Frame reply;
  if (!wire.receive(reply) || reply.type != MessageType::Result || reply.correlation != correlation) {
    return std::nullopt;
  }
  ResultMessage result;
  if (MessageCodec::decode(reply.payload.data(), reply.payload.size(), result) != DecodeStatus::Ok) {
    return std::nullopt;
  }
  return result;
}

}  // namespace

// ---------------------------------------------------------------------------
// Member lifecycle and per-record authority
// ---------------------------------------------------------------------------

RF_TEST(regression, withdrawing_evidence_cannot_resurrect_a_retired_member) {
  RackFabric fabric;
  rf_test::declare_rack(fabric, "rack-a", "epoch-1");
  const AuthorityToken op = rf_test::operator_token(fabric, "rack-a");
  rf_test::publish_member(fabric, op, member(MemberKind::Node, "node-1"));
  RetireMemberRequest retire;
  retire.authority = op;
  retire.member = kNode1;
  RF_REQUIRE(fabric.retire_member(retire).accepted());

  WithdrawEvidenceRequest withdraw;
  withdraw.authority = op;
  withdraw.member = kNode1;
  withdraw.scope = WithdrawScope::All;
  RF_CHECK_EQ(fabric.withdraw_evidence(withdraw).outcome, MutationOutcome::RejectRetired);
  RF_CHECK_EQ(fabric.find_member(kNode1)->lifecycle, MemberLifecycle::Retired);

  // The identity stays retired: it cannot be published as present again.
  RF_CHECK_EQ(publish(fabric, op, member(MemberKind::Node, "node-1")).outcome,
              MutationOutcome::RejectRetired);
  RF_CHECK_EQ(fabric.find_member(kNode1)->lifecycle, MemberLifecycle::Retired);
}

RF_TEST(regression, retirement_respects_record_ownership) {
  RackFabric fabric;
  rf_test::declare_rack(fabric, "rack-a", "epoch-1");
  rf_test::Publisher owner = rf_test::register_publisher(fabric, "rack-a", "worker-1", "boot-1");
  rf_test::Publisher other = rf_test::register_publisher(fabric, "rack-a", "worker-2", "boot-2");
  rf_test::publish_member(fabric, owner.token, member(MemberKind::Node, "node-1"));
  rf_test::publish_member(fabric, owner.token, member(MemberKind::Accelerator, "acc-1"));
  PublishRelationshipRequest link;
  link.authority = owner.token;
  link.record = relationship(RelationshipClass::Contains, kNode1,
                             MemberKey{MemberKind::Accelerator, "acc-1"});
  RF_REQUIRE(fabric.publish_relationship(link).accepted());
  rf_test::advance(owner.token);

  RetireMemberRequest retire;
  retire.authority = other.token;
  retire.member = kNode1;
  const MutationResult stolen = fabric.retire_member(retire);
  RF_CHECK_EQ(stolen.outcome, MutationOutcome::RejectNotAuthorized);
  RF_CHECK_EQ(stolen.explanation.code, std::string("MEMBER_OWNED_BY_OTHER_PROCESS"));
  RF_CHECK_EQ(fabric.find_member(kNode1)->lifecycle, MemberLifecycle::Present);
  RF_CHECK_EQ(fabric.relationships().size(), std::size_t{1});

  retire.authority = owner.token;
  RF_CHECK(fabric.retire_member(retire).accepted());
}

RF_TEST(regression, envelopes_respect_record_ownership) {
  RackFabric fabric;
  rf_test::declare_rack(fabric, "rack-a", "epoch-1");
  rf_test::Publisher owner = rf_test::register_publisher(fabric, "rack-a", "worker-1", "boot-1");
  rf_test::Publisher other = rf_test::register_publisher(fabric, "rack-a", "worker-2", "boot-2");

  PublishPowerEnvelopeRequest power;
  power.authority = owner.token;
  power.record = power_envelope(10000.0);
  RF_REQUIRE(fabric.publish_power_envelope(power).accepted());
  rf_test::advance(owner.token);
  power.authority = other.token;
  power.record = power_envelope(20000.0);
  const MutationResult power_stolen = fabric.publish_power_envelope(power);
  RF_CHECK_EQ(power_stolen.outcome, MutationOutcome::RejectNotAuthorized);
  RF_CHECK_EQ(fabric.power_envelope()->owner_boot->value(), std::string("boot-1"));
  RF_CHECK_EQ(fabric.power_envelope()->rack_limit->value, 10000.0);

  PublishCoolingEnvelopeRequest cooling;
  cooling.authority = owner.token;
  cooling.record = cooling_envelope();
  RF_REQUIRE(fabric.publish_cooling_envelope(cooling).accepted());
  rf_test::advance(owner.token);
  cooling.authority = other.token;
  cooling.record.source = std::string("other");
  const MutationResult cooling_stolen = fabric.publish_cooling_envelope(cooling);
  RF_CHECK_EQ(cooling_stolen.outcome, MutationOutcome::RejectNotAuthorized);
  RF_CHECK_EQ(fabric.cooling_envelope()->owner_boot->value(), std::string("boot-1"));
}

RF_TEST(regression, a_stale_expected_generation_is_refused_by_every_mutation) {
  RackFabric fabric;
  rf_test::declare_rack(fabric, "rack-a", "epoch-1");
  const AuthorityToken op = rf_test::operator_token(fabric, "rack-a");
  for (const char* id : {"node-1", "node-2", "node-3"}) {
    MemberRecord record = member(MemberKind::Node, id);
    rf_test::publish_member(fabric, op, record);
    record.source = std::string("updated");
    rf_test::publish_member(fabric, op, record);  // generation 2
  }
  const MemberGeneration stale = MemberGeneration::from_value(1);

  WithdrawEvidenceRequest withdraw;
  withdraw.authority = op;
  withdraw.member = kNode1;
  withdraw.scope = WithdrawScope::Health;
  withdraw.expected_generation = stale;
  RF_CHECK_EQ(fabric.withdraw_evidence(withdraw).outcome, MutationOutcome::RejectStaleGeneration);

  MarkUnavailableRequest unavailable;
  unavailable.authority = op;
  unavailable.member = kNode2;
  unavailable.expected_generation = stale;
  RF_CHECK_EQ(fabric.mark_unavailable(unavailable).outcome, MutationOutcome::RejectStaleGeneration);
  RF_CHECK_EQ(fabric.find_member(kNode2)->lifecycle, MemberLifecycle::Present);

  RetireMemberRequest retire;
  retire.authority = op;
  retire.member = MemberKey{MemberKind::Node, "node-3"};
  retire.expected_generation = stale;
  RF_CHECK_EQ(fabric.retire_member(retire).outcome, MutationOutcome::RejectStaleGeneration);
  RF_CHECK_EQ(fabric.find_member(retire.member)->lifecycle, MemberLifecycle::Present);
  for (const MemberKey& key : {kNode1, kNode2, retire.member}) {
    RF_CHECK_EQ(fabric.find_member(key)->generation.value(), std::uint64_t{2});
  }

  PublishRelationshipRequest link;
  link.authority = op;
  link.record = relationship(RelationshipClass::ConnectedTo, kNode1, kNode2);
  RF_REQUIRE(fabric.publish_relationship(link).accepted());
  link.record = relationship(RelationshipClass::ConnectedTo, kNode2, retire.member);
  RF_REQUIRE(fabric.publish_relationship(link).accepted());
  WithdrawRelationshipRequest unlink;
  unlink.authority = op;
  unlink.key = RelationshipKey{RelationshipClass::ConnectedTo, kNode1, kNode2};
  unlink.expected_generation = TopologyGeneration::from_value(1);
  RF_CHECK_EQ(fabric.withdraw_relationship(unlink).outcome, MutationOutcome::RejectStaleGeneration);
  RF_CHECK_EQ(fabric.relationships().size(), std::size_t{2});
}

RF_TEST(regression, a_rejected_revalidation_changes_nothing) {
  RackFabric fabric;
  rf_test::declare_rack(fabric, "rack-a", "epoch-1");
  rf_test::Publisher owner = rf_test::register_publisher(fabric, "rack-a", "worker-1", "boot-1");
  rf_test::Publisher other = rf_test::register_publisher(fabric, "rack-a", "worker-2", "boot-2");
  rf_test::publish_member(fabric, owner.token, member(MemberKind::Node, "node-1"));
  rf_test::publish_member(fabric, other.token, member(MemberKind::Node, "node-2"));
  rf_test::declare_rack(fabric, "rack-a", "epoch-2", true);  // every member must be revalidated
  const MemberRecord before = *fabric.find_member(kNode1);
  RF_REQUIRE(before.revalidation_required);
  const GenerationSet generations_before = fabric.generations();

  RevalidateMembersRequest request;
  request.authority = owner.token;
  request.members = {kNode1, kNode2};
  RF_CHECK_EQ(fabric.revalidate_members(request).outcome, MutationOutcome::RejectNotAuthorized);
  request.members = {kNode1, MemberKey{MemberKind::Node, "node-missing"}};
  RF_CHECK_EQ(fabric.revalidate_members(request).outcome, MutationOutcome::RejectUnknownMember);

  const MemberRecord after = *fabric.find_member(kNode1);
  RF_CHECK(after.revalidation_required);
  RF_CHECK_EQ(after.generation.value(), before.generation.value());
  RF_CHECK(fabric.generations() == generations_before);

  request.members = {kNode1};
  RF_CHECK(fabric.revalidate_members(request).accepted());
  RF_CHECK(!fabric.find_member(kNode1)->revalidation_required);
}

// ---------------------------------------------------------------------------
// Publisher leases and registration
// ---------------------------------------------------------------------------

RF_TEST(regression, an_expired_lease_carries_no_authority) {
  auto clock = std::make_shared<ManualClock>(rf_test::kObservationMillis);
  RackFabricOptions options;
  options.clock = clock;
  options.limits.publisher_lease_millis = 1000;
  RackFabric fabric(options);
  rf_test::declare_rack(fabric, "rack-a", "epoch-1");
  rf_test::Publisher publisher = rf_test::register_publisher(fabric, "rack-a", "worker-1", "boot-1");

  clock->advance(std::chrono::milliseconds{1500});
  // No sweep has run yet; the expired lease alone must refuse the mutation.
  const MutationResult late = publish(fabric, publisher.token, member(MemberKind::Node, "node-1"));
  RF_CHECK_EQ(late.outcome, MutationOutcome::RejectStaleWorkerBoot);
  RF_CHECK_EQ(late.explanation.code, std::string("PUBLISHER_LEASE_EXPIRED"));
  RF_CHECK(!fabric.find_member(kNode1).has_value());

  // Neither a heartbeat nor a repeated registration revives the incarnation.
  HeartbeatRequest heartbeat;
  heartbeat.authority = publisher.token;
  RF_CHECK_EQ(fabric.heartbeat(heartbeat).outcome, MutationOutcome::RejectStaleWorkerBoot);
  RF_CHECK(!register_boot(fabric, "worker-1", "boot-1").accepted());
  RF_CHECK_EQ(fabric.expire_publishers(), std::size_t{1});
  RF_CHECK(fabric.is_boot_fenced(publisher.boot));
}

RF_TEST(regression, a_refused_reregistration_does_not_renew_the_lease) {
  auto clock = std::make_shared<ManualClock>(rf_test::kObservationMillis);
  RackFabricOptions options;
  options.clock = clock;
  options.limits.publisher_lease_millis = 1000;
  RackFabric fabric(options);
  rf_test::declare_rack(fabric, "rack-a", "epoch-1");
  rf_test::Publisher publisher = rf_test::register_publisher(fabric, "rack-a", "worker-1", "boot-1");

  clock->advance(std::chrono::milliseconds{800});
  RF_CHECK_EQ(register_boot(fabric, "worker-1", "boot-1").outcome, MutationOutcome::NoChange);
  clock->advance(std::chrono::milliseconds{400});
  // 1200 ms after the last heartbeat: the lease is gone whatever was refused.
  RF_CHECK_EQ(fabric.expire_publishers(), std::size_t{1});
  RF_CHECK(fabric.is_boot_fenced(publisher.boot));
}

RF_TEST(regression, dead_publishers_do_not_exhaust_registration) {
  RackFabricOptions options;
  options.limits.max_connections = 2;
  RackFabric fabric(options);
  rf_test::declare_rack(fabric, "rack-a", "epoch-1");
  RF_REQUIRE(register_boot(fabric, "worker-1", "boot-1").accepted());
  RF_REQUIRE(register_boot(fabric, "worker-2", "boot-2").accepted());
  fence(fabric, AgentBootId{"boot-1"});
  RF_CHECK(register_boot(fabric, "worker-1", "boot-3").accepted());

  // After a restart every publisher is lost; new incarnations still register.
  TempDir directory;
  RF_REQUIRE(fabric.save_state(directory.file("state.rkf")).status == PersistenceStatus::Ok);
  RackFabric recovered(options);
  RF_REQUIRE(recovered.load_state(directory.file("state.rkf")).status == PersistenceStatus::Ok);
  RF_CHECK(register_boot(recovered, "worker-1", "boot-4").accepted());
  RF_CHECK(register_boot(recovered, "worker-2", "boot-5").accepted());
  // A lost incarnation stays lost.
  RF_CHECK_EQ(register_boot(recovered, "worker-2", "boot-2").outcome,
              MutationOutcome::RejectStaleWorkerBoot);
}

RF_TEST(regression, publisher_history_stays_bounded_loadable_and_fenced) {
  RackFabricOptions options;
  options.limits.max_connections = 1;
  TempDir directory;
  RackFabric first(options);
  rf_test::declare_rack(first, "rack-a", "epoch-1");
  RF_REQUIRE(register_boot(first, "worker-0", "boot-0").accepted());
  RF_REQUIRE(first.save_state(directory.file("first.rkf")).status == PersistenceStatus::Ok);

  // boot-0 is lost by the restart, so only the publisher table remembers it.
  RackFabric fabric(options);
  RF_REQUIRE(fabric.load_state(directory.file("first.rkf")).status == PersistenceStatus::Ok);
  for (int index = 1; index <= 40; ++index) {
    const std::string boot = "boot-" + std::to_string(index);
    const MutationResult registered = register_boot(fabric, "worker-1", boot);
    RF_CHECK(registered.accepted());
    if (!registered.accepted()) {
      break;
    }
    fence(fabric, AgentBootId{boot});
  }
  RF_CHECK(fabric.publishers().size() <= options.limits.max_connections * 16U);
  RF_CHECK_EQ(register_boot(fabric, "worker-0", "boot-0").outcome,
              MutationOutcome::RejectStaleWorkerBoot);
  RF_REQUIRE(fabric.save_state(directory.file("second.rkf")).status == PersistenceStatus::Ok);
  RackFabric again(options);
  RF_CHECK_EQ(again.load_state(directory.file("second.rkf")).status, PersistenceStatus::Ok);
}

RF_TEST(regression, a_reincarnation_reasserts_the_records_of_its_fenced_predecessor) {
  RackFabric fabric;
  rf_test::declare_rack(fabric, "rack-a", "epoch-1");
  rf_test::Publisher first = rf_test::register_publisher(fabric, "rack-a", "worker-1", "boot-1");
  rf_test::publish_member(fabric, first.token, member(MemberKind::Node, "node-1"));
  fence(fabric, first.boot);
  RF_REQUIRE(fabric.find_member(kNode1)->revalidation_required);

  rf_test::Publisher second = rf_test::register_publisher(fabric, "rack-a", "worker-1", "boot-2");
  const MutationResult republished = publish(fabric, second.token, member(MemberKind::Node, "node-1"));
  RF_CHECK(republished.accepted());
  const MemberRecord stored = *fabric.find_member(kNode1);
  RF_CHECK_EQ(stored.owner_boot->value(), std::string("boot-2"));
  RF_CHECK(!stored.revalidation_required);
  RF_CHECK(fabric.lifecycle() != RackLifecycle::RevalidationRequired);

  // The dead incarnation still has no authority.
  RF_CHECK_EQ(publish(fabric, first.token, member(MemberKind::Node, "node-9")).outcome,
              MutationOutcome::RejectStaleWorkerBoot);
}

// ---------------------------------------------------------------------------
// Fencing, recovery and persistence
// ---------------------------------------------------------------------------

RF_TEST(regression, fencing_flags_every_owned_record_and_demotes_live_observations) {
  auto clock = std::make_shared<ManualClock>(rf_test::kObservationMillis);
  RackFabricOptions options;
  options.clock = clock;
  RackFabric fabric(options);
  rf_test::declare_rack(fabric, "rack-a", "epoch-1");
  rf_test::Publisher owner = rf_test::register_publisher(fabric, "rack-a", "worker-1", "boot-1");
  rf_test::publish_member(fabric, owner.token, member(MemberKind::Node, "node-1"));
  rf_test::publish_member(fabric, owner.token, nic_with_live_speed("nic-1"));
  rf_test::publish_member(fabric, owner.token, member(MemberKind::CoolingDomain, "zone-1"));
  const MemberKey nic{MemberKind::Nic, "nic-1"};

  PublishRelationshipRequest link;
  link.authority = owner.token;
  link.record = relationship(RelationshipClass::Contains, kNode1, nic);
  link.record.capacity = quantity(100.0, QuantityUnit::GigabitsPerSecond, Durability::Ephemeral, kOneHour);
  RF_REQUIRE(fabric.publish_relationship(link).accepted());
  rf_test::advance(owner.token);
  PublishCoolingEnvelopeRequest cooling;
  cooling.authority = owner.token;
  cooling.record = cooling_envelope();
  cooling.record.zones.push_back(live_zone("zone-1"));
  RF_REQUIRE(fabric.publish_cooling_envelope(cooling).accepted());

  const Timestamp now = clock->now();
  RF_REQUIRE(quantity_current(fabric.cooling_envelope()->zones[0].observed_temperature, now));
  fence(fabric, owner.boot);

  const RelationshipRecord owned_link = *fabric.find_relationship(link.record.key);
  RF_CHECK(owned_link.revalidation_required);
  RF_CHECK(!quantity_current(owned_link.capacity, now));
  const CoolingEnvelopeRecord envelope = *fabric.cooling_envelope();
  RF_CHECK(envelope.revalidation_required);
  RF_CHECK(!quantity_current(envelope.zones[0].observed_temperature, now));
  RF_CHECK(!(envelope.zones[0].throttling.has_value() && envelope.zones[0].throttling->is_current_at(now)));
  const MemberRecord stored_nic = *fabric.find_member(nic);
  RF_CHECK(!quantity_current(std::get<NicDetails>(stored_nic.details).link_speed, now));
}

RF_TEST(regression, recovery_never_restores_live_observations_as_current) {
  auto clock = std::make_shared<ManualClock>(rf_test::kObservationMillis);
  RackFabricOptions options;
  options.clock = clock;
  RackFabric fabric(options);
  rf_test::declare_rack(fabric, "rack-a", "epoch-1");
  const AuthorityToken op = rf_test::operator_token(fabric, "rack-a");
  rf_test::publish_member(fabric, op, member(MemberKind::Node, "node-1"));
  rf_test::publish_member(fabric, op, nic_with_live_speed("nic-1"));
  rf_test::publish_member(fabric, op, member(MemberKind::CoolingDomain, "zone-1"));
  const MemberKey nic{MemberKind::Nic, "nic-1"};

  PublishRelationshipRequest link;
  link.authority = op;
  link.record = relationship(RelationshipClass::Contains, kNode1, nic);
  link.record.capacity = quantity(100.0, QuantityUnit::GigabitsPerSecond, Durability::Ephemeral, kOneHour);
  RF_REQUIRE(fabric.publish_relationship(link).accepted());
  PublishCoolingEnvelopeRequest cooling;
  cooling.authority = op;
  cooling.record = cooling_envelope();
  cooling.record.zones.push_back(live_zone("zone-1"));
  RF_REQUIRE(fabric.publish_cooling_envelope(cooling).accepted());
  PublishPowerEnvelopeRequest power;
  power.authority = op;
  power.record = power_envelope(40000.0);
  PowerDomainBudget budget{PowerDomainId{"pdu-1"}};
  budget.limit = quantity(20000.0, QuantityUnit::Watts);
  budget.observed_draw = quantity(9000.0, QuantityUnit::Watts, Durability::Ephemeral, kOneHour);
  power.record.domain_budgets.push_back(budget);
  RF_REQUIRE(fabric.publish_power_envelope(power).accepted());

  TempDir directory;
  RF_REQUIRE(fabric.save_state(directory.file("state.rkf")).status == PersistenceStatus::Ok);
  clock->advance(std::chrono::minutes{1});
  RackFabric recovered(options);
  RF_REQUIRE(recovered.load_state(directory.file("state.rkf")).status == PersistenceStatus::Ok);
  const Timestamp now = clock->now();

  const CoolingEnvelopeRecord envelope = *recovered.cooling_envelope();
  RF_CHECK(!quantity_current(envelope.zones[0].observed_temperature, now));
  RF_CHECK(!(envelope.zones[0].throttling.has_value() && envelope.zones[0].throttling->is_current_at(now)));
  RF_CHECK(!quantity_current(recovered.power_envelope()->domain_budgets[0].observed_draw, now));
  RF_CHECK(!quantity_current(recovered.find_relationship(link.record.key)->capacity, now));
  RF_CHECK(!quantity_current(std::get<NicDetails>(recovered.find_member(nic)->details).link_speed, now));
  // Durable declarations survive.
  RF_CHECK(quantity_current(recovered.power_envelope()->domain_budgets[0].limit, now));
}

RF_TEST(regression, accepted_state_always_reloads) {
  RackFabric fabric;
  rf_test::declare_rack(fabric, "rack-a", "epoch-1");
  const AuthorityToken op = rf_test::operator_token(fabric, "rack-a");
  rf_test::publish_member(fabric, op, member(MemberKind::Node, "node-1"));
  rf_test::publish_member(fabric, op, member(MemberKind::Node, "node-2"));

  // A power budget with a lifetime the persisted format cannot hold.
  PublishPowerEnvelopeRequest power;
  power.authority = op;
  power.record = power_envelope(40000.0);
  PowerDomainBudget budget{PowerDomainId{"pdu-1"}};
  budget.limit = quantity(20000.0, QuantityUnit::Watts);
  budget.limit->ttl = std::chrono::milliseconds{-1};
  power.record.domain_budgets.push_back(budget);
  RF_CHECK_EQ(fabric.publish_power_envelope(power).outcome, MutationOutcome::RejectInvalidInput);

  // Evidence that is absent still carries a lifetime that must be in bounds.
  MemberRecord node = member(MemberKind::Node, "node-3");
  node.health.ttl = std::chrono::milliseconds{-1};
  RF_CHECK_EQ(publish(fabric, op, node).outcome, MutationOutcome::RejectInvalidInput);

  // A detail quantity outside the persisted lifetime bound.
  MemberRecord nic = member(MemberKind::Nic, "nic-1");
  NicDetails details = std::get<NicDetails>(nic.details);
  details.link_speed = quantity(100.0, QuantityUnit::GigabitsPerSecond, Durability::Ephemeral,
                                std::chrono::milliseconds{2 * 86'400'000LL});
  nic.details = details;
  RF_CHECK_EQ(publish(fabric, op, nic).outcome, MutationOutcome::RejectInvalidInput);

  // Identities the persisted format refuses.
  MemberRecord unnamed = member(MemberKind::Node, "node-4");
  NodeDetails node_details = std::get<NodeDetails>(unnamed.details);
  node_details.worker = WorkerId{};
  unnamed.details = node_details;
  RF_CHECK_EQ(publish(fabric, op, unnamed).outcome, MutationOutcome::RejectInvalidInput);
  PublishRelationshipRequest link;
  link.authority = op;
  link.record = relationship(RelationshipClass::ConnectedTo, kNode1, kNode2);
  link.record.link = LinkId{};
  RF_CHECK_EQ(fabric.publish_relationship(link).outcome, MutationOutcome::RejectInvalidInput);

  // Whatever was accepted reloads.
  TempDir directory;
  RF_REQUIRE(fabric.save_state(directory.file("state.rkf")).status == PersistenceStatus::Ok);
  RackFabric recovered;
  RF_CHECK_EQ(recovered.load_state(directory.file("state.rkf")).status, PersistenceStatus::Ok);
}

RF_TEST(regression, concurrent_saves_never_leave_an_older_state_on_disk) {
  TempDir directory;
  for (int round = 0; round < 25; ++round) {
    RackFabric fabric;
    rf_test::declare_rack(fabric, "rack-a", "epoch-1");
    const AuthorityToken op = rf_test::operator_token(fabric, "rack-a");
    const std::filesystem::path path = directory.file("state-" + std::to_string(round) + ".rkf");
    std::atomic<int> ready{0};
    std::vector<std::thread> savers;
    for (int index = 0; index < 4; ++index) {
      savers.emplace_back([&fabric, &op, &path, &ready, index]() {
        ready.fetch_add(1);
        while (ready.load() < 4) {
          std::this_thread::yield();
        }
        (void)publish(fabric, op, member(MemberKind::Node, "node-" + std::to_string(index)));
        (void)fabric.save_state(path);
      });
    }
    for (auto& saver : savers) {
      saver.join();
    }
    RackFabric recovered;
    RF_REQUIRE(recovered.load_state(path).status == PersistenceStatus::Ok);
    RF_CHECK_EQ(recovered.members().size(), std::size_t{4});
  }
}

RF_TEST(regression, a_saved_state_never_exceeds_the_load_bound) {
  auto clock = std::make_shared<ManualClock>(rf_test::kObservationMillis);
  const auto populate = [](RackFabric& fabric) {
    rf_test::declare_rack(fabric, "rack-a", "epoch-1");
    const AuthorityToken op = rf_test::operator_token(fabric, "rack-a");
    for (const char* id : {"node-1", "node-2", "node-3"}) {
      rf_test::publish_member(fabric, op, member(MemberKind::Node, id));
    }
  };
  TempDir directory;
  RackFabricOptions options;
  options.clock = clock;
  RackFabric probe(options);
  populate(probe);
  const PersistenceResult measured = probe.save_state(directory.file("probe.rkf"));
  RF_REQUIRE(measured.status == PersistenceStatus::Ok);
  const std::uint64_t payload_bytes = measured.bytes_written - 80U;

  // The bound admits the payload but not the header and trailer around it.
  RackFabricOptions tight = options;
  tight.limits.max_persisted_bytes = payload_bytes;
  RackFabric fabric(tight);
  populate(fabric);
  const PersistenceResult saved = fabric.save_state(directory.file("tight.rkf"));
  if (saved.status == PersistenceStatus::Ok) {
    RackFabric loader(tight);
    RF_CHECK_EQ(loader.load_state(directory.file("tight.rkf")).status, PersistenceStatus::Ok);
  }
  RF_CHECK_EQ(saved.status, PersistenceStatus::LimitExceeded);
}

RF_TEST(regression, the_snapshot_digest_covers_the_whole_snapshot) {
  // Two racks that differ only in content encoded past the first mebibyte.
  const auto digest_for = [](double rack_limit) {
    RackFabricOptions options;
    options.clock = std::make_shared<ManualClock>(rf_test::kObservationMillis);
    RackFabric fabric(options);
    rf_test::declare_rack(fabric, "rack-a", "epoch-1");
    const AuthorityToken op = rf_test::operator_token(fabric, "rack-a");
    for (int index = 0; index < 24; ++index) {
      MemberRecord record = member(MemberKind::Node, "node-" + std::to_string(100 + index));
      for (int capability = 0; capability < 256; ++capability) {
        CapabilityRef ref;
        ref.id = CapabilityId{"cap-" + std::string(100, 'x') + "-" + std::to_string(capability)};
        ref.provenance = EvidenceProvenance::Measured;
        ref.observed_at = observed();
        ref.durability = Durability::Durable;
        ref.value = std::string(120, 'v');
        record.capabilities.push_back(ref);
      }
      (void)publish(fabric, op, record);
    }
    PublishPowerEnvelopeRequest power;
    power.authority = op;
    power.record = power_envelope(rack_limit);
    (void)fabric.publish_power_envelope(power);
    SnapshotRequest request;
    request.authority = op;
    const SnapshotResult snapshot = fabric.publish_snapshot(request);
    return snapshot.ok() ? snapshot.snapshot->digest() : std::string("unpublished");
  };
  const std::string low = digest_for(10000.0);
  const std::string high = digest_for(20000.0);
  RF_CHECK(low != "unpublished");
  RF_CHECK_NE(low, high);
}

RF_TEST(regression, zero_snapshot_retention_retains_nothing) {
  RackFabricOptions options;
  options.limits.max_retained_snapshots = 0;
  RackFabric fabric(options);
  rf_test::declare_rack(fabric, "rack-a", "epoch-1");
  SnapshotRequest request;
  request.authority = rf_test::operator_token(fabric, "rack-a");
  RF_CHECK(fabric.publish_snapshot(request).ok());
  RF_CHECK(fabric.publish_snapshot(request).ok());
  RF_CHECK_EQ(fabric.snapshot_count(), std::size_t{0});
  TempDir directory;
  RF_CHECK_EQ(fabric.save_state(directory.file("state.rkf")).status, PersistenceStatus::Ok);
}

// ---------------------------------------------------------------------------
// Coordinator sessions over a real loopback socket
// ---------------------------------------------------------------------------

RF_TEST(regression, a_failed_hello_ends_the_session) {
  const Winsock winsock;
  RF_REQUIRE(winsock.ok);
  const auto server = start_server(CoordinatorOptions{});
  RF_REQUIRE(server != nullptr);
  Wire wire;
  RF_REQUIRE(wire.open(server->port(), 3000));
  HelloMessage hello;
  hello.protocol_version = static_cast<std::uint16_t>(kProtocolVersion + 1);
  hello.agent_version = "future";
  Frame reply;
  RF_REQUIRE(wire.send(MessageType::Hello, encoded(hello)) && wire.receive(reply));
  RF_CHECK_EQ(reply.type, MessageType::Error);

  RegisterMessage message;
  message.rack = RackId{"rack-a"};
  message.worker = WorkerId{"worker-1"};
  message.boot = AgentBootId{"boot-1"};
  message.coordinator_epoch = server->epoch();
  (void)wire.send(MessageType::Register, encoded(message));
  Frame after;
  const bool answered = wire.receive(after);
  RF_CHECK(!answered || after.type != MessageType::RegisterAck);
  RF_CHECK(!server->fabric().find_publisher(AgentBootId{"boot-1"}).has_value());
  server->stop();
}

RF_TEST(regression, every_mutation_is_answered_whatever_its_explanation_length) {
  const Winsock winsock;
  RF_REQUIRE(winsock.ok);
  const auto server = start_server(CoordinatorOptions{});
  RF_REQUIRE(server != nullptr);
  const std::string long_a = "a-" + std::string(120, 'a');
  const std::string long_b = "b-" + std::string(120, 'b');
  const AuthorityToken op = rf_test::operator_token(server->fabric(), "rack-a");
  RF_REQUIRE(publish(server->fabric(), op, member(MemberKind::Accelerator, long_a)).accepted());
  RF_REQUIRE(publish(server->fabric(), op, member(MemberKind::Accelerator, long_b)).accepted());

  Wire wire;
  RF_REQUIRE(wire.open(server->port(), 3000));
  const auto publication = open_session(wire, *server, "boot-1");
  RF_REQUIRE(publication.has_value());

  // A rejection whose explanation is longer than one protocol string.
  PublishMemberMessage jump;
  jump.authority = wire_token(*server, "boot-1", *publication);
  jump.record = member(MemberKind::Accelerator, long_a);
  jump.record.generation = MemberGeneration::from_value(5);
  RF_REQUIRE(wire.send(MessageType::PublishDevice, encoded(jump)));
  const auto rejected = receive_result(wire, wire.correlation);
  RF_REQUIRE(rejected.has_value());
  RF_CHECK(!rejected->accepted);
  RF_CHECK_EQ(rejected->code, std::string("MEMBER_GENERATION_JUMP"));

  // An acceptance whose subject is longer than one protocol string.
  PublishLinkMessage link;
  link.authority = wire_token(*server, "boot-1", *publication);
  link.record = relationship(RelationshipClass::AttachedTo, MemberKey{MemberKind::Accelerator, long_a},
                             MemberKey{MemberKind::Accelerator, long_b});
  RF_REQUIRE(wire.send(MessageType::PublishLink, encoded(link)));
  const auto published = receive_result(wire, wire.correlation);
  RF_REQUIRE(published.has_value());
  RF_CHECK(published->accepted);
  server->stop();
}

RF_TEST(regression, a_snapshot_request_is_answered_exactly_once) {
  const Winsock winsock;
  RF_REQUIRE(winsock.ok);
  const auto server = start_server(CoordinatorOptions{});
  RF_REQUIRE(server != nullptr);
  Wire wire;
  RF_REQUIRE(wire.open(server->port(), 3000));
  const auto publication = open_session(wire, *server, "boot-1");
  RF_REQUIRE(publication.has_value());

  SnapshotRequestMessage request;
  request.authority = wire_token(*server, "boot-1", *publication);
  RF_REQUIRE(wire.send(MessageType::SnapshotRequest, encoded(request)));
  Frame snapshot;
  RF_REQUIRE(wire.receive(snapshot));
  RF_CHECK_EQ(snapshot.type, MessageType::SnapshotResponse);
  RF_CHECK_EQ(snapshot.correlation, wire.correlation);

  // The next request receives its own answer, not a leftover one.
  QueryMessage query;
  query.query_kind = static_cast<std::uint16_t>(QueryKind::Summary);
  RF_REQUIRE(wire.send(MessageType::Query, encoded(query)));
  Frame answer;
  RF_REQUIRE(wire.receive(answer));
  RF_CHECK_EQ(answer.type, MessageType::Result);
  RF_CHECK_EQ(answer.correlation, wire.correlation);
  server->stop();
}

RF_TEST(regression, a_frame_spanning_the_session_poll_is_received_whole) {
  const Winsock winsock;
  RF_REQUIRE(winsock.ok);
  CoordinatorOptions options;
  options.session_wait = std::chrono::milliseconds{600};
  const auto server = start_server(options);
  RF_REQUIRE(server != nullptr);
  Wire wire;
  RF_REQUIRE(wire.open(server->port(), 5000));
  RF_REQUIRE(say_hello(wire));

  QueryMessage query;
  query.query_kind = static_cast<std::uint16_t>(QueryKind::Summary);
  const auto bytes = wire.frame_bytes(MessageType::Query, encoded(query));
  RF_REQUIRE(bytes.has_value() && bytes->size() > kFrameHeaderBytes);
  // Four pieces 250 ms apart: each gap is well inside the poll interval, the
  // whole frame is not.
  const std::size_t cuts[] = {0, 8, 16, kFrameHeaderBytes, bytes->size()};
  for (std::size_t piece = 0; piece + 1 < std::size(cuts); ++piece) {
    if (piece > 0) {
      std::this_thread::sleep_for(std::chrono::milliseconds{250});
    }
    RF_REQUIRE(wire.send_bytes(bytes->data() + cuts[piece], cuts[piece + 1] - cuts[piece]));
  }
  const auto answer = receive_result(wire, wire.correlation);
  RF_CHECK(answer.has_value());
  server->stop();
}

RF_TEST(regression, finished_sessions_release_their_threads) {
  const Winsock winsock;
  RF_REQUIRE(winsock.ok);
  const auto server = start_server(CoordinatorOptions{});
  RF_REQUIRE(server != nullptr);
  const auto cycle = [&server]() {
    Wire wire;
    if (wire.open(server->port(), 3000)) {
      (void)say_hello(wire);
    }
  };
  const auto settle = [&server]() {
    for (int poll = 0; poll < 500 && server->open_connections() != 0; ++poll) {
      std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
  };
  cycle();
  settle();
  std::this_thread::sleep_for(std::chrono::milliseconds{100});
  DWORD before = 0;
  RF_REQUIRE(GetProcessHandleCount(GetCurrentProcess(), &before) != 0);

  for (int index = 0; index < 64; ++index) {
    cycle();
  }
  settle();
  DWORD after = 0;
  for (int poll = 0; poll < 500; ++poll) {
    RF_REQUIRE(GetProcessHandleCount(GetCurrentProcess(), &after) != 0);
    if (after <= before + 16U) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{10});
  }
  RF_CHECK(after <= before + 16U);
  server->stop();
}

RF_TEST(regression, frequent_connections_do_not_starve_lease_expiry) {
  const Winsock winsock;
  RF_REQUIRE(winsock.ok);
  auto clock = std::make_shared<ManualClock>(rf_test::kObservationMillis);
  CoordinatorOptions options;
  options.fabric.clock = clock;
  options.fabric.limits.publisher_lease_millis = 1000;
  options.accept_wait = std::chrono::milliseconds{200};
  const auto server = start_server(options);
  RF_REQUIRE(server != nullptr);
  Wire wire;
  RF_REQUIRE(wire.open(server->port(), 3000));
  RF_REQUIRE(open_session(wire, *server, "boot-1").has_value());
  clock->advance(std::chrono::seconds{5});

  // A client that connects every 50 ms: no accept wait ever runs out.
  std::atomic<bool> stop{false};
  const std::uint16_t port = server->port();
  std::thread churn([&stop, port]() {
    while (!stop.load()) {
      Wire probe;
      (void)probe.open(port, 1000);
      probe.close();
      std::this_thread::sleep_for(std::chrono::milliseconds{50});
    }
  });
  bool fenced = false;
  for (int poll = 0; poll < 150 && !fenced; ++poll) {
    std::this_thread::sleep_for(std::chrono::milliseconds{20});
    fenced = server->fabric().is_boot_fenced(AgentBootId{"boot-1"});
  }
  stop.store(true);
  churn.join();
  RF_CHECK(fenced);
  server->stop();
}

RF_TEST(regression, an_agent_keeps_publishing_after_heartbeats) {
  const auto server = start_server(CoordinatorOptions{});
  RF_REQUIRE(server != nullptr);
  AgentOptions options;
  options.coordinator_port = server->port();
  options.worker = WorkerId{"worker-1"};
  options.rack = RackId{"rack-a"};
  options.heartbeat_interval = std::chrono::milliseconds{20};
  options.hardware.include_cpu = false;
  options.hardware.include_memory = false;
  options.hardware.include_nics = false;
  options.hardware.include_storage = false;
  options.hardware.include_accelerators = false;
  options.hardware.include_pci_devices = false;
  std::string error;
  auto agent = Agent::start(options, error);
  RF_REQUIRE(agent.has_value());
  for (int poll = 0; poll < 500 && (*agent)->report().heartbeats_sent < 2; ++poll) {
    std::this_thread::sleep_for(std::chrono::milliseconds{10});
  }
  RF_REQUIRE((*agent)->report().heartbeats_sent >= 2);

  const std::size_t before = (*agent)->report().results.size();
  RF_REQUIRE((*agent)->publish_now(error));
  const AgentReport report = (*agent)->report();
  RF_CHECK(report.results.size() > before);
  for (std::size_t index = before; index < report.results.size(); ++index) {
    RF_CHECK(!report.results[index].rejected());
  }
  (*agent)->stop();
  server->stop();
}
