/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2019,  Regents of the University of California,
 *                           Arizona Board of Regents,
 *                           Colorado State University,
 *                           University Pierre & Marie Curie, Sorbonne University,
 *                           Washington University in St. Louis,
 *                           Beijing Institute of Technology,
 *                           The University of Memphis.
 *
 * This file is part of NFD (Named Data Networking Forwarding Daemon).
 * See AUTHORS.md for complete list of NFD authors and contributors.
 *
 * NFD is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * NFD is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NFD, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NFD_DAEMON_FW_SELF_LEARNING_STRATEGY_MULTI_SOURCE_UTIL_HPP
#define NFD_DAEMON_FW_SELF_LEARNING_STRATEGY_MULTI_SOURCE_UTIL_HPP

#include "fw/strategy.hpp"

#include <ndn-cxx/lp/prefix-announcement-header.hpp>

namespace nfd {
namespace fw {

/** \brief Self-learning strategy
 *
 *  This strategy first broadcasts Interest to learn a all the paths towards data
 *
 */
class SelfLearningStrategyMultiSourceUtil : public Strategy
{
public:
  explicit
  SelfLearningStrategyMultiSourceUtil(Forwarder& forwarder, const Name& name = getStrategyName());

  static const Name&
  getStrategyName();

  /// StrategyInfo on pit::InRecord
  class InRecordInfo : public StrategyInfo
  {
  public:
    static constexpr int
    getTypeId()
    {
      return 1040;
    }

  public:
    bool isNonDiscoveryInterest = false;
  };

  /// StrategyInfo on pit::OutRecord
  class OutRecordInfo : public StrategyInfo
  {
  public:
    static constexpr int
    getTypeId()
    {
      return 1041;
    }

  public:
    bool isNonDiscoveryInterest = false;
  };

public: // triggers
  void
  afterReceiveInterest(const FaceEndpoint& ingress, const Interest& interest,
                       const shared_ptr<pit::Entry>& pitEntry) override;

  void
  afterReceiveData(const shared_ptr<pit::Entry>& pitEntry,
                   const FaceEndpoint& ingress, const Data& data) override;

  void
  afterReceiveNack(const FaceEndpoint& ingress, const lp::Nack& nack,
                   const shared_ptr<pit::Entry>& pitEntry) override;

private: // operations

  /** \brief Send an Interest to all possible faces
   *
   *  This function is invoked when the forwarder has no matching FIB entries for
   *  an incoming discovery Interest, which will be forwarded to faces that
   *    - do not violate the Interest scope
   *    - are non-local
   *    - are not the face from which the Interest arrived, unless the face is ad-hoc
   */
  void
  broadcastInterest(const Interest& interest, const Face& inFace,
                    const shared_ptr<pit::Entry>& pitEntry);

  /** \brief Send an Interest to \p nexthops
   */
  void
  multicastInterest(const Interest& interest, const Face& inFace,
                    const shared_ptr<pit::Entry>& pitEntry,
                    const fib::NextHopList& nexthops);

  /** \brief Find a Prefix Announcement for the Data on the RIB thread, and forward
   *         the Data with the Prefix Announcement on the main thread
   */
  void
  asyncProcessData(const shared_ptr<pit::Entry>& pitEntry, const Face& inFace, const Data& data);

  /** \brief Check whether a PrefixAnnouncement needs to be attached to an incoming Data
   *
   *  The conditions that a Data packet requires a PrefixAnnouncement are
   *    - the incoming Interest was discovery and
   *    - the outgoing Interest was non-discovery and
   *    - this forwarder does not directly connect to the consumer
   */
  static bool
  needPrefixAnn(const shared_ptr<pit::Entry>& pitEntry);

  void
  sendBackResponse(Name name, shared_ptr<pit::Entry>& UnSatisfiedPitEntry);

  /** \brief renew a route using RibManager::slRenew on the RIB thread
   */
  void
  renewRoute(const Name& name, FaceId inFaceId, time::milliseconds maxLifetime);

  void
  deletePitEntry(const shared_ptr<pit::Entry>& pitEntry, FaceId faceid);

  void
  eraseOutstandingInterest(Name name);

  void
  deleteNackedInterest(Name name);

  void
  processUtilData(const shared_ptr<pit::Entry>& pitEntry,
                  const Face& inFace, const Data& data);

  void
  sendBackResponseUtil(Name name, shared_ptr<pit::Entry>& UnSatisfiedPitEntry);

  void
  updateNextHopWeights(const shared_ptr<pit::Entry>& pitEntry, const Face& inFace, const Data& data, uint32_t delay);

private:
  static const time::milliseconds ROUTE_RENEW_LIFETIME;

  // <name, timestamp, responses received, number of interfaces, shortest path, delta, expiration event>
  std::vector<std::tuple<Name, ns3::Time, int, int, int, int, ns3::EventId>> m_outstandingInterests;

  // data, pit entry, in face
  std::vector<std::tuple<shared_ptr<const Data>, shared_ptr<pit::Entry>, FaceId>> m_shortestPathData;

  // name, event id
  std::vector<std::tuple<Name, ns3::EventId>> m_deletePit;

  // name, face id
  std::vector<Name> m_recentlyNacked;

  // time limit in ms
  int time_limit;

  // routing weight
  int weight;

  // next hop, util
  std::vector<std::tuple<FaceId, double>> m_utilTable;

  uint64_t m_InterestCounter; // number of Interests that have been received since last utilization report
  uint64_t m_utilInterestNumber; // how many Interests we request utilization reporting from edge nodes

  // Name, responses received, number of interfaces, expiration event, timestamp
  std::vector<std::tuple<Name, int, int, ns3::EventId, ns3::Time>> m_outstandingUtilData;

  double alpha; // alpha value for objective function of nexthop cost
};

} // namespace fw
} // namespace nfd

#endif // NFD_DAEMON_FW_SELF_LEARNING_STRATEGY_HPP
