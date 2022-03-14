/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2017,  Regents of the University of California,
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

#ifndef NFD_DAEMON_PROACTIVE_UTIL_STRATEGY_HPP
#define NFD_DAEMON_PROACTIVE_UTIL_STRATEGY_HPP
#include "forwarder.hpp"
#include "strategy.hpp"
#include "process-nack-traits.hpp"
#include "retx-suppression-exponential.hpp"

namespace nfd {
namespace fw {

/** \brief a forwarding strategy that forwards Interest to all FIB nexthops
 */
class ProactiveUtil : public Strategy
                        , public ProcessNackTraits<ProactiveUtil>
{
public:
  explicit
  ProactiveUtil(Forwarder& forwarder, const Name& name = getStrategyName());

  static const Name&
  getStrategyName();

  void
  afterReceiveInterest(const FaceEndpoint& ingress, const Interest& interest,
                       const shared_ptr<pit::Entry>& pitEntry) override;

  void
  afterReceiveNack(const FaceEndpoint& ingress, const lp::Nack& nack,
                   const shared_ptr<pit::Entry>& pitEntry) override;

  void
  broadcastInterest(const Interest& interest, const FaceEndpoint& ingress,
                    const shared_ptr<pit::Entry>& pitEntry);

  void
  processRegularInterest(const Face& inFace, const Interest& interest,
                         const shared_ptr<pit::Entry>& pitEntry);

  void
  processUtilInterest(const Face& inFace, const Interest& interest,
                      const shared_ptr<pit::Entry>& pitEntry);

  std::vector<std::string>
  SplitString( std::string strLine, int limit ) {

        std::string str = strLine;
        std::vector<std::string> result;
        std::istringstream isstr( str );
        int i = 0;
        std::string finalStr = "";

        for ( std::string str; isstr >> str;  ) {

                if ( i < limit || limit == 0 ) {
                        result.push_back( str );
                } else {
                        finalStr += str;
                }

                i++;
        }

        result.push_back( finalStr );

        return result;
  }

 std::set<std::string> utilMap;
private:
  int prevutilcnt;
  friend ProcessNackTraits<ProactiveUtil>;
  RetxSuppressionExponential m_retxSuppression;
  uint32_t  m_iface;
  // std::set<std::string> utilMap;
 // std::unordered_map<Name, std::unordered_set<uint64_t>> utilMap;
 // std::unordered_map<Name, std::unordered_set<std:string>> utilMap;
  // next hop, util
  std::vector<std::tuple<Name, std::vector<std::tuple<FaceId, double>>>> m_utilTable;

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  static const time::milliseconds RETX_SUPPRESSION_INITIAL;
  static const time::milliseconds RETX_SUPPRESSION_MAX;
};

} // namespace fw
} // namespace nfd

#endif // NFD_DAEMON_FW_MULTICAST_STRATEGY_HPP
