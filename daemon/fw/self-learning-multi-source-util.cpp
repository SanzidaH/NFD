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

#include "self-learning-multi-source-util.hpp"
#include "algorithm.hpp"

#include "common/logger.hpp"
#include "common/global.hpp"
//#include "core/global-io.hpp"
#include "rib/service.hpp"

#include <ndn-cxx/lp/empty-value.hpp>
#include <ndn-cxx/lp/prefix-announcement-header.hpp>
#include <ndn-cxx/lp/tags.hpp>
#include <ndn-cxx/lp/util-header.hpp>

#include <boost/range/adaptor/reversed.hpp>

#include "ns3/ndnSIM/helper/ndn-fib-helper.hpp"
#include "ns3/ndnSIM/helper/ndn-stack-helper.hpp"

namespace nfd {
namespace fw {

NFD_LOG_INIT(SelfLearningStrategyMultiSourceUtil);
NFD_REGISTER_STRATEGY(SelfLearningStrategyMultiSourceUtil);

const time::milliseconds SelfLearningStrategyMultiSourceUtil::ROUTE_RENEW_LIFETIME(600_s);

SelfLearningStrategyMultiSourceUtil::SelfLearningStrategyMultiSourceUtil(Forwarder& forwarder, const Name& name)
  : Strategy(forwarder)
{
  ParsedInstanceName parsed = parseInstanceName(name);
  if (!parsed.parameters.empty()) {
    BOOST_THROW_EXCEPTION(std::invalid_argument("SelfLearningStrategyMultiSourceUtil does not accept parameters"));
  }
  if (parsed.version && *parsed.version != getStrategyName()[-1].toVersion()) {
    BOOST_THROW_EXCEPTION(std::invalid_argument(
      "SelfLearningStrategyMultiSourceUtil does not support version " + to_string(*parsed.version)));
  }
  this->setInstanceName(makeInstanceName(name, getStrategyName()));
  time_limit = 100;
  weight = 1;

  m_utilInterestNumber = 2;

  alpha = 0.5;
}

const Name&
SelfLearningStrategyMultiSourceUtil::getStrategyName()
{
  static Name strategyName("/localhost/nfd/strategy/self-learning-multi-source-util/%FD%01");
  return strategyName;
}

void
SelfLearningStrategyMultiSourceUtil::afterReceiveInterest(const FaceEndpoint& ingress, const Interest& interest,
                                           const shared_ptr<pit::Entry>& pitEntry)
{
  const Face& inFace = ingress.face;	
  NFD_LOG_DEBUG("Received Interest: " << interest << " from=" << inFace.getId());

  // check if the Interest was recently NACKed
  for (auto i = m_recentlyNacked.begin(); i != m_recentlyNacked.end(); i++) {
    if ((*i) == interest.getName()) {
      NFD_LOG_DEBUG("NACKed Interest recently. Sending NACK directly for: " << interest.getName());
      lp::Nack nack(std::move(interest));
      nack.setReason(lp::NackReason::OVERLOADED);
      this->sendNacks(pitEntry, nack.getHeader());
      return;
    }
  }

  auto outRecIt = pitEntry->getOutRecord(inFace);
  if (outRecIt != pitEntry->out_end()) {
    return;
  }

  if (interest.hasApplicationParameters())
    m_InterestCounter++;

  const fib::Entry& fibEntry = this->lookupFib(*pitEntry);
  const fib::NextHopList& nexthops = fibEntry.getNextHops();

  // if received a util Interest, set Interest counter to 1
  if (interest.getTag<lp::UtilInterestTag>() != nullptr) {
    m_InterestCounter = 1;
    NFD_LOG_DEBUG("Received Util Interest: " << interest.getName());
    multicastInterest(interest, inFace, pitEntry, nexthops);
    return;
  }

  // check if Interest needs to be marked as utilization Interest
  if (m_InterestCounter % m_utilInterestNumber == 0) {
    NFD_LOG_DEBUG("Setting Util Tag for Interest: " << interest.getName());
    // Interest newInterest(interest.wireEncode());
    interest.setTag(make_shared<lp::UtilInterestTag>(lp::EmptyValue{}));
    m_InterestCounter = 1;
    multicastInterest(interest, inFace, pitEntry, nexthops);
    return;
  }

  bool isNonDiscovery = interest.getTag<lp::NonDiscoveryTag>() != nullptr;
  auto inRecordInfo = pitEntry->getInRecord(inFace)->insertStrategyInfo<InRecordInfo>().first;
  if (isNonDiscovery) { // "non-discovery" Interest
    inRecordInfo->isNonDiscoveryInterest = true;
    if (nexthops.empty()) { // return NACK if no matching FIB entry exists
      NFD_LOG_DEBUG("NACK non-discovery Interest=" << interest << " from=" << inFace.getId() << " noNextHop");
      lp::NackHeader nackHeader;
      nackHeader.setReason(lp::NackReason::NO_ROUTE);
      this->sendNack(pitEntry, FaceEndpoint(inFace,0), nackHeader);
      this->rejectPendingInterest(pitEntry);
    }
    else { // forward to best next hop if FIB entry already exists
      // multicastInterest(interest, inFace, pitEntry, nexthops);
      const fib::Entry& fibEntry = this->lookupFib(*pitEntry);
      for (const auto& nexthop : fibEntry.getNextHops()) {
        Face& outFace = nexthop.getFace();
        if (!wouldViolateScope(inFace, interest, outFace) &&
            canForwardToLegacy(*pitEntry, outFace)) {
          this->sendInterest(pitEntry, FaceEndpoint(outFace,0), interest);
          return;
        }
      }
    }
  }
  else { // "discovery" Interest
    inRecordInfo->isNonDiscoveryInterest = false;
    if (nexthops.empty()) { // broadcast it if no matching FIB entry exists
      broadcastInterest(interest, inFace, pitEntry);
    }
    else { // multicast it with "non-discovery" mark if matching FIB entry exists
      interest.setTag(make_shared<lp::NonDiscoveryTag>(lp::EmptyValue{}));
      multicastInterest(interest, inFace, pitEntry, nexthops);
    }
  }
}

void
SelfLearningStrategyMultiSourceUtil::afterReceiveData(const shared_ptr<pit::Entry>& pitEntry,
                                       const FaceEndpoint& ingress, const Data& data)
{
  const Face& inFace = ingress.face;
  NFD_LOG_DEBUG("Received data packet for: " << data.getName().toUri());

  if (data.getTag<lp::UtilTag>() != nullptr) {
    // process data packet with utilization tag
    processUtilData(pitEntry, inFace, data);
    return;
  }

  OutRecordInfo* outRecordInfo = pitEntry->getOutRecord(inFace)->getStrategyInfo<OutRecordInfo>();
  if (outRecordInfo && outRecordInfo->isNonDiscoveryInterest) { // outgoing Interest was non-discovery
    if (!needPrefixAnn(pitEntry)) { // no need to attach a PA (common cases)
      sendDataToAll(pitEntry,FaceEndpoint(inFace,0), data);
    }
    else { // needs a PA (to respond discovery Interest)
      asyncProcessData(pitEntry, inFace, data);
    }
  }
  else { // outgoing Interest was discovery
    auto paTag = data.getTag<lp::PrefixAnnouncementTag>();
    if (paTag != nullptr) {
      //addRoute(pitEntry, inFace, data, *paTag->get().getPrefixAnn());
      // find outstanding Interest
      for (auto i = m_outstandingInterests.begin(); i != m_outstandingInterests.end(); i++) {
        if (std::get<0>(*i).isPrefixOf(data.getName())) {
          NFD_LOG_DEBUG("Received data packet with prefix announcement for: " << paTag->get().getPrefixAnn()->getAnnouncedName().toUri());
          ns3::ndn::FibHelper::AddRoute(m_forwarder.m_node, paTag->get().getPrefixAnn()->getAnnouncedName(), inFace.getId(), weight * std::get<2>(*i));
          // check if we have already sent response back
          for (auto itPit = m_deletePit.begin(); itPit != m_deletePit.end(); itPit++) {
            if (std::get<0>(*itPit).isPrefixOf(data.getName())) {
              NFD_LOG_DEBUG("Have already sent response for: " << std::get<0>(*itPit) << ". Returning...");
              m_deletePit.erase(itPit);
              return;
            }
          }

          // if first response, get delay for shortest path
          if (std::get<2>(*i) == 0) {
            ns3::EventId id = ns3::Simulator::Schedule(ns3::MilliSeconds(time_limit), &SelfLearningStrategyMultiSourceUtil::sendBackResponse, this, pitEntry->getInterest().getName(), pitEntry);
            std::get<6>(*i) = id;
            std::get<4>(*i) = (ns3::Simulator::Now() - std::get<1>(*i)).GetMilliSeconds();
            m_shortestPathData.push_back(std::make_tuple(data.shared_from_this(), pitEntry, inFace.getId()));
          }
          // if not first response, record delta
          else {
            int delta = (ns3::Simulator::Now() - std::get<1>(*i)).GetMilliSeconds();
            // check if this delta is greater than already recorded delta
            if (delta > std::get<5>(*i)) {
              std::get<5>(*i) = delta;
            }
          }

          //
          std::get<2>(*i) = std::get<2>(*i) + 1;
          if (std::get<2>(*i) == std::get<3>(*i)) {
            std::get<6>(*i).Cancel();
            // Send data to the downstream
            for (auto it = m_shortestPathData.begin(); it != m_shortestPathData.end(); it++) {
              if (std::get<0>(*i).isPrefixOf(std::get<0>(*it)->getName())) {

                // // send data to all in-records
                // for (auto inRec = pitEntry->getInRecords().begin(); inRec != pitEntry->getInRecords().end(); inRec++) {
                //   this->sendData(pitEntry, std::get<0>(*it), inRec->getFace());
                // }
                // std::get<0>(*it).removeTag<lp::PrefixAnnouncementTag>();
                NFD_LOG_DEBUG("Got all responses. Sending response back:" << std::get<0>(*it)->getName());
                FaceId faceId = std::get<2>(*it);
                this->sendDataToAll(pitEntry, FaceEndpoint(*getFace(faceId),0), *(std::get<0>(*it)));
                m_shortestPathData.erase(it);
                m_outstandingInterests.erase(i);
                beforeSatisfyInterest(pitEntry, FaceEndpoint(*getFace(faceId),0), *(std::get<0>(*it)));
                deletePitEntry(pitEntry, faceId);
                return;
              }
            }
          }
          return;
        }
      }
      NFD_LOG_DEBUG("Could not find matching Interest: " << data.getName());
    }
    else { // Data contains no PrefixAnnouncement, upstreams do not support self-learning
      sendDataToAll(pitEntry, FaceEndpoint(inFace,0), data);
    }
  }
}

void
SelfLearningStrategyMultiSourceUtil::afterReceiveNack(const FaceEndpoint& ingress, const lp::Nack& nack,
                                       const shared_ptr<pit::Entry>& pitEntry)
{
  const Face& inFace =  ingress.face;
  NFD_LOG_DEBUG("Nack for " << nack.getInterest() << " from=" << inFace.getId() << ": " << nack.getReason());
  if (nack.getReason() == lp::NackReason::NO_ROUTE) { // remove FIB entries
    BOOST_ASSERT(this->lookupFib(*pitEntry).hasNextHops());
    NFD_LOG_DEBUG("Send NACK to all downstreams");
    this->sendNacks(pitEntry, nack.getHeader());
    renewRoute(nack.getInterest().getName(), inFace.getId(), 0_ms);
  }
  else if (nack.getReason() == lp::NackReason::OVERLOADED) { // edge node overloaded
    const fib::Entry& fibEntry = this->lookupFib(*pitEntry);
    for (const auto& nexthop : fibEntry.getNextHops()) {
      // find previously received NACKs
      bool faceNacked = false;
      for (auto i = pitEntry->out_begin(); i != pitEntry->out_end(); i++) {
        if (&(i->getFace()) == &(nexthop.getFace())) {
          faceNacked = true;
          break;
        }
        for (auto i = pitEntry->in_begin(); i != pitEntry->in_end(); i++) {
          if (&(i->getFace()) == &(nexthop.getFace())) {
            faceNacked = true;
            break;
          }
        }
      }
      if (!faceNacked) {
        Face& outFace = nexthop.getFace();
        this->setExpiryTimer(pitEntry, 1000_ms);
        this->sendInterest(pitEntry, FaceEndpoint(outFace,0), pitEntry->getInterest());
        return;
      }
    }
    NFD_LOG_DEBUG("Send OVERLOADED NACK to all downstreams");
    m_recentlyNacked.push_back(pitEntry->getInterest().getName());
    ns3::Simulator::Schedule(ns3::MilliSeconds(time_limit), &SelfLearningStrategyMultiSourceUtil::deleteNackedInterest, this, pitEntry->getInterest().getName());
    this->sendNacks(pitEntry, nack.getHeader());
  }
}

void
SelfLearningStrategyMultiSourceUtil::broadcastInterest(const Interest& interest, const Face& inFace,
                                        const shared_ptr<pit::Entry>& pitEntry)
{
  int face_counter = 0;
  for (auto& outFace : this->getFaceTable() | boost::adaptors::reversed) {
    if ((outFace.getId() == inFace.getId() && outFace.getLinkType() != ndn::nfd::LINK_TYPE_AD_HOC) ||
        wouldViolateScope(inFace, interest, outFace) || outFace.getScope() == ndn::nfd::FACE_SCOPE_LOCAL) {
      continue;
    }
    face_counter++;
    this->sendInterest(pitEntry,FaceEndpoint(outFace,0), interest);
    pitEntry->getOutRecord(outFace)->insertStrategyInfo<OutRecordInfo>().first->isNonDiscoveryInterest = false;
    NFD_LOG_DEBUG("send discovery Interest=" << interest << " from="
                  << inFace.getId() << " to=" << outFace.getId());
  }
  ns3::EventId id;
  m_outstandingInterests.push_back(std::make_tuple(interest.getName(), ns3::Simulator::Now(), 0, face_counter, 0, 0, id));
}

void
SelfLearningStrategyMultiSourceUtil::multicastInterest(const Interest& interest, const Face& inFace,
                                        const shared_ptr<pit::Entry>& pitEntry,
                                        const fib::NextHopList& nexthops)
{
  int face_counter = 0;
  for (const auto& nexthop : nexthops) {
    Face& outFace = nexthop.getFace();
    if ((outFace.getId() == inFace.getId() && outFace.getLinkType() != ndn::nfd::LINK_TYPE_AD_HOC) ||
        wouldViolateScope(inFace, interest, outFace)) {
      continue;
    }
    face_counter++;
    this->sendInterest(pitEntry, FaceEndpoint(outFace,0), interest);
    pitEntry->getOutRecord(outFace)->insertStrategyInfo<OutRecordInfo>().first->isNonDiscoveryInterest = true;
    NFD_LOG_DEBUG("send non-discovery Interest=" << interest << " from="
                  << inFace.getId() << " to=" << outFace.getId());
  }
  if (interest.getTag<lp::UtilInterestTag>() != nullptr) {
    ns3::EventId id;
    m_outstandingUtilData.push_back(std::make_tuple(interest.getName(), 0, face_counter, id, ns3::Simulator::Now()));
  }
}

void
SelfLearningStrategyMultiSourceUtil::asyncProcessData(const shared_ptr<pit::Entry>& pitEntry, const Face& inFace, const Data& data)
{
  // Given that this processing is asynchronous, the PIT entry's expiry timer is extended first
  // to ensure that the entry will not be removed before the whole processing is finished
  // (the PIT entry's expiry timer was set to 0 before dispatching)
  this->setExpiryTimer(pitEntry, 1_s);

  ndn::PrefixAnnouncement pa;
  pa.setAnnouncedName(Name(data.getName().get(0).toUri()));
  pa.toData(ns3::ndn::StackHelper::getKeyChain());
  NFD_LOG_DEBUG("Attaching PrefixAnnouncement=" << pa.getAnnouncedName());
  data.setTag(make_shared<lp::PrefixAnnouncementTag>(lp::PrefixAnnouncementHeader(pa)));
  // send data to all in-records
  this->sendDataToAll(pitEntry,FaceEndpoint(inFace,0), data);
}

bool
SelfLearningStrategyMultiSourceUtil::needPrefixAnn(const shared_ptr<pit::Entry>& pitEntry)
{
  bool hasDiscoveryInterest = false;
  bool directToConsumer = true;

  auto now = time::steady_clock::now();
  for (const auto& inRecord : pitEntry->getInRecords()) {
    if (inRecord.getExpiry() > now) {
      InRecordInfo* inRecordInfo = inRecord.getStrategyInfo<InRecordInfo>();
      if (inRecordInfo && !inRecordInfo->isNonDiscoveryInterest) {
        hasDiscoveryInterest = true;
      }
      if (inRecord.getFace().getScope() != ndn::nfd::FACE_SCOPE_LOCAL) {
        directToConsumer = false;
      }
    }
  }
  return hasDiscoveryInterest && !directToConsumer;
}

void
SelfLearningStrategyMultiSourceUtil::renewRoute(const Name& name, FaceId inFaceId, time::milliseconds maxLifetime)
{
  // renew route with PA or ignore PA (if route has no PA)
  runOnRibIoService([name, inFaceId, maxLifetime] {
    rib::Service::get().getRibManager().slRenew(name, inFaceId, maxLifetime,
      [] (RibManager::SlAnnounceResult res) {
        NFD_LOG_DEBUG("Renew route with result=" << res);
      });
  });
}

void
SelfLearningStrategyMultiSourceUtil::sendBackResponse(Name name, shared_ptr<pit::Entry>& UnSatisfiedPitEntry)
{
  NFD_LOG_DEBUG("Time is over. Looking for response: " << name);
  for (auto i = m_outstandingInterests.begin(); i != m_outstandingInterests.end(); i++) {
    if (std::get<0>(*i) == name) {
      for (auto it = m_shortestPathData.begin(); it != m_shortestPathData.end(); it++) {
        // std::cout << "std::get<0>(*i): " << std::get<0>(*i) << std::endl;
        // std::cout << "std::get<0>(*it)->getName(): " << std::get<0>(*it)->getName() << std::endl;
        if (std::get<0>(*i).isPrefixOf(std::get<0>(*it)->getName())) {
          //std::cout << "In if statement" << std::endl;
          // send to all in records
          shared_ptr<pit::Entry>& pitEntry = std::get<1>(*it);
          // for (auto inRec = pitEntry->getInRecords().begin(); inRec != pitEntry->getInRecords().end(); inRec++) {
          //   this->sendData(pitEntry, std::get<0>(*it), inRec->getFace());
          // }
          NFD_LOG_DEBUG("Sending back response:" << name);
          this->sendDataToAll(pitEntry,FaceEndpoint(*getFace(std::get<2>(*it)),0), *(std::get<0>(*it)));
          beforeSatisfyInterest(pitEntry, FaceEndpoint(*getFace(std::get<2>(*it)),0), *(std::get<0>(*it)));
          ns3::EventId id = ns3::Simulator::Schedule(ns3::MilliSeconds(time_limit), &SelfLearningStrategyMultiSourceUtil::deletePitEntry, this, pitEntry, std::get<2>(*it));
          m_deletePit.push_back(std::make_tuple(std::get<0>(*i), id));
          m_shortestPathData.erase(it);
          ns3::Simulator::Schedule(ns3::MilliSeconds(time_limit), &SelfLearningStrategyMultiSourceUtil::eraseOutstandingInterest, this, name);
          return;
        }
      }
    }
    break;
  }
  // set PIT expiry timer to now
  this->setExpiryTimer(UnSatisfiedPitEntry, 0_ms);
}

void
SelfLearningStrategyMultiSourceUtil::deletePitEntry(const shared_ptr<pit::Entry>& pitEntry, FaceId faceid)
{
  // set PIT expiry timer to now
  this->setExpiryTimer(pitEntry, 0_ms);

  pitEntry->isSatisfied = true;
  //pitEntry->dataFreshnessPeriod = data.getFreshnessPeriod();

  // Dead Nonce List insert if necessary (for out-record of inFace)
  m_forwarder.insertDeadNonceList(*pitEntry, getFace(faceid));

  // delete PIT entry's out-record
  pitEntry->deleteOutRecord(*getFace(faceid));
}

void
SelfLearningStrategyMultiSourceUtil::eraseOutstandingInterest(Name name)
{
  for (auto i = m_outstandingInterests.begin(); i != m_outstandingInterests.end(); i++) {
    if (std::get<0>(*i) == name) {
      m_outstandingInterests.erase(i);
      return;
    }
  }
}

void
SelfLearningStrategyMultiSourceUtil::deleteNackedInterest(Name name)
{
  for (auto i = m_recentlyNacked.begin(); i != m_recentlyNacked.end(); i++) {
    if ((*i) == name) {
      m_recentlyNacked.erase(i);
      return;
    }
  }
}

void
SelfLearningStrategyMultiSourceUtil::processUtilData(const shared_ptr<pit::Entry>& pitEntry,
                                       const Face& inFace, const Data& data)
{
  // find outstanding Interest
  for (auto i = m_outstandingUtilData.begin(); i != m_outstandingUtilData.end(); i++) {
    // std::cout << "std::get<0>(*i): " << std::get<0>(*i) << std::endl;
    // std::cout << "data.getName(): " << data.getName() << std::endl;
    if (std::get<0>(*i).isPrefixOf(data.getName())) {
      uint32_t delay = (ns3::Simulator::Now() - std::get<4>(*i)).GetMilliSeconds();
      // update the weights of FIB next hops
      updateNextHopWeights(pitEntry, inFace, data, delay);

      NFD_LOG_DEBUG("Received data packet with utilization: " << data.getName());
      // if first response, get delay for shortest path
      if (std::get<1>(*i) == 0) {
        ns3::EventId id = ns3::Simulator::Schedule(ns3::MilliSeconds(time_limit), &SelfLearningStrategyMultiSourceUtil::sendBackResponseUtil, this, pitEntry->getInterest().getName(), pitEntry);
        std::get<3>(*i) = id;
        m_shortestPathData.push_back(std::make_tuple(data.shared_from_this(), pitEntry, inFace.getId()));
        // add utilization and delays to UtilTag
        ndn::lp::UtilStruct u;
        auto oldUtilTag = data.getTag<ndn::lp::UtilTag>();
        u.utils.insert(u.utils.begin(), oldUtilTag->get().m_utils->utils.begin(), oldUtilTag->get().m_utils->utils.end());
        u.delays.insert(u.delays.begin(), oldUtilTag->get().m_utils->delays.begin(), oldUtilTag->get().m_utils->delays.end());
        for (auto it = u.delays.begin(); it != u.delays.end(); it++) {
          *it = *it + delay;
        }
        // finally set the updated tag of the packet
        ndn::lp::UtilHeader h(u);
        data.setTag(make_shared<ndn::lp::UtilTag>(h));
      }
      // if not first response, attach Util to data packet
      else {
        for (auto it = m_shortestPathData.begin(); it != m_shortestPathData.end(); it++) {
          if (std::get<0>(*i).isPrefixOf(std::get<0>(*it)->getName())) {
            ndn::lp::UtilStruct u;
            // get tag of newly arrived data packet and create a new Util Tag
            auto newUtilTag = data.getTag<ndn::lp::UtilTag>();
            u.utils.insert(u.utils.begin(), newUtilTag->get().m_utils->utils.begin(), newUtilTag->get().m_utils->utils.end());
            // add reception delay to existing delays of the received tag
            u.delays.insert(u.delays.begin(), newUtilTag->get().m_utils->delays.begin(), newUtilTag->get().m_utils->delays.end());
            for (auto it2 = u.delays.begin(); it2 != u.delays.end(); it2++) {
              *it2 = *it2 + delay;
            }
            auto oldUtilTag = std::get<0>(*it)->getTag<ndn::lp::UtilTag>();
            u.utils.insert(u.utils.begin(), oldUtilTag->get().m_utils->utils.begin(), oldUtilTag->get().m_utils->utils.end());
            u.delays.insert(u.delays.begin(), oldUtilTag->get().m_utils->delays.begin(), oldUtilTag->get().m_utils->delays.end());

            // finally set the updated tag of the packet
            ndn::lp::UtilHeader h(u);
            std::get<0>(*it)->setTag(make_shared<ndn::lp::UtilTag>(h));
          }
        }
      }

      //
      std::get<1>(*i) = std::get<1>(*i) + 1;
      if (std::get<1>(*i) == std::get<2>(*i)) {
        std::get<3>(*i).Cancel();
        // Send data to the downstream
        for (auto it = m_shortestPathData.begin(); it != m_shortestPathData.end(); it++) {
          if (std::get<0>(*i).isPrefixOf(std::get<0>(*it)->getName())) {
            NFD_LOG_DEBUG("Got all responses for utilization. Sending response back:" << std::get<0>(*it)->getName());
            FaceId faceId = std::get<2>(*it);
            this->sendDataToAll(pitEntry, FaceEndpoint(*getFace(faceId),0), *(std::get<0>(*it)));
            m_shortestPathData.erase(it);
            m_outstandingUtilData.erase(i);
            beforeSatisfyInterest(pitEntry, FaceEndpoint(*getFace(faceId),0), *(std::get<0>(*it)));
            deletePitEntry(pitEntry, faceId);
            return;
          }
        }
      }
      return;
    }
  }
  NFD_LOG_DEBUG("Could not find matching util Interest: " << data.getName());
}

void
SelfLearningStrategyMultiSourceUtil::sendBackResponseUtil(Name name, shared_ptr<pit::Entry>& UnSatisfiedPitEntry)
{
  NFD_LOG_DEBUG("Time is over. Looking for util response: " << name);
  for (auto i = m_outstandingUtilData.begin(); i != m_outstandingUtilData.end(); i++) {
    if (std::get<0>(*i) == name) {
      for (auto it = m_shortestPathData.begin(); it != m_shortestPathData.end(); it++) {
        // std::cout << "std::get<0>(*i): " << std::get<0>(*i) << std::endl;
        // std::cout << "std::get<0>(*it)->getName(): " << std::get<0>(*it)->getName() << std::endl;
        if (std::get<0>(*i).isPrefixOf(std::get<0>(*it)->getName())) {
          //std::cout << "In if statement" << std::endl;
          // send to all in records
          shared_ptr<pit::Entry>& pitEntry = std::get<1>(*it);
          // for (auto inRec = pitEntry->getInRecords().begin(); inRec != pitEntry->getInRecords().end(); inRec++) {
          //   this->sendData(pitEntry, std::get<0>(*it), inRec->getFace());
          // }
          NFD_LOG_DEBUG("Sending back util response:" << name);
          this->sendDataToAll(pitEntry,FaceEndpoint(*getFace(std::get<2>(*it)),0), *(std::get<0>(*it)));
          beforeSatisfyInterest(pitEntry,FaceEndpoint(*getFace(std::get<2>(*it)),0), *(std::get<0>(*it)));
          ns3::EventId id = ns3::Simulator::Schedule(ns3::MilliSeconds(0), &SelfLearningStrategyMultiSourceUtil::deletePitEntry, this, pitEntry, std::get<2>(*it));
          // m_deletePit.push_back(std::make_tuple(std::get<0>(*i), id));
          m_shortestPathData.erase(it);
          ns3::Simulator::Schedule(ns3::MilliSeconds(0), &SelfLearningStrategyMultiSourceUtil::eraseOutstandingInterest, this, name);
          return;
        }
      }
    }
    break;
  }
  // set PIT expiry timer to now
  this->setExpiryTimer(UnSatisfiedPitEntry, 0_ms);
}

void
SelfLearningStrategyMultiSourceUtil::updateNextHopWeights(const shared_ptr<pit::Entry>& pitEntry,
                                                          const Face& inFace, const Data& data, uint32_t delay)
{
  auto utilTag = data.getTag<ndn::lp::UtilTag>();
  uint32_t sumDelays = 0;
  uint32_t sumUtils = 0;
  uint32_t counter = 0;

  for (auto i = utilTag->get().m_utils->utils.begin(); i != utilTag->get().m_utils->utils.end(); i++) {
    sumUtils += *i;
    sumDelays = sumDelays + delay + utilTag->get().m_utils->delays[counter];
    counter++;
  }

  // const fib::Entry& fibEntry = this->lookupFib(*pitEntry);
  fib::Entry* fibEntry = m_forwarder.m_fib.findExactMatch(Name(data.getName().get(0).toUri()));
  for (auto& nexthop : fibEntry->getNextHops()) {
    Face& outFace = nexthop.getFace();
    if (&outFace == &inFace) {
     //// uint64_t endpointId = nexthop.getEndpointId();
      // objective function
      double value = alpha * ((1.0 * sumDelays) / counter) + (1 - alpha) * (((1.0 * sumUtils) / counter));
      // fibEntry.addOrUpdateNextHop(inFace, endpointId, value);
      fibEntry->findNextHop(inFace)->setCost(value);
      fibEntry->sortNextHops();
      return;
    }
  }

}

} // namespace fw
} // namespace nfd
