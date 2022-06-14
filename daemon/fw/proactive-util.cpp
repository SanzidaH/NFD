/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2018,  Regents of the University of California,
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

#include "proactive-util.hpp"
#include "algorithm.hpp"
#include "common/logger.hpp"
#include "strategy.hpp"
#include "forwarder.hpp"

#include <ndn-cxx/lp/empty-value.hpp>
#include <ndn-cxx/lp/prefix-announcement-header.hpp>
#include <ndn-cxx/lp/tags.hpp>
#include <ndn-cxx/lp/util-header.hpp>

#include <boost/range/adaptor/reversed.hpp>

#include "ns3/ndnSIM/helper/ndn-fib-helper.hpp"
#include "ns3/ndnSIM/helper/ndn-stack-helper.hpp"

namespace nfd {
namespace fw {

NFD_REGISTER_STRATEGY(ProactiveUtil);

NFD_LOG_INIT(ProactiveUtil);

const time::milliseconds ProactiveUtil::RETX_SUPPRESSION_INITIAL(10);
const time::milliseconds ProactiveUtil::RETX_SUPPRESSION_MAX(250);

ProactiveUtil::ProactiveUtil(Forwarder& forwarder, const Name& name)
  : Strategy(forwarder)
  , ProcessNackTraits(this)
  , m_retxSuppression(RETX_SUPPRESSION_INITIAL,
                      RetxSuppressionExponential::DEFAULT_MULTIPLIER,
                      RETX_SUPPRESSION_MAX)
{
  ParsedInstanceName parsed = parseInstanceName(name);
  if (!parsed.parameters.empty()) {
    BOOST_THROW_EXCEPTION(std::invalid_argument("ProactiveUtil does not accept parameters"));
  }
  if (parsed.version && *parsed.version != getStrategyName()[-1].toVersion()) {
    BOOST_THROW_EXCEPTION(std::invalid_argument(
      "ProactiveUtil does not support version " + to_string(*parsed.version)));
  }
  this->setInstanceName(makeInstanceName(name, getStrategyName()));
  prevutilcnt = 0;
  pertaskcnt["/prefix/1"] = 0;
  pertaskcnt["/prefix/2"] = 0;
  pertaskcnt["/prefix/3"] = 0;
  pertaskcnt["/prefix/4"] = 0;

}

const Name&
ProactiveUtil::getStrategyName()
{
  static Name strategyName("/localhost/nfd/strategy/proactive-util/%FD%01");
  return strategyName;
}

void
ProactiveUtil::afterReceiveInterest(const  FaceEndpoint& ingress, const Interest& interest,
                                    const shared_ptr<pit::Entry>& pitEntry)
{
//	int hl = interest.getHopLimit().value();
 //        NS_LOG_TEST("hoplimit "<<hl);
//	NS_LOG_TEST(interest.getTag<lp::HopLimitTag>());
//	 NS_LOG_TEST(interest.getName().get(0).toUri());
  if (interest.getTag<lp::HopLimitTag>() == nullptr) {
 //   if(!interest.getHopLimit().has_value()){   
// if(interest.getName().get(0).toUri()=="prefix"){
 // regular interest
  //   NS_LOG_TEST("Should enter processRegularInterest()");
      processRegularInterest(ingress.face, interest, pitEntry);
  }
  else {
    // util Interest
    processUtilInterest(ingress.face, interest, pitEntry);
  }
}

void
ProactiveUtil::afterReceiveNack(const FaceEndpoint& ingress, const lp::Nack& nack,
                                    const shared_ptr<pit::Entry>& pitEntry)
{
 /* 
	if (nack.getReason() == lp::NackReason::OVERLOADED) { // remove FIB entries
         const fib::Entry& fibEntry = this->lookupFib(*pitEntry);
       	 const fib::NextHopList& nexthops = fibEntry.getNextHops();
	 //Face& candidateFace = ingress.face;
	 bool has_candidate = false;
         for (const auto& nexthop : nexthops) {
        	Face& outFace = nexthop.getFace();
		NS_LOG_TEST(" other faces "<< outFace.getId() << " from " << ingress.face.getId() <<" Cost: " << nexthop.getCost()<< "name " << nack.getInterest());
                if( nexthop.getCost()!= 0 && nexthop.getCost()!=100 
				&&  ingress.face.getId()!=outFace.getId()){
          //           has_candidate = true;
	//	     Face& candidateFace = outFace;
		     NS_LOG_TEST("Forwarding Interest to " << outFace.getId());
		     this->sendInterest(pitEntry, FaceEndpoint(outFace, 0), nack.getInterest());
                     //TODO:extend PIT entry lifetime
		     this->setExpiryTimer(pitEntry, 1000_ms);
		     return;
                }else NS_LOG_TEST("not valid outface");	
		
	}
        	if(has_candidate){
		     NS_LOG_TEST("Forwarding Interest to " << candidateFace.getId());
	             this->sendInterest(pitEntry, FaceEndpoint(candidateFace, 0), nack.getInterest());
		}
		else{
		     this->processNack(ingress.face, nack, pitEntry);
		}
        
	}*/
	this->processNack(ingress.face, nack, pitEntry);
	 NS_LOG_TEST(" Nack sent  from " << ingress.face.getId() << "  name " << nack.getInterest());

}

void
ProactiveUtil::broadcastInterest(const Interest& interest, const FaceEndpoint& ingress,
                                        const shared_ptr<pit::Entry>& pitEntry)
{
  const Face& inFace = ingress.face;
  for (auto& outFace : this->getFaceTable() | boost::adaptors::reversed) {
    if ((outFace.getId() == inFace.getId() && outFace.getLinkType() != ndn::nfd::LINK_TYPE_AD_HOC) ||
        wouldViolateScope(inFace, interest, outFace) || outFace.getScope() == ndn::nfd::FACE_SCOPE_LOCAL) {
      continue;
    }
    this->sendInterest(pitEntry,FaceEndpoint(outFace, 0), interest);
    //pitEntry->getOutRecord(outFace)->insertStrategyInfo<OutRecordInfo>().first->isNonDiscoveryInterest = false;
    NFD_LOG_DEBUG("send Util Interest (broadcasted)=" << interest << " from="
                  << inFace.getId() << " to=" << outFace.getId());
  }
}

void
ProactiveUtil::processRegularInterest(const Face& inFace, const Interest& interest,
                                      const shared_ptr<pit::Entry>& pitEntry)
{
// 	const Face& inFace = ingress.face;
     const fib::Entry& fibEntry = this->lookupFib(*pitEntry);
   //  Name serviceName = interest.getName().getSubName(1,2);
   //  fib::Entry* fibEntry = m_forwarder.getFib().findExactMatch(serviceName);
     /* Checking fib */
     for (const auto& nexthop : fibEntry.getNextHops()) {
	Face& outFace = nexthop.getFace();
        uint64_t cost = nexthop.getCost();   
        NS_LOG_TEST(" Regular Interest next hops select: " << fibEntry.getPrefix() <<" to "<< outFace.getId() << " from " << inFace.getId() <<" Cost: " << cost);
       }


     for (const auto& nexthop : fibEntry.getNextHops()) {
             Face& outFace = nexthop.getFace();
             uint64_t cost = nexthop.getCost();
         if(cost<10 && cost>0 && interest.getForwardingHint().empty()){//cost<10 && 
	        continue;
         }
  /*  std::set<std::string>::iterator itr;
    for (itr = utilMap.begin(); itr != utilMap.end(); itr++) {
         NS_LOG_DEBUG("Set elements: " << *itr); 
    }
            for (const auto& x: utilMap){
            NS_LOG_TEST("set element" << x << "  size: " <<  utilMap.size() );
    }

     if(utilMap.find(fibEntry.getPrefix().toUri()+":"+to_string(inFace.getId()))== utilMap.end()){
	     NFD_LOG_TEST("not received util: "<< fibEntry.getPrefix().toUri()+":"+to_string(inFace.getId()) );
	    //    continue;
     }else { NFD_LOG_TEST("this face received util: "<< fibEntry.getPrefix().toUri()+":"+to_string(inFace.getId()) );}*/

     if (!wouldViolateScope(inFace, interest, outFace) &&
        canForwardToLegacy(*pitEntry, outFace)) {
           NFD_LOG_DEBUG("send regular Interest=" << interest << " from="
                     << inFace.getId() << " to=" << outFace.getId() <<" cost=" << cost);
     // NFD_LOG_DEBUG("PIT entry: "<< fibEntry.getPrefix());
      this->sendInterest(pitEntry, FaceEndpoint(outFace, 0), interest);
      return;
    }
  }
}

void
ProactiveUtil::processUtilInterest(const Face& inFace, const Interest& interest,
                                   const shared_ptr<pit::Entry>& pitEntry)
{
   Name interestName = interest.getName();	
   uint32_t newPeriod = std::stoul(interestName.get(1).toUri());
   int newInface = inFace.getId(); 
   uint32_t newCost = std::stoul(interestName.get(-1).toUri());
   uint32_t oldCost = 0;
   NS_LOG_TEST("newInface "<< std::to_string(newInface) << ", newperiod " << std::to_string(newPeriod) << "  interest " << interestName.toUri() ); 
 // const Face& inFace = ingress.face;
  if (interestName.size() <= 1) {
    NFD_LOG_WARN("Util Interest with no services of utilization received");
    return;
  }
  
  for (uint8_t i = 3; i < interestName.size() - 1; i++) {

    Name serviceName = Name("prefix");
    serviceName.append(interestName.get(i).toUri());
   // NS_LOG_TEST("serviceName " << serviceName);
    bool not_internal = false; 
    // already have this service name, check inFace
    fib::Entry* fibEntry = m_forwarder.getFib().findExactMatch(serviceName);
  //  NS_LOG_TEST("fibEntry " << fibEntry->getPrefix());
    int oldpertaskcnt =  pertaskcnt[fibEntry->getPrefix().toUri()];
    int newpertaskcnt =  std::stoi(interestName.get(1).toUri()); 
    NS_LOG_TEST("fibEntry " << fibEntry->getPrefix()  <<" Inface:" <<  std::to_string(newInface)<<" lowestUtil[newInface]:"  << lowestUtil[newInface]  << " name:" << interestName.toUri());
   /* if (fibEntry == nullptr){
	    NS_LOG_TEST("null fibEntry");
	    ns3::Ptr<ns3::Node>  node= ns3::NodeContainer::GetGlobal().Get( ns3::Simulator::GetContext() );
	    ns3::ndn::FibHelper::AddRoute(node, serviceName, inFace.getId(), std::stoi(interestName.get(-1).toUri()));
    } 
    else*/ 
    if(fibEntry->getNextHops().empty()){
      ns3::ndn::FibHelper::AddRoute(m_forwarder.m_node, serviceName, inFace.getId(), std::stoi(interestName.get(-1).toUri()));
      NS_LOG_TEST("New Route added (No nexthop found) for Node " << m_forwarder.m_node << " Service: " << serviceName << " from = " << inFace.getId() << " Cost: " << std::stoi(interestName.get(-1).toUri()) );
    }
    else {
      bool found = false;

 /*	for (const auto& nexthop : fibEntry->getNextHops()) {
        	Face& outFace = nexthop.getFace();
        	NS_LOG_TEST("Before Sorting Check Service: " << serviceName <<" to "<< outFace.getId() << " from " << inFace.getId() <<" Cost: " << fibEntry->findNextHop(outFace)->getCost());
        }*/

 	for (const auto& nexthop : fibEntry->getNextHops()) {
     		Face& outFace = nexthop.getFace();
		if (outFace.getId() == inFace.getId()) {
          		found = true;
          		uint64_t endpointId = nexthop.getEndpointId();
 			if(fibEntry->findNextHop(inFace, endpointId)->getCost()!=0){
				not_internal = true;
			  // if(fibEntry->findNextHop(inFace, endpointId)->getCost()>9 && fibEntry->findNextHop(inFace, endpointId)->getCost()
			//		   <  std::stoul(interestName.get(-1).toUri()) && prevutilcnt >= std::stoi(interestName.get(1).toUri())){
		                if( lowestCost[newInface] == 0 ){
                                    oldCost =   fibEntry->findNextHop(outFace)->getCost();
                                    NS_LOG_TEST("fibEntry->findNextHop(outFace)->getCost() oldcost " << oldCost); 
				}else{ 
				    oldCost = lowestCost[newInface];
				     NS_LOG_TEST("lowestCost[newInface] oldcost " << oldCost);
				}

				if( oldCost>9 && lowestUtil[newInface] == std::stoul(interestName.get(1).toUri()) 
					       && oldCost <  newCost){
	                            
				      NS_LOG_TEST2(fibEntry->findNextHop(outFace)->getCost()); 
         		       	NS_LOG_TEST("oldcost " << fibEntry->findNextHop(outFace)->getCost() << " < newcost " <<  std::stoul(interestName.get(-1).toUri()) << " " 
					<< std::to_string(newCost) << " " <<  std::to_string(lowestUtil[newInface]) << " ==  " << std::stoi(interestName.get(1).toUri()) << " " << interestName.toUri() );
			   }else{
		                //lowestUtil[newPeriod] = newCost;
				 NS_LOG_TEST2("lowestUtil[newInface] before: " << lowestUtil[newInface]);		   
				 lowestUtil[newInface] = newPeriod;
				 lowestCost[newInface] = newCost;
				 NS_LOG_TEST2("lowestUtil[newInface] after: " << lowestUtil[newInface]);
				 fibEntry->findNextHop(inFace, endpointId)->setCost(std::stoi(interestName.get(-1).toUri()));
	               // m_forwarder.getFib().addOrUpdateNextHop(*fibEntry, outFace, std::stoi(interestName.get(-1).toUri()));
	  /*     	if(utilMap.find(serviceName.toUri()+":"+to_string(outFace.getId()))==utilMap.end()){
	         NFD_LOG_TEST("Set Insert: "<< serviceName.toUri()+":"+to_string(outFace.getId()));
                      utilMap.insert(serviceName.toUri()+":"+to_string(outFace.getId()));
		}*/
	 //   bool tbool = utilMap.find(serviceName.toUri()+":"+to_string(outFace.getId()))==utilMap.end();
          //   std::string temp =  utilMap.find(serviceName.toUri()+":"+to_string(outFace.getId()));
	 //    NS_LOG_TEST("Set elements: " << std::string(utilMap.find(serviceName.toUri()+":"+to_string(outFace.getId()))));
		
         ///   fibEntry->findNextHop(inFace)->setCost(std::stoi(interestName.get(-1).toUri()));	
          			NS_LOG_TEST("Not internal face -> update cost: Service: " << interestName <<" from "<< inFace.getId() << " to "<< outFace.getId() << " Cost update: " << fibEntry->findNextHop(inFace)->getCost());
			   }
		       }	
		fibEntry->sortNextHops();
		}else{
  	 	m_iface= inFace.getId(); 
	//	NS_LOG_TEST("Internal face" << m_iface);
        	}

  	}	
        pertaskcnt[fibEntry->getPrefix().toUri()]++;
	if(not_internal){ //not Server
 	for (const auto& nexthop : fibEntry->getNextHops()){
        	Face& outFace = nexthop.getFace();
		NS_LOG_TEST("After Sorting Check Service: " << serviceName <<" to "<< outFace.getId() << " from " << inFace.getId()  << " Updated Cost: " << fibEntry->findNextHop(outFace)->getCost());
        } }
        if (!found)
        {
		 ns3::ndn::FibHelper::AddRoute(m_forwarder.m_node, serviceName, inFace.getId(), std::stoi(interestName.get(-1).toUri()));
          	 NS_LOG_TEST("New Route added for Node " << m_forwarder.m_node << " Service: " << serviceName << " from = " << inFace.getId() << " Cost: " << std::stoi(interestName.get(-1).toUri()) );
        }      
     }
  }
  NS_LOG_TEST("HopLimit: "<<uint64_t(*interest.getTag<lp::HopLimitTag>())<<" for interest: "<< interestName);
  if (uint64_t(*interest.getTag<lp::HopLimitTag>()) == 0) {
    // interest to be discarded
    NFD_LOG_WARN("Util Interest with 0 hop limit. Will be discarded..");
    return;
  }
  NS_LOG_TEST("prev util count: " << std::to_string(prevutilcnt) );
  prevutilcnt =  std::stoi(interestName.get(1).toUri());
  NS_LOG_TEST("prev util count: " << std::to_string(prevutilcnt) );
  NS_LOG_TEST("Interest will be broadcasted " << interest << " from " << inFace.getId());
  broadcastInterest(interest, FaceEndpoint(inFace,0), pitEntry);

}

} // namespace fw
} // namespace nfd
