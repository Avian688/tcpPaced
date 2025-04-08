            //
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

#ifndef TRANSPORTLAYER_TCP_TCPPACEDCONNECTION_H_
#define TRANSPORTLAYER_TCP_TCPPACEDCONNECTION_H_

#include <queue>
#include <inet/common/INETUtils.h>
#include <inet/transportlayer/tcp/TcpConnection.h>
#include <inet/networklayer/common/EcnTag_m.h>
#include <inet/transportlayer/common/L4Tools.h>
#include <inet/networklayer/common/DscpTag_m.h>
#include <inet/networklayer/common/HopLimitTag_m.h>
#include <inet/networklayer/common/TosTag_m.h>
#include <inet/networklayer/common/L3AddressTag_m.h>
#include <inet/networklayer/contract/IL3AddressType.h>
#include "SkbInfo_m.h"
#include "flavours/TcpPacedFamily.h"

namespace inet {
namespace tcp {

class TcpPacedConnection : public TcpConnection {
public:
    static simsignal_t throughputSignal;
    static simsignal_t mDeliveredSignal;
    static simsignal_t mFirstSentTimeSignal;
    static simsignal_t mLastSentTimeSignal;
    static simsignal_t msendElapsedSignal;
    static simsignal_t mackElapsedSignal;
    static simsignal_t mbytesInFlightSignal;
    static simsignal_t mbytesInFlightTotalSignal;
    static simsignal_t mbytesLossSignal;
    static simsignal_t paceRateSignal;

    struct RateSample {
      uint32_t m_deliveryRate;
      bool m_isAppLimited;
      simtime_t m_interval;
      uint32_t m_delivered;
      uint32_t m_priorDelivered;
      simtime_t m_priorTime;
      simtime_t m_sendElapsed;
      simtime_t m_ackElapsed;
      uint32_t m_bytesLoss;
      uint32_t m_priorInFlight;
      uint32_t m_ackedSacked;
      };

    TcpPacedConnection();
    virtual ~TcpPacedConnection();
protected:
    virtual bool processAckInEstabEtc(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader) override;

    virtual void initConnection(TcpOpenCommand *openCmd) override;

    virtual void initClonedConnection(TcpConnection *listenerConn) override;

    virtual void configureStateVariables() override;

    virtual TcpConnection *cloneListeningConnection() override;

    virtual TcpEventCode process_RCV_SEGMENT(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader, L3Address src, L3Address dest) override;

    virtual void enqueueData();

    virtual void updateSample(uint32_t delivered, uint32_t lost, bool is_sack_reneg, uint32_t priorInFlight, simtime_t minRtt);

    virtual void calculateAppLimited();

    virtual bool processSACKOption(const Ptr<const TcpHeader>& tcpHeader, const TcpOptionSack& option) override;

public:
    virtual bool processTimer(cMessage *msg) override;

    virtual bool sendData(uint32_t congestionWindow) override;

    virtual uint32_t sendSegment(uint32_t bytes) override;

    virtual void changeIntersendingTime(simtime_t _intersendingTime);

    virtual simtime_t getPacingRate();

    virtual void retransmitOneSegment(bool called_at_rto) override;

    virtual bool sendDataDuringLossRecovery(uint32_t congestionWindow);

    virtual void doRetransmit();

    virtual void cancelPaceTimer();

    virtual void sendPendingData();

    virtual void setAllSackedLost();

    virtual void setSackedHeadLost();

    virtual void computeThroughput();

    virtual bool nextSeg(uint32_t& seqNum, bool isRecovery);

    virtual bool checkIsLost(uint32_t seqNo);

    virtual uint32_t getHighestRexmittedSeqNum();

    virtual void skbDelivered(uint32_t seqNum);

    virtual void updateInFlight();

    virtual void setPipe() override {};

    virtual simtime_t getFirstSent() {return m_firstSentTime;};

    virtual simtime_t getDeliveredTime() {return m_deliveredTime;};

    virtual uint32_t getDelivered() {return m_delivered;};

    virtual uint32_t getTxItemDelivered() {return m_txItemDelivered;};

    virtual RateSample getRateSample() {return m_rateSample;};

    virtual uint32_t getBytesInFlight() {return m_bytesInFlight;};

    virtual simtime_t getMinRtt() {return connMinRtt;};

    virtual void setMinRtt(simtime_t rtt) { connMinRtt = rtt;};

    virtual uint32_t getLastAckedSackedBytes() {return m_lastAckedSackedBytes;};

    virtual void addSkbInfoTags(const Ptr<TcpHeader> &tcpHeader, uint32_t payloadBytes);
protected:
    cOutVector paceValueVec;
    cOutVector bufferedPacketsVec;
    bool pace;
    simtime_t paceStart;
    simtime_t timerDifference;

    bool retransmitOnePacket;
    bool retransmitAfterTimeout;

    simtime_t lastThroughputTime;
    simtime_t prevLastThroughputTime;
    long lastBytesReceived;
    long prevLastBytesReceived;

    long bytesRcvd;

    uint32_t currThroughput;


    uint32_t m_lastAckedSackedBytes;

    uint32_t m_delivered;
    simtime_t m_deliveredTime;
    uint32_t m_rateDelivered;
    simtime_t m_rateInterval;
    simtime_t m_firstSentTime;

    RateSample m_rateSample;
    uint32_t m_bytesInFlight;
    uint32_t m_bytesLoss;

    uint32_t m_appLimited; //NOT NEEDED
    bool m_rateAppLimited; //NOT NEEDED
    uint32_t m_txItemDelivered; //NOT NEEDED

    simtime_t connMinRtt = SIMTIME_MAX;
public:
    cMessage *paceMsg;
    cMessage *throughputTimer;
    simtime_t intersendingTime;
    double throughputInterval;

};

}
}

#endif /* TRANSPORTLAYER_TCP_TCPPACEDCONNECTION_H_ */
