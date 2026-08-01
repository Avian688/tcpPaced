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
#include <vector>
#include <inet/common/INETUtils.h>
#include <inet/transportlayer/tcp/TcpConnection.h>
#include <inet/networklayer/common/EcnTag_m.h>
#include <inet/transportlayer/common/L4Tools.h>
#include <inet/networklayer/common/DscpTag_m.h>
#include <inet/networklayer/common/HopLimitTag_m.h>
#include <inet/networklayer/common/TosTag_m.h>
#include <inet/networklayer/common/L3AddressTag_m.h>
#include <inet/networklayer/contract/IL3AddressType.h>
#include <inet/transportlayer/tcp/TcpRack.h>
#include "SkbInfo_m.h"

#include "flavours/TcpPacedFamily.h"

namespace inet {
namespace tcp {

class TcpPacedFamily;

class TcpPacedConnection : public TcpConnection {
  protected:
    enum class RackTimerMode {
        NONE,
        REORDERING,
        LOSS_PROBE
    };

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
    static simsignal_t retransmissionRateSignal;

    struct RateSample {
      uint32_t m_deliveryRate;
      bool m_isAppLimited;
      simtime_t m_interval;
      uint32_t m_delivered;
      uint32_t m_priorDelivered;
      simtime_t m_priorTime;
      simtime_t m_sendElapsed;
      simtime_t m_ackElapsed;
      simtime_t m_lastSentTime;
      uint32_t m_bytesLoss;
      uint32_t m_txInFlight;
      uint32_t m_priorInFlight;
      uint32_t m_ackedSacked;
      uint32_t m_lastEndSeq;
      };

    struct LossNotificationSample {
      bool m_valid = false;
      uint32_t m_bytesLoss = 0;
      uint32_t m_txInFlight = 0;
      bool m_isAppLimited = false;
      };

    // Keep detailed samples out of TcpPacedConnection's stored object layout.
    struct DetailedLossNotificationSample {
      bool m_valid = false;
      uint32_t m_lostPacketBytes = 0;
      uint32_t m_bytesLoss = 0;
      uint32_t m_txInFlight = 0;
      bool m_isAppLimited = false;
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

    virtual void beginRateSample();

    virtual void updateSample(uint32_t delivered, uint32_t lost, bool is_sack_reneg, uint32_t priorInFlight, simtime_t minRtt);

    virtual void updateLossNotificationSample();

    virtual void rackAdvance(uint32_t endSeqNo, const Ptr<const TcpHeader>& tcpHeader);

    virtual void calculateAppLimited();

    virtual bool processSACKOption(const Ptr<const TcpHeader>& tcpHeader, const TcpOptionSack& option) override;

    virtual uint32_t sendSegmentDuringLossRecoveryPhase(uint32_t seqNum) override;

public:
    virtual bool processTimer(cMessage *msg) override;

    virtual bool sendData(uint32_t congestionWindow) override;

    virtual uint32_t sendSegment(uint32_t bytes) override;

    virtual void sendOneNewSegment(bool fullSegmentsOnly, uint32_t congestionWindow) override;

    virtual void changeIntersendingTime(simtime_t _intersendingTime);

    virtual simtime_t getPacingRate();

    virtual void setAppLimited(uint32_t deliveredThreshold) { m_appLimited = deliveredThreshold; }

    virtual bool isCwndLimited(uint32_t congestionWindow) const;

    bool wasCwndLimited() const { return m_isCwndLimited; }

    virtual void retransmitOneSegment(bool called_at_rto) override;

    virtual bool sendDataDuringLossRecovery(uint32_t congestionWindow);

    virtual bool doRetransmit();

    virtual void cancelPaceTimer();

    virtual bool sendPendingData();

    virtual void setAllSackedLost();

    virtual void setSackedHeadLost();

    virtual void setSackedHeadLostIfRackDisabled();

    virtual void computeThroughput();

    virtual void computeRetransmissionRate();

    virtual bool nextSeg(uint32_t& seqNum, bool isRecovery);

    virtual bool checkIsLost(uint32_t seqNo);

    virtual bool isHeadLost() const;

    virtual uint32_t getHighestRexmittedSeqNum();

    virtual void skbDelivered(uint32_t seqNum);

    virtual void updateInFlight();

    virtual void setPipe() override {};

    virtual simtime_t getFirstSent() {return m_firstSentTime;};

    virtual simtime_t getDeliveredTime() {return m_deliveredTime;};

    virtual uint32_t getDelivered() {return m_delivered;};

    virtual uint32_t getTxItemDelivered() {return m_txItemDelivered;};

    virtual RateSample getRateSample() {return m_rateSample;};

    virtual LossNotificationSample consumeLossNotificationSample();

    // Protocol connections live in separate dylibs, so this must not add a vtable slot.
    std::vector<DetailedLossNotificationSample> consumeLossNotificationSamples();

    virtual uint32_t getBytesInFlight() {return m_bytesInFlight;};

    virtual uint64_t getTotalDetectedLostBytes() const;

    virtual uint32_t getIsRetransDataAcked() {return isRetransDataAcked;};

    virtual simtime_t getMinRtt() {return connMinRtt;};

    virtual void setMinRtt(simtime_t rtt) { connMinRtt = rtt;};

    virtual uint32_t getLastAckedSackedBytes() {return m_lastAckedSackedBytes;};

    virtual bool isRackEnabled() const { return rack_enabled; }

    virtual bool isRackTimerLossDetection() const { return m_rackTimerLossDetection; }

    virtual void addSkbInfoTags(const Ptr<TcpHeader> &tcpHeader, uint32_t payloadBytes);

    virtual bool checkFackLoss();

    virtual bool checkRackLoss(bool *newLossDetected = nullptr);

    bool checkRackLoss(bool *newLossDetected, bool forceScan);

    virtual void resetTailLossProbe();

    virtual void resetRackTimersForRto();

protected:
    virtual void configureMechanismParameters();

    virtual TcpPacedFamily *getPacedAlgorithm() const;

    virtual void armRackTimer(RackTimerMode mode, simtime_t delay);

    virtual void clearRackTimer(RackTimerMode mode);

    void suspendRtoForRack();

    void releaseRtoAfterRack();

    virtual void scheduleTailLossProbe();

    virtual void sendTailLossProbe();

    virtual bool processTailLossProbeAck(uint32_t ackNo, bool pureDuplicateAck, bool dsackForProbe);

    virtual void clearTailLossProbe(bool cancelProbeTimer);

    virtual bool isInRtoRecovery() const;

    virtual bool shouldApplyRackCongestionResponse() const;

    virtual uint32_t getNewlyDetectedLostBytes(uint64_t previousTotalDetectedLostBytes,
                                               bool lossDetected) const;

    void updateCwndLimitedState(bool isCwndLimited);

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
    uint32_t m_newlySackedBytesForAck = 0;

    uint32_t m_delivered;
    simtime_t m_deliveredTime;
    uint32_t m_rateDelivered;
    simtime_t m_rateInterval;
    simtime_t m_firstSentTime;

    RateSample m_rateSample;
    LossNotificationSample m_lossNotificationSample;
    uint32_t m_bytesInFlight;
    uint32_t m_bytesLoss;

    bool m_isCwndLimited = false;
    uint32_t m_cwndUsageSeq = 0;
    uint32_t m_maxBytesInFlight = 0;

    uint32_t m_appLimited; //NOT NEEDED
    bool m_rateAppLimited; //NOT NEEDED
    uint32_t m_txItemDelivered; //NOT NEEDED

    simtime_t connMinRtt = SIMTIME_MAX;

    //** ADDED FACK, DSACK, RACK VARIABLES **//
    bool fack_enabled;
    bool rack_enabled;
    uint32_t m_sndFack;
    bool m_reorder;
    TcpRack *m_rack;
    bool m_dsackSeen;

    bool isRetransDataAcked;

    RackTimerMode m_rackTimerMode = RackTimerMode::NONE;
    bool m_tlpProbeOutstanding = false;
    bool m_tlpIsRetransmission = false;
    uint32_t m_tlpProbeBeginSeq = 0;
    uint32_t m_tlpEndSeq = 0;
    uint64_t m_rttSampleGeneration = 0;
    uint64_t m_tlpLastProbeRttGeneration = 0;
    bool m_tlpHasSentProbe = false;
    bool m_sackOptionSeenForAck = false;
    bool m_tlpDsackSeenForProbe = false;
    bool m_rackTimerLossDetection = false;

    // Retransmission-rate accounting (count bytes when retransmissions are sent)
    simtime_t lastRetransmissionRateTime;
    uint32_t totalRetransmittedBytesCounter = 0;
    uint32_t lastTotalRetransmittedBytes = 0;
    uint32_t prevLastTotalRetransmittedBytes = 0;
    double currRetransmissionRate = 0;
    bool nextSegSelectedRetransmission = false;

public:
    cMessage *paceMsg;
    cMessage *throughputTimer;
    cMessage *retransmissionRateTimer;
    simtime_t intersendingTime;
    cMessage *rackTimer;
    double throughputInterval;

};

}
}

#endif /* TRANSPORTLAYER_TCP_TCPPACEDCONNECTION_H_ */
