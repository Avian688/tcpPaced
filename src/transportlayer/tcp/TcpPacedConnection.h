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

#include "flavours/TcpPacedFamily.h"

namespace inet {
namespace tcp {

class TcpPacedConnection : public TcpConnection {
public:
    static simsignal_t throughputSignal;

    TcpPacedConnection();
    virtual ~TcpPacedConnection();
protected:
    virtual bool processAckInEstabEtc(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader) override;

    virtual void initConnection(TcpOpenCommand *openCmd) override;
    virtual void initClonedConnection(TcpConnection *listenerConn) override;
    virtual TcpConnection *cloneListeningConnection() override;

    virtual TcpEventCode process_RCV_SEGMENT(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader, L3Address src, L3Address dest) override;

public:
    virtual bool processTimer(cMessage *msg) override;
    virtual bool sendData(uint32_t congestionWindow) override;
    virtual void changeIntersendingTime(simtime_t _intersendingTime);

    virtual simtime_t getPacingRate();

    virtual void retransmitOneSegment(bool called_at_rto) override;

    virtual bool sendDataDuringLossRecovery(uint32_t congestionWindow);

    virtual void cancelPaceTimer();

    virtual void sendPendingData();

    virtual void retransmitNext(bool timeout);

    virtual void computeThroughput();

    virtual void setPipe() override;

    virtual bool nextSeg(uint32_t& seqNum, bool isRecovery);
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

public:
    cMessage *paceMsg;
    cMessage *throughputTimer;
    simtime_t intersendingTime;
    double throughputInterval;

};

}
}

#endif /* TRANSPORTLAYER_TCP_TCPPACEDCONNECTION_H_ */
