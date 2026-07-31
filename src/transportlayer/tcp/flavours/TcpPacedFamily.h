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

#ifndef INET_TRANSPORTLAYER_TCP_FLAVOURS_TCPPACEDFAMILY_H_
#define INET_TRANSPORTLAYER_TCP_FLAVOURS_TCPPACEDFAMILY_H_

#include <cstdint>

#include "../TcpPacedConnection.h"
#include "inet/transportlayer/tcp/flavours/TcpTahoeRenoFamily.h"

namespace inet {
namespace tcp {
/**
 * Provides utility functions to implement TcpPacedFamily.
 */
class TcpPacedFamily : public TcpTahoeRenoFamily
{
  protected:
    bool prrActive = false;
    uint64_t prrDeliveredPackets = 0;
    uint64_t prrOutPackets = 0;
    uint64_t prrPriorCwndPackets = 0;

    // Loss-based algorithms opt in; model-based algorithms keep their own recovery control.
    virtual bool usesPrrRecovery() const { return false; }
    virtual uint64_t packetsForBytes(uint64_t bytes) const;
    virtual void beginPrrRecovery();
    virtual void resetPrrRecovery();
    virtual void updatePrrCongestionWindow(uint32_t newlyDeliveredBytes,
                                           bool sndUnaAdvanced,
                                           uint32_t newlyLostBytes);

  public:
    /** Ctor */
    TcpPacedFamily();

    virtual void initialize() override;

    virtual void established(bool active) override;

    virtual bool sendData(bool sendCommandInvoked) override;

    virtual uint32_t getCwnd() { return state->snd_cwnd;};

    virtual uint32_t getRecoveryPoint() { return state->recoveryPoint;};

    virtual simtime_t getRtt() { return state->srtt;};

    virtual uint32_t getSsthresh() { return state->ssthresh;};

    virtual bool isRexmitTimer(const cMessage *msg) const { return msg == rexmitTimer; }

    virtual simtime_t getRexmitTimerExpiry() const;

    // Recovery retransmissions must not postpone an RTO already in progress.
    void preserveRexmitTimerExpiry(simtime_t expiry);

    // Congestion-control flavours live in separate dylibs; keep these out of the vtable.
    simtime_t getRexmitTimeout() const { return state->rexmit_timeout; }

    virtual bool shouldApplyRtoCongestionResponse() const { return applyRtoCongestionResponse; }

    virtual void notifyLost(){};

    virtual void rackLossDetected();

    virtual void recoveryDataSent(uint32_t bytes);

  protected:
    bool applyRtoCongestionResponse = true;

    virtual bool shouldEnterLossRecoveryOnDuplicateAck() const;
    virtual void setRecoveryCongestionWindow();

    virtual void processRexmitTimer(TcpEventCode& event) override;
};

} // namespace tcp
} // namespace inet

#endif
