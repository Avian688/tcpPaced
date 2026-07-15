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

#include "TcpPacedFamily.h"

#include <algorithm>
#include <limits>

namespace inet {
namespace tcp {

// ---

TcpPacedFamily::TcpPacedFamily()
{
}


bool TcpPacedFamily::sendData(bool sendCommandInvoked)
{
    // RFC 2581, pages 7 and 8: "When TCP has not received a segment for
    // more than one retransmission timeout, cwnd is reduced to the value
    // of the restart window (RW) before transmission begins.
    // For the purposes of this standard, we define RW = IW.
    // (...)
    // Using the last time a segment was received to determine whether or
    // not to decrease cwnd fails to deflate cwnd in the common case of
    // persistent HTTP connections [HTH98].
    // (...)
    // Therefore, a TCP SHOULD set cwnd to no more than RW before beginning
    // transmission if the TCP has not sent data in an interval exceeding
    // the retransmission timeout."

    if(state->snd_cwnd < state->snd_mss){
        state->snd_cwnd = state->snd_mss;
    }
    //
    // Send window is effectively the minimum of the congestion window (cwnd)
    // and the advertised window (snd_wnd).
    //
    return dynamic_cast<TcpPacedConnection*>(conn)->sendPendingData();
}

simtime_t TcpPacedFamily::getRexmitTimerExpiry() const
{
    return rexmitTimer != nullptr && rexmitTimer->isScheduled() ? rexmitTimer->getArrivalTime() : SIMTIME_MAX;
}

void TcpPacedFamily::rackLossDetected()
{
    auto pacedConn = dynamic_cast<TcpPacedConnection *>(conn);
    if (!state->sack_enabled)
        return;

    pacedConn->resetTailLossProbe();

    if (!state->lossRecovery) {
        state->recoveryPoint = state->snd_max;
        state->lossRecovery = true;
        pacedConn->updateInFlight();
        setRecoveryCongestionWindow();
    }
    else
        pacedConn->updateInFlight();

    if (pacedConn->doRetransmit())
        restartRexmitTimer();
}

bool TcpPacedFamily::shouldEnterLossRecoveryOnDuplicateAck() const
{
    auto pacedConn = dynamic_cast<TcpPacedConnection *>(conn);
    if (pacedConn->isRackEnabled())
        return false;

    bool dupAckFallback = state->dupacks == state->dupthresh;
    return state->sack_enabled && !state->lossRecovery &&
            (dupAckFallback || pacedConn->isHeadLost());
}

void TcpPacedFamily::setRecoveryCongestionWindow()
{
    auto pacedConn = dynamic_cast<TcpPacedConnection *>(conn);
    uint64_t recoveryCwnd = static_cast<uint64_t>(pacedConn->getBytesInFlight()) +
            std::max(pacedConn->getLastAckedSackedBytes(), state->snd_mss);
    state->snd_cwnd = static_cast<uint32_t>(
            std::min(recoveryCwnd, static_cast<uint64_t>(std::numeric_limits<uint32_t>::max())));
}

void TcpPacedFamily::processRexmitTimer(TcpEventCode &event) {
    const bool recoveryOutstanding = state->sack_enabled &&
            state->recoveryPoint != 0 && seqLess(state->snd_una, state->recoveryPoint);
    applyRtoCongestionResponse = !recoveryOutstanding;

    dynamic_cast<TcpPacedConnection *>(conn)->resetRackTimersForRto();
    TcpTahoeRenoFamily::processRexmitTimer(event);

    dynamic_cast<TcpPacedConnection*>(conn)->updateInFlight();

    if (event == TCP_E_ABORT)
        return;

    // Preserve the RTO recovery boundary so RACK does not apply another
    // congestion response to losses from the same timeout episode.
    if (state->sack_enabled)
        state->recoveryPoint = state->snd_max;

    // After REXMIT timeout TCP Reno should start slow start with snd_cwnd = snd_mss.
    //
    // If calling "retransmitData();" there is no rexmit limitation (bytesToSend > snd_cwnd)
    // therefore "sendData();" has been modified and is called to rexmit outstanding data.
    //
    // RFC 2581, page 5:
    // "Furthermore, upon a timeout cwnd MUST be set to no more than the loss
    // window, LW, which equals 1 full-sized segment (regardless of the
    // value of IW).  Therefore, after retransmitting the dropped segment
    // the TCP sender uses the slow start algorithm to increase the window
    // from 1 full-sized segment to the new value of ssthresh, at which
    // point congestion avoidance again takes over."

    // begin Slow Start (RFC 2581)
    //recalculateSlowStartThreshold();
    //dynamic_cast<BbrConnection*>(conn)->updateInFlight();
}

} // namespace tcp
} // namespace inet
