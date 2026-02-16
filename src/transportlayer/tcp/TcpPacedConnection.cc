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


#include "TcpPacedConnection.h"
#include "TcpPaced.h"
#include <algorithm>
#include <inet/transportlayer/tcp/TcpSendQueue.h>
#include <inet/transportlayer/tcp/TcpAlgorithm.h>
#include <inet/transportlayer/tcp/TcpReceiveQueue.h>
#include <inet/transportlayer/tcp/TcpSackRexmitQueue.h>
#include <inet/transportlayer/tcp/TcpRack.h>

namespace inet {
namespace tcp {

Define_Module(TcpPacedConnection);

simsignal_t TcpPacedConnection::throughputSignal = registerSignal("throughput");

simsignal_t TcpPacedConnection::paceRateSignal = registerSignal("paceRate");

simsignal_t TcpPacedConnection::mDeliveredSignal = registerSignal("mDelivered");
simsignal_t TcpPacedConnection::mFirstSentTimeSignal = registerSignal("mFirstSentTime");
simsignal_t TcpPacedConnection::mLastSentTimeSignal = registerSignal("mLastSentTime");
simsignal_t TcpPacedConnection::msendElapsedSignal = registerSignal("msendElapsed");
simsignal_t TcpPacedConnection::mackElapsedSignal = registerSignal("mackElapsed");
simsignal_t TcpPacedConnection::mbytesInFlightSignal = registerSignal("mbytesInFlight");
simsignal_t TcpPacedConnection::mbytesInFlightTotalSignal = registerSignal("mbytesInFlightTotal");
simsignal_t TcpPacedConnection::mbytesLossSignal = registerSignal("mbytesLoss");

TcpPacedConnection::TcpPacedConnection() { // @suppress("Class members should be properly initialized") // @suppress("Class members should be properly initialized") // @suppress("Class members should be properly initialized")
    // TODO Auto-generated constructor stub

}

TcpPacedConnection::~TcpPacedConnection() {
    // TODO Auto-generated destructor stub
    cancelEvent(paceMsg);
    delete paceMsg;
    cancelEvent(throughputTimer);
    delete throughputTimer;
    cancelEvent(rackTimer);
    delete rackTimer;
}

void TcpPacedConnection::initConnection(TcpOpenCommand *openCmd)
{
    TcpConnection::initConnection(openCmd);

    m_delivered = 0;
    throughputInterval = 0;
    paceMsg = new cMessage("pacing message");
    throughputTimer = new cMessage("throughputTimer");
    rackTimer = new cMessage("rackTimer");
    intersendingTime = 0.0000001;
    paceValueVec.setName("paceValue");
    retransmitOnePacket = false;
    retransmitAfterTimeout = false;
    throughputInterval = 0;
    lastBytesReceived = 0;
    prevLastBytesReceived = 0;
    currThroughput = 0;
    pace = true;
    m_appLimited = false;
    m_rateAppLimited = false;
    m_txItemDelivered = 0;

    scoreboardUpdated = false;

    m_bytesInFlight = 0;
    m_bytesLoss = 0;

    lastThroughputTime = simTime();
    prevLastThroughputTime = simTime();

    m_firstSentTime = simTime();
    m_deliveredTime = simTime();

    m_rack = new TcpRack();

    m_rateInterval = 0;
    m_rateDelivered = 0;

    m_lastAckedSackedBytes = 0;
    bytesRcvd = 0;

    m_rateSample.m_ackElapsed = 0;
    m_rateSample.m_ackedSacked = 0;
    m_rateSample.m_bytesLoss = 0;
    m_rateSample.m_delivered = 0;
    m_rateSample.m_deliveryRate = 0;
    m_rateSample.m_interval = 0;
    m_rateSample.m_isAppLimited = false;
    m_rateSample.m_priorDelivered = 0;
    m_rateSample.m_priorInFlight = 0;
    m_rateSample.m_priorTime = 0;
    m_rateSample.m_sendElapsed = 0;

    fack_enabled = true;
    rack_enabled = true;
}

TcpConnection *TcpPacedConnection::cloneListeningConnection()
{
    auto moduleType = cModuleType::get("tcppaced.transportlayer.tcp.TcpPacedConnection");
    int newSocketId = getEnvir()->getUniqueNumber();
    char submoduleName[24];
    sprintf(submoduleName, "conn-%d", newSocketId);
    auto conn = check_and_cast<TcpPacedConnection *>(moduleType->createScheduleInit(submoduleName, tcpMain));
    conn->TcpConnection::initConnection(tcpMain, newSocketId);
    conn->initClonedConnection(this);
    return conn;
}

void TcpPacedConnection::initClonedConnection(TcpConnection *listenerConn)
{
    Enter_Method("initClonedConnection");
    throughputInterval = check_and_cast<TcpPaced*>(tcpMain)->par("throughputInterval");
    paceMsg = new cMessage("pacing message");
    throughputTimer = new cMessage("throughputTimer");
    rackTimer = new cMessage("rackTimer");
    intersendingTime = 0.0000001;
    paceValueVec.setName("paceValue");
    pace = false;
    retransmitOnePacket = false;
    retransmitAfterTimeout = false;
    lastBytesReceived = 0;
    prevLastBytesReceived = 0;
    m_rack = new TcpRack();

    lastThroughputTime = simTime();
    prevLastThroughputTime = simTime();
    scheduleAt(simTime() + throughputInterval, throughputTimer);

    TcpConnection::initClonedConnection(listenerConn);
}

void TcpPacedConnection::configureStateVariables()
{
    state->dupthresh = tcpMain->par("dupthresh");
    long advertisedWindowPar = tcpMain->par("advertisedWindow");
    state->ws_support = tcpMain->par("windowScalingSupport"); // if set, this means that current host supports WS (RFC 1323)
    state->ws_manual_scale = tcpMain->par("windowScalingFactor"); // scaling factor (set manually) to help for Tcp validation
    state->ecnWillingness = tcpMain->par("ecnWillingness"); // if set, current host is willing to use ECN
    if ((!state->ws_support && advertisedWindowPar > TCP_MAX_WIN) || advertisedWindowPar <= 0 || advertisedWindowPar > TCP_MAX_WIN_SCALED)
        throw cRuntimeError("Invalid advertisedWindow parameter: %ld", advertisedWindowPar);

    state->rcv_wnd = advertisedWindowPar;
    state->rcv_adv = advertisedWindowPar;

    if (state->ws_support && advertisedWindowPar > TCP_MAX_WIN) {
        state->rcv_wnd = TCP_MAX_WIN; // we cannot to guarantee that the other end is also supporting the Window Scale (header option) (RFC 1322)
        state->rcv_adv = TCP_MAX_WIN; // therefore TCP_MAX_WIN is used as initial value for rcv_wnd and rcv_adv
    }

    state->maxRcvBuffer = advertisedWindowPar;
    state->delayed_acks_enabled = tcpMain->par("delayedAcksEnabled"); // delayed ACK algorithm (RFC 1122) enabled/disabled
    state->nagle_enabled = tcpMain->par("nagleEnabled"); // Nagle's algorithm (RFC 896) enabled/disabled
    state->limited_transmit_enabled = tcpMain->par("limitedTransmitEnabled"); // Limited Transmit algorithm (RFC 3042) enabled/disabled
    state->increased_IW_enabled = tcpMain->par("increasedIWEnabled"); // Increased Initial Window (RFC 3390) enabled/disabled
    state->snd_mss = tcpMain->par("mss"); // Maximum Segment Size (RFC 793)
    state->ts_support = tcpMain->par("timestampSupport"); // if set, this means that current host supports TS (RFC 1323)
    state->sack_support = tcpMain->par("sackSupport"); // if set, this means that current host supports SACK (RFC 2018, 2883, 3517)

    //Removed congestion control check - not needed
}

bool TcpPacedConnection::processAckInEstabEtc(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader)
{
    EV_DETAIL << "Processing ACK in a data transfer state\n";
    uint64_t previousDelivered = m_delivered;  //RATE SAMPLER SPECIFIC STUFF
    uint32_t previousLost = m_bytesLoss; //TODO Create Sack method to get exact amount of lost packets
    uint32_t priorInFlight = m_bytesInFlight;//get current BytesInFlight somehow
    int payloadLength = tcpSegment->getByteLength() - B(tcpHeader->getHeaderLength()).get();
    //updateInFlight();

    // ECN
    TcpStateVariables *state = getState();
    if (state && state->ect) {
        if (tcpHeader->getEceBit() == true)
            EV_INFO << "Received packet with ECE\n";

        state->gotEce = tcpHeader->getEceBit();
    }

    //
    //"
    //  If SND.UNA < SEG.ACK =< SND.NXT then, set SND.UNA <- SEG.ACK.
    //  Any segments on the retransmission queue which are thereby
    //  entirely acknowledged are removed.  Users should receive
    //  positive acknowledgments for buffers which have been SENT and
    //  fully acknowledged (i.e., SEND buffer should be returned with
    //  "ok" response).  If the ACK is a duplicate
    //  (SEG.ACK < SND.UNA), it can be ignored.  If the ACK acks
    //  something not yet sent (SEG.ACK > SND.NXT) then send an ACK,
    //  drop the segment, and return.
    //
    //  If SND.UNA < SEG.ACK =< SND.NXT, the send window should be
    //  updated.  If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and
    //  SND.WL2 =< SEG.ACK)), set SND.WND <- SEG.WND, set
    //  SND.WL1 <- SEG.SEQ, and set SND.WL2 <- SEG.ACK.
    //
    //  Note that SND.WND is an offset from SND.UNA, that SND.WL1
    //  records the sequence number of the last segment used to update
    //  SND.WND, and that SND.WL2 records the acknowledgment number of
    //  the last segment used to update SND.WND.  The check here
    //  prevents using old segments to update the window.
    //"
    // Note: should use SND.MAX instead of SND.NXT in above checks
    //
    if (seqGE(state->snd_una, tcpHeader->getAckNo())) {
        //
        // duplicate ACK? A received TCP segment is a duplicate ACK if all of
        // the following apply:
        //    (1) snd_una == ackNo
        //    (2) segment contains no data
        //    (3) there's unacked data (snd_una != snd_max)
        //
        // Note: ssfnet uses additional constraint "window is the same as last
        // received (not an update)" -- we don't do that because window updates
        // are ignored anyway if neither seqNo nor ackNo has changed.
        //
        if (state->snd_una == tcpHeader->getAckNo() && payloadLength == 0 && state->snd_una != state->snd_max) {
            state->dupacks++;

            emit(dupAcksSignal, state->dupacks);

            // we need to update send window even if the ACK is a dupACK, because rcv win
            // could have been changed if faulty data receiver is not respecting the "do not shrink window" rule
            if (rack_enabled)
            {
             uint32_t tser = state->ts_recent;
             simtime_t rtt = dynamic_cast<TcpPacedFamily*>(tcpAlgorithm)->getRtt();

             // Get information of the latest packet (cumulatively)ACKed packet and update RACK parameters
             if (!scoreboardUpdated && rexmitQueue->findRegion(tcpHeader->getAckNo()))
             {
                 TcpSackRexmitQueue::Region& skbRegion = rexmitQueue->getRegion(tcpHeader->getAckNo());
                 m_rack->updateStats(tser, skbRegion.rexmitted, skbRegion.m_lastSentTime, tcpHeader->getAckNo(), state->snd_nxt, rtt);
             }
             else // Get information of the latest packet (Selectively)ACKed packet and update RACK parameters
             {
                 uint32_t highestSacked;
                 highestSacked = rexmitQueue->getHighestSackedSeqNum();
                 if(rexmitQueue->findRegion(highestSacked)){
                     TcpSackRexmitQueue::Region& skbRegion = rexmitQueue->getRegion(highestSacked);
                     m_rack->updateStats(tser, skbRegion.rexmitted,  skbRegion.m_lastSentTime, highestSacked, state->snd_nxt, rtt);
                 }
             }

             // Check if TCP will be exiting loss recovery
            bool exiting = false;
            if (state->lossRecovery && dynamic_cast<TcpPacedFamily*>(tcpAlgorithm)->getRecoveryPoint() <= tcpHeader->getAckNo())
            {
                 exiting = true;
            }

            m_rack->updateReoWnd(m_reorder, m_dsackSeen, state->snd_nxt, tcpHeader->getAckNo(), rexmitQueue->getTotalAmountOfSackedBytes(), 3, exiting, state->lossRecovery);
            }
            scoreboardUpdated = false;

            updateWndInfo(tcpHeader);

            std::list<uint32_t> skbDeliveredList = rexmitQueue->getDiscardList(tcpHeader->getAckNo());
            for (uint32_t endSeqNo : skbDeliveredList) {
                skbDelivered(endSeqNo);
            }
//
            uint32_t currentDelivered  = m_delivered - previousDelivered;
            m_lastAckedSackedBytes = currentDelivered;
////
            updateInFlight();
////
            uint32_t currentLost = m_bytesLoss;
            uint32_t lost = (currentLost > previousLost) ? currentLost - previousLost : previousLost - currentLost;
////
            updateSample(currentDelivered, lost, false, priorInFlight, connMinRtt);

            tcpAlgorithm->receivedDuplicateAck();
            isRetransDataAcked = false;
            sendPendingData();

            m_reorder = false;
            //
            // Update m_sndFack if possible
            if (fack_enabled || rack_enabled)
            {
              if (tcpHeader->getAckNo() > m_sndFack)
                {
                  m_sndFack = tcpHeader->getAckNo();
                }
              // Packet reordering seen
              else if (tcpHeader->getAckNo() < m_sndFack)
                {
                  m_reorder = true;
                }
            }
        }
        else {
            // if doesn't qualify as duplicate ACK, just ignore it.
            if (payloadLength == 0) {
                if (state->snd_una != tcpHeader->getAckNo()){
                    EV_DETAIL << "Old ACK: ackNo < snd_una\n";
                }
                else if (state->snd_una == state->snd_max) {
                    EV_DETAIL << "ACK looks duplicate but we have currently no unacked data (snd_una == snd_max)\n";
                }
            }
            // reset counter
            state->dupacks = 0;

            emit(dupAcksSignal, state->dupacks);
        }
    }
    else if (seqLE(tcpHeader->getAckNo(), state->snd_max)) {
        // ack in window.
        uint32_t old_snd_una = state->snd_una;
        state->snd_una = tcpHeader->getAckNo();

        emit(unackedSignal, state->snd_max - state->snd_una);

        // after retransmitting a lost segment, we may get an ack well ahead of snd_nxt
        if (seqLess(state->snd_nxt, state->snd_una))
            state->snd_nxt = state->snd_una;

        // RFC 1323, page 36:
        // "If SND.UNA < SEG.ACK =< SND.NXT then, set SND.UNA <- SEG.ACK.
        // Also compute a new estimate of round-trip time.  If Snd.TS.OK
        // bit is on, use my.TSclock - SEG.TSecr; otherwise use the
        // elapsed time since the first segment in the retransmission
        // queue was sent.  Any segments on the retransmission queue
        // which are thereby entirely acknowledged."
        if (state->ts_enabled)
            tcpAlgorithm->rttMeasurementCompleteUsingTS(getTSecr(tcpHeader));
        // Note: If TS is disabled the RTT measurement is completed in TcpBaseAlg::receivedDataAck()

        uint32_t discardUpToSeq = state->snd_una;
        // our FIN acked?
        if (state->send_fin && tcpHeader->getAckNo() == state->snd_fin_seq + 1) {
            // set flag that our FIN has been acked
            EV_DETAIL << "ACK acks our FIN\n";
            state->fin_ack_rcvd = true;
            discardUpToSeq--; // the FIN sequence number is not real data
        }

        if (rack_enabled)
        {
          uint32_t tser = state->ts_recent;
          simtime_t rtt = dynamic_cast<TcpPacedFamily*>(tcpAlgorithm)->getRtt();

          // Get information of the latest packet (cumulatively)ACKed packet and update RACK parameters
          if (!scoreboardUpdated && rexmitQueue->findRegion(tcpHeader->getAckNo()))
          {
              TcpSackRexmitQueue::Region& skbRegion = rexmitQueue->getRegion(tcpHeader->getAckNo());
              m_rack->updateStats(tser, skbRegion.rexmitted, skbRegion.m_lastSentTime, tcpHeader->getAckNo(), state->snd_nxt, rtt);
          }
          else // Get information of the latest packet (Selectively)ACKed packet and update RACK parameters
          {
              uint32_t highestSacked;
              highestSacked = rexmitQueue->getHighestSackedSeqNum();
              if(rexmitQueue->findRegion(highestSacked)){
                  TcpSackRexmitQueue::Region& skbRegion = rexmitQueue->getRegion(highestSacked);
                  m_rack->updateStats(tser, skbRegion.rexmitted,  skbRegion.m_lastSentTime, highestSacked, state->snd_nxt, rtt);
              }
          }

          // Check if TCP will be exiting loss recovery
          bool exiting = false;
          if (state->lossRecovery && dynamic_cast<TcpPacedFamily*>(tcpAlgorithm)->getRecoveryPoint() <= tcpHeader->getAckNo())
            {
              exiting = true;
            }

          m_rack->updateReoWnd(m_reorder, m_dsackSeen, state->snd_nxt, old_snd_una, rexmitQueue->getTotalAmountOfSackedBytes(), 3, exiting, state->lossRecovery);
        }
        scoreboardUpdated = false;
        // acked data no longer needed in send queue

        // acked data no longer needed in rexmit queue
        std::list<uint32_t> skbDeliveredList = rexmitQueue->getDiscardList(discardUpToSeq);
        for (uint32_t endSeqNo : skbDeliveredList) {
            skbDelivered(endSeqNo);
            if(state->lossRecovery){
                if(rexmitQueue->isRetransmittedDataAcked(endSeqNo)){
                    isRetransDataAcked = true;
                }
            }
        }

        // acked data no longer needed in send queue
        sendQueue->discardUpTo(discardUpToSeq);
        enqueueData();

        // acked data no longer needed in rexmit queue
        if (state->sack_enabled){
            rexmitQueue->discardUpTo(discardUpToSeq);
        }

        updateWndInfo(tcpHeader);

        // if segment contains data, wait until data has been forwarded to app before sending ACK,
        // otherwise we would use an old ACKNo
        if (payloadLength == 0 && fsm.getState() != TCP_S_SYN_RCVD) {

            uint32_t currentDelivered  = m_delivered - previousDelivered;
            m_lastAckedSackedBytes = currentDelivered;

            updateInFlight();

            uint32_t currentLost = m_bytesLoss;
            uint32_t lost = (currentLost > previousLost) ? currentLost - previousLost : previousLost - currentLost;
            // notify

            updateSample(currentDelivered, lost, false, priorInFlight, connMinRtt);

            tcpAlgorithm->receivedDataAck(old_snd_una);
            isRetransDataAcked = false;
            // in the receivedDataAck we need the old value
            state->dupacks = 0;

            sendPendingData();

            m_reorder = false;
            //
            // Update m_sndFack if possible
            if (fack_enabled || rack_enabled)
            {
              if (tcpHeader->getAckNo() > m_sndFack)
                {
                  m_sndFack = tcpHeader->getAckNo();
                }
              // Packet reordering seen
              else if (tcpHeader->getAckNo() < m_sndFack)
                {
                  m_reorder = true;
                }
            }

            emit(dupAcksSignal, state->dupacks);
            emit(mDeliveredSignal, m_delivered);
        }
    }
    else {
        ASSERT(seqGreater(tcpHeader->getAckNo(), state->snd_max)); // from if-ladder

        // send an ACK, drop the segment, and return.
        tcpAlgorithm->receivedAckForDataNotYetSent(tcpHeader->getAckNo());
        state->dupacks = 0;

        emit(dupAcksSignal, state->dupacks);
        return false; // means "drop"
    }
    return true;
}

TcpEventCode TcpPacedConnection::process_RCV_SEGMENT(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader, L3Address src, L3Address dest)
{
    EV_INFO << "Seg arrived: ";
    printSegmentBrief(tcpSegment, tcpHeader);
    EV_DETAIL << "TCB: " << state->str() << "\n";

    emit(rcvSeqSignal, tcpHeader->getSequenceNo());
    emit(rcvAckSignal, tcpHeader->getAckNo());

    emit(tcpRcvPayloadBytesSignal, int(tcpSegment->getByteLength() - B(tcpHeader->getHeaderLength()).get()));
    //
    // Note: this code is organized exactly as RFC 793, section "3.9 Event
    // Processing", subsection "SEGMENT ARRIVES".
    //
    TcpEventCode event;

    if (fsm.getState() == TCP_S_LISTEN) {
        event = processSegmentInListen(tcpSegment, tcpHeader, src, dest);
    }
    else if (fsm.getState() == TCP_S_SYN_SENT) {
        event = processSegmentInSynSent(tcpSegment, tcpHeader, src, dest);
    }
    else {
        // RFC 793 steps "first check sequence number", "second check the RST bit", etc
        bytesRcvd += tcpSegment->getByteLength();
        //this should be sent to main connection??
        event = processSegment1stThru8th(tcpSegment, tcpHeader);
    }

    delete tcpSegment;
    return event;
}

bool TcpPacedConnection::processTimer(cMessage *msg)
{
    printConnBrief();
    EV_DETAIL << msg->getName() << " timer expired\n";

    // first do actions
    TcpEventCode event;

    if (msg == paceMsg) {
        sendPendingData();
    }
    else if(msg == rackTimer) {
        checkRackLoss();
    }
    else if(msg == throughputTimer) {
        EV_TRACE << "Message received at: " << simTime() << std::endl;
        computeThroughput();

        prevLastBytesReceived = lastBytesReceived;
        lastBytesReceived = bytesRcvd;
        prevLastThroughputTime = lastThroughputTime;
        lastThroughputTime = simTime();

        scheduleAt(simTime() + throughputInterval, throughputTimer);
    }
    else if (msg == the2MSLTimer) {
        event = TCP_E_TIMEOUT_2MSL;
        process_TIMEOUT_2MSL();
    }
    else if (msg == connEstabTimer) {
        event = TCP_E_TIMEOUT_CONN_ESTAB;
        process_TIMEOUT_CONN_ESTAB();
    }
    else if (msg == finWait2Timer) {
        event = TCP_E_TIMEOUT_FIN_WAIT_2;
        process_TIMEOUT_FIN_WAIT_2();
    }
    else if (msg == synRexmitTimer) {
        event = TCP_E_IGNORE;
        process_TIMEOUT_SYN_REXMIT(event);
    }
    else {
        event = TCP_E_IGNORE;
        tcpAlgorithm->processTimer(msg, event);
    }

    // then state transitions
    return performStateTransition(event);
}

bool TcpPacedConnection::sendData(uint32_t congestionWindow)
{
    // we'll start sending from snd_max, if not after RTO
    if (!state->afterRto)
        state->snd_nxt = state->snd_max;

    uint32_t old_highRxt = 0;

    if (state->sack_enabled)
        old_highRxt = rexmitQueue->getHighestRexmittedSeqNum();

    // check how many bytes we have
    uint32_t buffered = sendQueue->getBytesAvailable(state->snd_nxt);

    if (buffered == 0)
        return false;

    // maxWindow is minimum of snd_wnd and congestionWindow (snd_cwnd)
    uint32_t maxWindow = std::min(state->snd_wnd, congestionWindow);

    // effectiveWindow: number of bytes we're allowed to send now
    int64_t effectiveWin = (int64_t)maxWindow - (state->snd_nxt - state->snd_una);

    if (effectiveWin <= 0) {
        EV_WARN << "Effective window is zero (advertised window " << state->snd_wnd
                << ", congestion window " << congestionWindow << "), cannot send.\n";
        return false;
    }

    uint32_t bytesToSend = std::min(buffered, (uint32_t)effectiveWin);

    // make a temporary tcp header for detecting tcp options length (copied from 'TcpConnection::sendSegment(uint32_t bytes)' )
    const auto& tmpTcpHeader = makeShared<TcpHeader>();
    tmpTcpHeader->setAckBit(true); // needed for TS option, otherwise TSecr will be set to 0
    writeHeaderOptions(tmpTcpHeader);
    uint options_len = B(tmpTcpHeader->getHeaderLength() - TCP_MIN_HEADER_LENGTH).get();
    ASSERT(options_len < state->snd_mss);
    //uint32_t effectiveMss = state->snd_mss - options_len;
    uint32_t effectiveMss = state->snd_mss;

    uint32_t old_snd_nxt = state->snd_nxt;

    // start sending 'bytesToSend' bytes
    EV_INFO << "May send " << bytesToSend << " bytes (effectiveWindow " << effectiveWin << ", in buffer " << buffered << " bytes)\n";

    if(bytesToSend >= effectiveMss) {
        uint32_t sentBytes = sendSegment(effectiveMss);
        bytesToSend -= sentBytes;
    }

    if (old_snd_nxt == state->snd_nxt)
        return false; // no data sent

    emit(unackedSignal, state->snd_max - state->snd_una);

    // notify (once is enough)
    tcpAlgorithm->ackSent();

    if (state->sack_enabled && state->lossRecovery && old_highRxt != state->highRxt) {
        // Note: Restart of REXMIT timer on retransmission is not part of RFC 2581, however optional in RFC 3517 if sent during recovery.
        EV_DETAIL << "Retransmission sent during recovery, restarting REXMIT timer.\n";
        tcpAlgorithm->restartRexmitTimer();
    }
    else // don't measure RTT for retransmitted packets
        tcpAlgorithm->dataSent(old_snd_nxt);

    return true;
}

uint32_t TcpPacedConnection::sendSegment(uint32_t bytes)
{
    // FIXME check it: where is the right place for the next code (sacked/rexmitted)
    if (state->sack_enabled && state->afterRto) {
        // check rexmitQ and try to forward snd_nxt before sending new data
        uint32_t forward = rexmitQueue->checkRexmitQueueForSackedOrRexmittedSegments(state->snd_nxt);

        if (forward > 0) {
            EV_INFO << "sendSegment(" << bytes << ") forwarded " << forward << " bytes of snd_nxt from " << state->snd_nxt;
            state->snd_nxt += forward;
            EV_INFO << " to " << state->snd_nxt << endl;
            EV_DETAIL << rexmitQueue->detailedInfo();
        }
    }

    uint32_t buffered = sendQueue->getBytesAvailable(state->snd_nxt);

    if (bytes > buffered) // last segment?
        bytes = buffered;

    // if header options will be added, this could reduce the number of data bytes allowed for this segment,
    // because following condition must to be respected:
    //     bytes + options_len <= snd_mss
    const auto& tmpTcpHeader = makeShared<TcpHeader>();
    tmpTcpHeader->setAckBit(true); // needed for TS option, otherwise TSecr will be set to 0
    writeHeaderOptions(tmpTcpHeader);
    //uint options_len = B(tmpTcpHeader->getHeaderLength() - TCP_MIN_HEADER_LENGTH).get();

    //ASSERT(options_len < state->snd_mss);

    //if (bytes + options_len > state->snd_mss)
    //    bytes = state->snd_mss - options_len;
    bytes = state->snd_mss;
    uint32_t sentBytes = bytes;

    // send one segment of 'bytes' bytes from snd_nxt, and advance snd_nxt
    Packet *tcpSegment = sendQueue->createSegmentWithBytes(state->snd_nxt, bytes);
    const auto& tcpHeader = makeShared<TcpHeader>();
    tcpHeader->setSequenceNo(state->snd_nxt);
    ASSERT(tcpHeader != nullptr);

    // Remember old_snd_next to store in SACK rexmit queue.
    uint32_t old_snd_nxt = state->snd_nxt;

    tcpHeader->setAckNo(state->rcv_nxt);
    tcpHeader->setAckBit(true);
    tcpHeader->setWindow(updateRcvWnd());

    // ECN
    if (state->ect && state->sndCwr) {
        tcpHeader->setCwrBit(true);
        EV_INFO << "\nDCTCPInfo - sending TCP segment. Set CWR bit. Setting sndCwr to false\n";
        state->sndCwr = false;
    }

    // TODO when to set PSH bit?
    // TODO set URG bit if needed
    ASSERT(bytes == tcpSegment->getByteLength());

    state->snd_nxt += bytes;

    // check if afterRto bit can be reset
    if (state->afterRto && seqGE(state->snd_nxt, state->snd_max))
        state->afterRto = false;

    if (state->send_fin && state->snd_nxt == state->snd_fin_seq) {
        EV_DETAIL << "Setting FIN on segment\n";
        tcpHeader->setFinBit(true);
        state->snd_nxt = state->snd_fin_seq + 1;
    }

    // if sack_enabled copy region of tcpHeader to rexmitQueue
    if (state->sack_enabled){
        rexmitQueue->enqueueSentData(old_snd_nxt, state->snd_nxt);
        if(pace){
            rexmitQueue->skbSent(state->snd_nxt, m_firstSentTime, simTime(), m_deliveredTime, false, m_delivered, m_appLimited);
        }
    }
    // add header options and update header length (from tcpseg_temp)
    for (uint i = 0; i < tmpTcpHeader->getHeaderOptionArraySize(); i++)
        tcpHeader->appendHeaderOption(tmpTcpHeader->getHeaderOption(i)->dup());
    tcpHeader->setHeaderLength(TCP_MIN_HEADER_LENGTH + tcpHeader->getHeaderOptionArrayLength());
    tcpHeader->setChunkLength(B(tcpHeader->getHeaderLength()));

    ASSERT(tcpHeader->getHeaderLength() == tmpTcpHeader->getHeaderLength());

    // send it

    calculateAppLimited();

    sendToIP(tcpSegment, tcpHeader);

    // let application fill queue again, if there is space
    const uint32_t alreadyQueued = sendQueue->getBytesAvailable(sendQueue->getBufferStartSeq());
    const uint32_t abated = (state->sendQueueLimit > alreadyQueued) ? state->sendQueueLimit - alreadyQueued : 0;
    if ((state->sendQueueLimit > 0) && !state->queueUpdate && (abated >= state->snd_mss)) { // request more data if space >= 1 MSS
        // Tell upper layer readiness to accept more data
        sendIndicationToApp(TCP_I_SEND_MSG, abated);
        state->queueUpdate = true;
    }

    // remember highest seq sent (snd_nxt may be set back on retransmission,
    // but we'll need snd_max to check validity of ACKs -- they must ack
    // something we really sent)
    if (seqGreater(state->snd_nxt, state->snd_max))
        state->snd_max = state->snd_nxt;

    updateInFlight();
    return sentBytes;
}

bool TcpPacedConnection::sendPendingData()
{
    bool dataSent = false;
    if(pace){
        if (!paceMsg->isScheduled()){
            if(state->lossRecovery){
                dataSent = sendDataDuringLossRecovery(dynamic_cast<TcpPacedFamily*>(tcpAlgorithm)->getCwnd());
                //dataSent = sendSegment(dynamic_cast<TcpPacedFamily*>(tcpAlgorithm)->getCwnd());
    //                    if(!dataSent){
    //                        dataSent = sendSegment(dynamic_cast<TcpPacedFamily*>(tcpAlgorithm)->getCwnd());
    //                    }
            }
            else{
                dataSent = sendDataDuringLossRecovery(dynamic_cast<TcpPacedFamily*>(tcpAlgorithm)->getCwnd());
            }
            if(dataSent){
                EV_INFO << "sendPendingData: Data sent! Scheduling pacing timer for " << simTime() + intersendingTime << "\n";
                if(intersendingTime > 0){
                    scheduleAt(simTime() + intersendingTime, paceMsg);
                }
            }
            else{
                EV_INFO << "sendPendingData: no data sent!"  << "\n";
            }
        }
    }
    return dataSent;
}

bool TcpPacedConnection::sendDataDuringLossRecovery(uint32_t congestionWindow)
{
    // RFC 3517 pages 7 and 8: "(5) In order to take advantage of potential additional available
    // cwnd, proceed to step (C) below.
    // (...)
    // (C) If cwnd - pipe >= 1 SMSS the sender SHOULD transmit one or more
    // segments as follows:
    // (...)
    // (C.5) If cwnd - pipe >= 1 SMSS, return to (C.1)"
    uint32_t availableWindow = (state->pipe > congestionWindow) ? 0 : congestionWindow - state->pipe;
    if (availableWindow >= (int)state->snd_mss) { // Note: Typecast needed to avoid prohibited transmissions
        // RFC 3517 pages 7 and 8: "(C.1) The scoreboard MUST be queried via NextSeg () for the
        // sequence number range of the next segment to transmit (if any),
        // and the given segment sent.  If NextSeg () returns failure (no
        // data to send) return without sending anything (i.e., terminate
        // steps C.1 -- C.5)."

        uint32_t seqNum;

        if (!nextSeg(seqNum, state->lossRecovery)){ // if nextSeg() returns false (=failure): terminate steps C.1 -- C.5
            return false;
        }

        uint32_t sentBytes = sendSegmentDuringLossRecoveryPhase(seqNum);

        if(sentBytes > 0){
            return true;
        }
        else{
            return false;
        }
        //m_bytesInFlight += sentBytes;
        // RFC 3517 page 8: "(C.4) The estimate of the amount of data outstanding in the
        // network must be updated by incrementing pipe by the number of
        // octets transmitted in (C.1)."
    }
    return false;
}

bool TcpPacedConnection::doRetransmit()
{
    uint32_t seqNum;
    if(rexmitQueue->isRetransmittedDataAcked(state->snd_una+state->snd_mss)){
        return false;
    }

    if (!nextSeg(seqNum, state->lossRecovery)){ // if nextSeg() returns false (=failure): terminate steps C.1 -- C.5
        return false;
    }

    uint32_t sentBytes = sendSegmentDuringLossRecoveryPhase(seqNum);

    if(sentBytes > 0){
        if(!paceMsg->isScheduled()){
            paceStart = simTime();
            scheduleAt(simTime() + intersendingTime, paceMsg);
        }
        return true;
    }
    return false;
}


void TcpPacedConnection::changeIntersendingTime(simtime_t _intersendingTime)
{
    if(pace){
        ASSERT(_intersendingTime > 0);
        if(_intersendingTime != intersendingTime){
            simtime_t prevIntersendingTime = intersendingTime;
            intersendingTime = _intersendingTime;
            EV_TRACE << "New pace: " << intersendingTime << "s\n";
            paceValueVec.record(intersendingTime);
            emit(paceRateSignal, ((1/intersendingTime)*state->snd_mss)/125000);
        }
    }
}

void TcpPacedConnection::retransmitOneSegment(bool called_at_rto)
{
    // rfc-3168, page 20:
    // ECN-capable TCP implementations MUST NOT set either ECT codepoint
    // (ECT(0) or ECT(1)) in the IP header for retransmitted data packets
    if (state && state->ect)
        state->rexmit = true;

    uint32_t old_snd_nxt = state->snd_nxt;

    // retransmit one segment at snd_una, and set snd_nxt accordingly (if not called at RTO)
    state->snd_nxt = state->snd_una;

    // When FIN sent the snd_max - snd_nxt larger than bytes available in queue
    uint32_t bytes = std::min(std::min(state->snd_mss, state->snd_max - state->snd_nxt),
                sendQueue->getBytesAvailable(state->snd_nxt));

    // FIN (without user data) needs to be resent
    if (bytes == 0 && state->send_fin && state->snd_fin_seq == sendQueue->getBufferEndSeq()) {
        state->snd_max = sendQueue->getBufferEndSeq();
        EV_DETAIL << "No outstanding DATA, resending FIN, advancing snd_nxt over the FIN\n";
        state->snd_nxt = state->snd_max;
        sendFin();
        tcpAlgorithm->segmentRetransmitted(state->snd_nxt, state->snd_nxt + 1);
        state->snd_max = ++state->snd_nxt;

        emit(unackedSignal, state->snd_max - state->snd_una);
    }
    else {
        ASSERT(bytes != 0);
        sendSegment(bytes);
        tcpAlgorithm->segmentRetransmitted(state->snd_una, state->snd_nxt);

        if (!called_at_rto) {
            if (seqGreater(old_snd_nxt, state->snd_nxt))
                state->snd_nxt = old_snd_nxt;
        }

        // notify
        tcpAlgorithm->ackSent();

        if (state->sack_enabled) {
            // RFC 3517, page 7: "(3) Retransmit the first data segment presumed dropped -- the segment
            // starting with sequence number HighACK + 1.  To prevent repeated
            // retransmission of the same data, set HighRxt to the highest
            // sequence number in the retransmitted segment."
            state->highRxt = rexmitQueue->getHighestRexmittedSeqNum();
        }
    }

    //std::cout << "\n AT END OF METHOD IN FLIGHT IS " << state->pipe << endl;

    if (state && state->ect)
        state->rexmit = false;
}

bool TcpPacedConnection::nextSeg(uint32_t& seqNum, bool isRecovery)
{
    ASSERT(state->sack_enabled);

    // RFC 3517, page 5: "This routine uses the scoreboard data structure maintained by the
    // Update() function to determine what to transmit based on the SACK
    // information that has arrived from the data receiver (and hence
    // been marked in the scoreboard).  NextSeg () MUST return the
    // sequence number range of the next segment that is to be
    // transmitted, per the following rules:"


    state->highRxt = rexmitQueue->getHighestRexmittedSeqNum();// not needed?
    uint32_t highestSackedSeqNum = rexmitQueue->getHighestSackedSeqNum();
    uint32_t shift = state->snd_mss;
    bool sacked = false; // required for rexmitQueue->checkSackBlock()
    bool rexmitted = false; // required for rexmitQueue->checkSackBlock()
    bool lost = false; // required for rexmitQueue->checkSackBlock()
    //auto currIter = rexmitQueue->searchSackBlock(state->highRxt);
    seqNum = 0;

//    if (state->ts_enabled){
//        shift -= B(TCP_OPTION_TS_SIZE).get();
//    }
    // RFC 3517, page 5: "(1) If there exists a smallest unSACKed sequence number 'S2' that
    // meets the following three criteria for determining loss, the
    // sequence range of one segment of up to SMSS octets starting
    // with S2 MUST be returned.
    //
    // (1.a) S2 is greater than HighRxt.
    //
    // (1.b) S2 is less than the highest octet covered by any
    //       received SACK.
    //
    // (1.c) IsLost (S2) returns true."

    // Note: state->highRxt == RFC.HighRxt + 1
    uint32_t seqPerRule3 = 0;
    bool isSeqPerRule3Valid = false;

    for (uint32_t s2 = rexmitQueue->getBufferStartSeq();
         seqLess(s2, state->snd_max) && seqLess(s2, highestSackedSeqNum);
         s2 += shift)
    {
        //rexmitQueue->checkSackBlockIter(s2, shift, sacked, rexmitted, currIter);
        rexmitQueue->checkSackBlockLost(s2, shift, sacked, rexmitted, lost);

        //EV_INFO << "checkSackBlockLost: s2: " << s2 << " shift: " << shift << " sacked: " << sacked << " rexmitted: " << rexmitted << " lost: " << lost << "\n";
        if (!sacked) {
            //if (isLost(s2)) { // 1.a and 1.b are true, see above "for" statement
            if(lost && !rexmitted) {
                //std::cout << "\n HIGHEST SACKED SEQ NUM: " << highestSackedSeqNum << endl;
                //std::cout << "\n FOUND LOST PACKET: " << s2 << endl;
                seqNum = s2;
                return true;
            }
            else if(seqPerRule3 == 0 && isRecovery)
            {
                isSeqPerRule3Valid = true;
                seqPerRule3 = s2;
            }

            //break; // !isLost(x) --> !isLost(x + d)
        }
    }

    //rexmitQueue->checkSackBlockIsLost(state->highRxt, state->snd_max, highestSackedSeqNum);
    // RFC 3517, page 5: "(2) If no sequence number 'S2' per rule (1) exists but there
    // exists available unsent data and the receiver's advertised
    // window allows, the sequence range of one segment of up to SMSS
    // octets of previously unsent data starting with sequence number
    // HighData+1 MUST be returned."
    {
        // check how many unsent bytes we have
        uint32_t buffered = sendQueue->getBytesAvailable(state->snd_max);
        uint32_t maxWindow = state->snd_wnd;
        // effectiveWindow: number of bytes we're allowed to send now
        uint32_t effectiveWin = maxWindow - state->pipe;

        if (buffered > 0 && effectiveWin >= state->snd_mss) {
            seqNum = state->snd_max; // HighData = snd_max
            return true;
        }
    }

    // RFC 3517, pages 5 and 6: "(3) If the conditions for rules (1) and (2) fail, but there exists
    // an unSACKed sequence number 'S3' that meets the criteria for
    // detecting loss given in steps (1.a) and (1.b) above
    // (specifically excluding step (1.c)) then one segment of up to
    // SMSS octets starting with S3 MAY be returned.
    //
    // Note that rule (3) is a sort of retransmission "last resort".
    // It allows for retransmission of sequence numbers even when the
    // sender has less certainty a segment has been lost than as with
    // rule (1).  Retransmitting segments via rule (3) will help
    // sustain TCP's ACK clock and therefore can potentially help
    // avoid retransmission timeouts.  However, in sending these
    // segments the sender has two copies of the same data considered
    // to be in the network (and also in the Pipe estimate).  When an
    // ACK or SACK arrives covering this retransmitted segment, the
    // sender cannot be sure exactly how much data left the network
    // (one of the two transmissions of the packet or both
    // transmissions of the packet).  Therefore the sender may
    // underestimate Pipe by considering both segments to have left
    // the network when it is possible that only one of the two has.
    //
    // We believe that the triggering of rule (3) will be rare and
    // that the implications are likely limited to corner cases
    // relative to the entire recovery algorithm.  Therefore we leave
    // the decision of whether or not to use rule (3) to
    // implementors."


    {
        //auto currIter = rexmitQueue->searchSackBlock(state->highRxt);
//        for (uint32_t s3 = state->highRxt;
//             seqLess(s3, state->snd_max) && seqLess(s3, highestSackedSeqNum);
//             s3 += shift)
//        {
//            //rexmitQueue->checkSackBlockIter(s3, shift, sacked, rexmitted, currIter);
//            rexmitQueue->checkSackBlock(s3, shift, sacked, rexmitted);
//
//            if (!sacked) {
//                // 1.a and 1.b are true, see above "for" statement
//                seqNum = s3;
//                return true;
//            }
//        }
        if(isSeqPerRule3Valid)
        {
            std::cout << "\n WEIRD EDGE CASE HAPPENING" << endl;
            seqNum = seqPerRule3;
            return true;
        }
    }


//    if(isSeqPerRule3Valid)
//    {
//        seqNum = seqPerRule3;
//        return true;
//    }
    // RFC 3517, page 6: "(4) If the conditions for each of (1), (2), and (3) are not met,
    // then NextSeg () MUST indicate failure, and no segment is
    // returned."
    seqNum = 0;

    return false;
}

void TcpPacedConnection::computeThroughput()
{
    EV_TRACE << "Bytes received since last measurement: " << bytesRcvd - lastBytesReceived << "B. Time elapsed since last time measured: " << simTime() - lastThroughputTime << std::endl;
    currThroughput = (bytesRcvd - lastBytesReceived) * 8 / (simTime().dbl() - lastThroughputTime.dbl());
    EV_TRACE << "Throughput computed from application: " << currThroughput << std::endl;
    emit(throughputSignal, currThroughput);
}

simtime_t TcpPacedConnection::getPacingRate()
{
    return intersendingTime;
}

void TcpPacedConnection::cancelPaceTimer() {
    cancelEvent(paceMsg);
}

void TcpPacedConnection::enqueueData()
{
    if(sendQueue->getBufferEndSeq() - sendQueue->getBufferStartSeq() < (2000000000)){
        Packet *msg = new Packet("Packet");
        const uint32_t packetSize = (2000000000 - (sendQueue->getBufferEndSeq() - sendQueue->getBufferStartSeq()));
        Ptr<Chunk> bytes = makeShared<ByteCountChunk>(B(packetSize));
        msg->insertAtBack(bytes);
        sendQueue->enqueueAppData(msg);
    }
}

void TcpPacedConnection::setSackedHeadLost()
{
    if(!rexmitQueue->checkHeadIsLost()){
        rexmitQueue->markHeadAsLost();
    }
}

void TcpPacedConnection::setAllSackedLost()
{
    // From RFC 6675, Section 5.1
   // [RFC2018] suggests that a TCP sender SHOULD expunge the SACK
   // information gathered from a receiver upon a retransmission timeout
   // (RTO) "since the timeout might indicate that the data receiver has
   // reneged."  Additionally, a TCP sender MUST "ignore prior SACK
   // information in determining which data to retransmit."
   // It has been suggested that, as long as robust tests for
   // reneging are present, an implementation can retain and use SACK
   // information across a timeout event [Errata1610].
   // The head of the sent list will not be marked as sacked, therefore
   // will be retransmitted, if the receiver renegotiate the SACK blocks
   // that we received.

    rexmitQueue->setAllLost();
    state->highRxt = rexmitQueue->getHighestRexmittedSeqNum();
}

bool TcpPacedConnection::checkIsLost(uint32_t seqNo)
{
    return rexmitQueue->checkIsLost(seqNo, rexmitQueue->getHighestSackedSeqNum());
}

uint32_t TcpPacedConnection::getHighestRexmittedSeqNum(){
    return rexmitQueue->getHighestRexmittedSeqNum();
}

void TcpPacedConnection::skbDelivered(uint32_t seqNum)
{
    if(rexmitQueue->findRegion(seqNum)){
        TcpSackRexmitQueue::Region& skbRegion = rexmitQueue->getRegion(seqNum);
        if(skbRegion.m_deliveredTime != SIMTIME_MAX){
            m_delivered += skbRegion.endSeqNum - skbRegion.beginSeqNum;
            if((skbRegion.endSeqNum - skbRegion.beginSeqNum) != 1448){
                std::cout << "\n AMOUNT DELIVERED" << skbRegion.endSeqNum - skbRegion.beginSeqNum << endl;
            }
            m_deliveredTime = simTime();

            if (m_rateSample.m_priorDelivered == 0 || skbRegion.m_delivered > m_rateSample.m_priorDelivered)
            {
                m_rateSample.m_ackElapsed = simTime() - skbRegion.m_deliveredTime;
                m_rateSample.m_priorDelivered = skbRegion.m_delivered;
                m_rateSample.m_priorTime = skbRegion.m_deliveredTime;
                m_rateSample.m_isAppLimited = skbRegion.m_isAppLimited;
                m_rateSample.m_sendElapsed = skbRegion.m_lastSentTime - skbRegion.m_firstSentTime;

                m_firstSentTime = skbRegion.m_lastSentTime;

                emit(msendElapsedSignal, m_rateSample.m_sendElapsed);
                emit(mackElapsedSignal, m_rateSample.m_ackElapsed);
                emit(mFirstSentTimeSignal, skbRegion.m_firstSentTime);
                emit(mLastSentTimeSignal, skbRegion.m_lastSentTime);
            }

            skbRegion.m_deliveredTime = SIMTIME_MAX;
            m_txItemDelivered = skbRegion.m_delivered;
        }
    }
    else{
        std::cout << "\n SKB NOT FOUND" << endl;
        EV_DETAIL << "\n SkbDelivered cant find segment!: " << seqNum << endl;
        EV_DETAIL << rexmitQueue->str() << endl;
    }
}

void TcpPacedConnection::updateInFlight() {
    ASSERT(state->sack_enabled);

    state->highRxt = rexmitQueue->getHighestRexmittedSeqNum();
    uint32_t currentInFlight = 0;
    uint32_t bytesLoss = 0;
    uint32_t length = 0; // required for rexmitQueue->checkSackBlock()
    bool sacked; // required for rexmitQueue->checkSackBlock()
    bool rexmitted; // required for rexmitQueue->checkSackBlock()

    m_bytesInFlight = rexmitQueue->getInFlight();
    m_bytesLoss = rexmitQueue->getLost();
    state->pipe = m_bytesInFlight;

    emit(mbytesInFlightSignal, m_bytesInFlight);
    emit(mbytesLossSignal, m_bytesLoss);
}

void TcpPacedConnection::updateSample(uint32_t delivered, uint32_t lost, bool is_sack_reneg, uint32_t priorInFlight, simtime_t minRtt) //GenerateSample in ns3 rate sampler
{
    if(m_appLimited != 0 && m_delivered > m_appLimited){ //NOT NEEDED
        m_appLimited = 0;
    }

    m_rateSample.m_ackedSacked = delivered; /* freshly ACKed or SACKed */
    m_rateSample.m_bytesLoss = lost;        /* freshly marked lost */
    m_rateSample.m_priorInFlight = priorInFlight;

    /* Return an invalid sample if no timing information is available or
     * in recovery from loss with SACK reneging. Rate samples taken during
     * a SACK reneging event may overestimate bw by including packets that
     * were SACKed before the reneg.
     */
    if (m_rateSample.m_priorTime == 0 || is_sack_reneg) {
        m_rateSample.m_delivered = -1;
        m_rateSample.m_interval = 0;
        return;
    }

    // LINUX:
    //  /* Model sending data and receiving ACKs as separate pipeline phases
    //   * for a window. Usually the ACK phase is longer, but with ACK
    //   * compression the send phase can be longer. To be safe we use the
    //   * longer phase.
    //   */
    //  auto snd_us = m_rateSample.m_interval;  /* send phase */
    //  auto ack_us = Simulator::Now () - m_rateSample.m_prior_mstamp;
    //  m_rateSample.m_interval = std::max (snd_us, ack_us);
    //m_rateSample.m_ackElapsed = simTime() - m_rateSample.m_priorTime;
    m_rateSample.m_interval = std::max(m_rateSample.m_sendElapsed, m_rateSample.m_ackElapsed);
    m_rateSample.m_delivered = m_delivered - m_rateSample.m_priorDelivered;

    /* Normally we expect m_interval >= minRtt.
     * Note that rate may still be over-estimated when a spuriously
     * retransmitted skb was first (s)acked because "interval_us"
     * is under-estimated (up to an RTT). However continuously
     * measuring the delivery rate during loss recovery is crucial
     * for connections suffer heavy or prolonged losses.
     */
    if(m_rateSample.m_interval < minRtt) {
        m_rateSample.m_interval = 0;
        m_rateSample.m_priorTime = 0; // To make rate sample invalid
        return;
    }

    /* Record the last non-app-limited or the highest app-limited bw */
    if (!m_rateSample.m_isAppLimited || (m_rateSample.m_delivered * m_rateInterval >= m_rateDelivered * m_rateSample.m_interval)) {
        m_rateDelivered = m_rateSample.m_delivered;
        m_rateInterval = m_rateSample.m_interval;
        m_rateAppLimited = m_rateSample.m_isAppLimited;
        m_rateSample.m_deliveryRate = m_rateSample.m_delivered / m_rateSample.m_interval;
    }
}

bool TcpPacedConnection::processSACKOption(const Ptr<const TcpHeader>& tcpHeader, const TcpOptionSack& option)
{
    if (option.getLength() % 8 != 2) {
        EV_ERROR << "ERROR: option length incorrect\n";
        return false;
    }

    uint n = option.getSackItemArraySize();
    ASSERT(option.getLength() == 2 + n * 8);

    if (!state->sack_enabled) {
        EV_ERROR << "ERROR: " << n << " SACK(s) received, but sack_enabled is set to false\n";
        return false;
    }

    if (fsm.getState() != TCP_S_SYN_RCVD && fsm.getState() != TCP_S_ESTABLISHED
        && fsm.getState() != TCP_S_FIN_WAIT_1 && fsm.getState() != TCP_S_FIN_WAIT_2)
    {
        EV_ERROR << "ERROR: Tcp Header Option SACK received, but in unexpected state\n";
        return false;
    }

    if (n > 0) { // sacks present?
        EV_INFO << n << " SACK(s) received:\n";
        for (uint i = 0; i < n; i++) {
            Sack tmp;
            tmp.setStart(option.getSackItem(i).getStart());
            tmp.setEnd(option.getSackItem(i).getEnd());

            EV_INFO << (i + 1) << ". SACK: " << tmp.str() << endl;

            // check for D-SACK
            if (i == 0 && seqLE(tmp.getEnd(), tcpHeader->getAckNo())) {
                // RFC 2883, page 8:
                // "In order for the sender to check that the first (D)SACK block of an
                // acknowledgement in fact acknowledges duplicate data, the sender
                // should compare the sequence space in the first SACK block to the
                // cumulative ACK which is carried IN THE SAME PACKET.  If the SACK
                // sequence space is less than this cumulative ACK, it is an indication
                // that the segment identified by the SACK block has been received more
                // than once by the receiver.  An implementation MUST NOT compare the
                // sequence space in the SACK block to the TCP state variable snd.una
                // (which carries the total cumulative ACK), as this may result in the
                // wrong conclusion if ACK packets are reordered."
                if(rack_enabled){
                    m_dsackSeen = true;
                    if(rexmitQueue->isRetransmitted(tmp.getEnd())){
                        m_reorder = true;
                    }
                }
                EV_DETAIL << "Received D-SACK below cumulative ACK=" << tcpHeader->getAckNo()
                          << " D-SACK: " << tmp.str() << endl;
                // Note: RFC 2883 does not specify what should be done in this case.
                // RFC 2883, page 9:
                // "5. Detection of Duplicate Packets
                // (...) This document does not specify what action a TCP implementation should
                // take in these cases. The extension to the SACK option simply enables
                // the sender to detect each of these cases.(...)"
            }
            else if (i == 0 && n > 1 && seqGreater(tmp.getEnd(), tcpHeader->getAckNo())) {
                m_dsackSeen = false;
                // RFC 2883, page 8:
                // "If the sequence space in the first SACK block is greater than the
                // cumulative ACK, then the sender next compares the sequence space in
                // the first SACK block with the sequence space in the second SACK
                // block, if there is one.  This comparison can determine if the first
                // SACK block is reporting duplicate data that lies above the cumulative
                // ACK."
                Sack tmp2(option.getSackItem(1).getStart(), option.getSackItem(1).getEnd());

                if (tmp2.contains(tmp)) {
                    EV_DETAIL << "Received D-SACK above cumulative ACK=" << tcpHeader->getAckNo()
                              << " D-SACK: " << tmp.str()
                              << ", SACK: " << tmp2.str() << endl;
                    // Note: RFC 2883 does not specify what should be done in this case.
                    // RFC 2883, page 9:
                    // "5. Detection of Duplicate Packets
                    // (...) This document does not specify what action a TCP implementation should
                    // take in these cases. The extension to the SACK option simply enables
                    // the sender to detect each of these cases.(...)"
                }
            }

            if (seqGreater(tmp.getEnd(), tcpHeader->getAckNo()) && seqGreater(tmp.getEnd(), state->snd_una)){
                //rexmitQueue->setSackedBit(tmp.getStart(), tmp.getEnd());
                //rexmitQueue->setSackedBit(tmp.getStart(), tmp.getEnd());
                //std::cout << "\n SACKING: " << tmp.getEnd() - tmp.getStart() << " BYTES" << endl;
//                rexmitQueue->setSackedBit(tmp.getStart(), tmp.getEnd());
//                for (uint32_t seqNo = tmp.getStart()+state->snd_mss; seqNo <= tmp.getEnd(); seqNo += state->snd_mss) {
//                    skbDelivered(seqNo);
//                }
                std::list<uint32_t> skbDeliveredList = rexmitQueue->setSackedBitList(tmp.getStart(), tmp.getEnd());
                scoreboardUpdated = true;
                for (uint32_t endSeqNo : skbDeliveredList) {
                        if(fack_enabled || rack_enabled){
                            if(endSeqNo > m_sndFack){
                                m_sndFack = endSeqNo;
                            }
                            else{
                                m_reorder = true;
                            }
                        }
                        skbDelivered(endSeqNo);
                }
            }
            else
                EV_DETAIL << "Received SACK below total cumulative ACK snd_una=" << state->snd_una << "\n";

//            if (seqGreater(tmp.getEnd(), tcpHeader->getAckNo()) && seqGreater(tmp.getEnd(), state->snd_una){
//                std::list<uint32_t> skbDeliveredList = rexmitQueue->setSackedBitList(tmp.getStart(), tmp.getEnd());
//            }
//
//            for (uint32_t endSeqNo : skbDeliveredList) {
//                    skbDelivered(endSeqNo);
//            }
//            for (uint32_t seqNo = tmp.getStart()+state->snd_mss; seqNo <= tmp.getEnd(); seqNo += state->snd_mss) {
//               skbDelivered(seqNo);
//            }

        }

        if(rexmitQueue->updateLost(rexmitQueue->getHighestSackedSeqNum())){
            dynamic_cast<TcpPacedFamily*>(tcpAlgorithm)->notifyLost();
        }
        state->rcv_sacks += n; // total counter, no current number

        emit(rcvSacksSignal, state->rcv_sacks);

        // update scoreboard
        state->sackedBytes_old = state->sackedBytes; // needed for RFC 3042 to check if last dupAck contained new sack information
        state->sackedBytes = rexmitQueue->getTotalAmountOfSackedBytes();

        emit(sackedBytesSignal, state->sackedBytes);
    }
    return true;
}

void TcpPacedConnection::calculateAppLimited()
{
    m_appLimited = 0;
}

void TcpPacedConnection::addSkbInfoTags(const Ptr<TcpHeader> &tcpHeader, uint32_t payloadBytes)
{
    tcpHeader->addTagIfAbsent<SkbInfo>()->setFirstSent(m_firstSentTime);
    tcpHeader->addTagIfAbsent<SkbInfo>()->setLastSent(simTime());
    tcpHeader->addTagIfAbsent<SkbInfo>()->setDeliveredTime(m_deliveredTime);
    tcpHeader->addTagIfAbsent<SkbInfo>()->setDelivered(m_delivered);
    tcpHeader->addTagIfAbsent<SkbInfo>()->setPayloadBytes(payloadBytes);
}

bool TcpPacedConnection::checkFackLoss()
{
    if(fack_enabled){
        uint32_t fack_diff = std::max((uint32_t)0, (m_sndFack - rexmitQueue->getBufferStartSeq()));
        return fack_diff > state->snd_mss * 3;
    }
    else{
        return false;
    }

}

bool TcpPacedConnection::checkRackLoss()
{
    double timeout = 0.0;
    bool enterRecovery = false;
    if(rexmitQueue->checkRackLoss(m_rack, timeout)){
        dynamic_cast<TcpPacedFamily*>(tcpAlgorithm)->notifyLost();
    }

    if (rexmitQueue->getLost() != 0 && !state->lossRecovery)
    {
        enterRecovery = true;
    }

    if (timeout > 0)
    {
        if((simTime() + timeout) > simTime()){
            rescheduleAt(simTime() + timeout, rackTimer); //TODO Cancel old timer if new timeout is shorter
        }
        tcpAlgorithm->restartRexmitTimer();

    }
    return enterRecovery;

}

uint32_t TcpPacedConnection::getTotalRetransmitted()
{
 return rexmitQueue->getTotalRetransmitted();
}

}
}
