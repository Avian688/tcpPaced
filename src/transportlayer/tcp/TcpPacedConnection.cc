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
namespace inet {
namespace tcp {

Define_Module(TcpPacedConnection);

simsignal_t TcpPacedConnection::throughputSignal = registerSignal("throughput");

TcpPacedConnection::TcpPacedConnection() { // @suppress("Class members should be properly initialized") // @suppress("Class members should be properly initialized") // @suppress("Class members should be properly initialized")
    // TODO Auto-generated constructor stub

}

TcpPacedConnection::~TcpPacedConnection() {
    // TODO Auto-generated destructor stub
    cancelEvent(paceMsg);
    delete paceMsg;
    cancelEvent(throughputTimer);
    delete throughputTimer;
}

void TcpPacedConnection::initConnection(TcpOpenCommand *openCmd)
{
    TcpConnection::initConnection(openCmd);

    throughputInterval = 0;
    paceMsg = new cMessage("pacing message");
    throughputTimer = new cMessage("throughputTimer");
    intersendingTime = 0.0000001;
    paceValueVec.setName("paceValue");
    retransmitOnePacket = false;
    retransmitAfterTimeout = false;
    throughputInterval = 0;
    lastBytesReceived = 0;
    prevLastBytesReceived = 0;
    currThroughput = 0;
    pace = true;

    lastThroughputTime = simTime();
    prevLastThroughputTime = simTime();
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
    intersendingTime = 0.0000001;
    paceValueVec.setName("paceValue");
    pace = false;
    retransmitOnePacket = false;
    retransmitAfterTimeout = false;
    lastBytesReceived = 0;
    prevLastBytesReceived = 0;


    lastThroughputTime = simTime();
    prevLastThroughputTime = simTime();
    scheduleAt(simTime() + throughputInterval, throughputTimer);

    TcpConnection::initClonedConnection(listenerConn);
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
        event = processSegment1stThru8th(tcpSegment, tcpHeader);
    }

    delete tcpSegment;
    return event;
}

bool TcpPacedConnection::processAckInEstabEtc(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader)
{
    EV_DETAIL << "Processing ACK in a data transfer state\n";

    int payloadLength = tcpSegment->getByteLength() - B(tcpHeader->getHeaderLength()).get();

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

            updateWndInfo(tcpHeader);

            tcpAlgorithm->receivedDuplicateAck();
        }
        else {
            // if doesn't qualify as duplicate ACK, just ignore it.
            if (payloadLength == 0) {
                if (state->snd_una != tcpHeader->getAckNo())
                    EV_DETAIL << "Old ACK: ackNo < snd_una\n";
                else if (state->snd_una == state->snd_max)
                    EV_DETAIL << "ACK looks duplicate but we have currently no unacked data (snd_una == snd_max)\n";
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
            // notify
            tcpAlgorithm->receivedDataAck(old_snd_una);
            // in the receivedDataAck we need the old value
            state->dupacks = 0;
            emit(dupAcksSignal, state->dupacks);
            //tcpAlgorithm->restartRexmitTimer();
        }
    }
    else {
        ASSERT(seqGreater(tcpHeader->getAckNo(), state->snd_max)); // from if-ladder

        // send an ACK, drop the segment, and return.
        tcpAlgorithm->receivedAckForDataNotYetSent(tcpHeader->getAckNo());
        state->dupacks = 0;

        emit(dupAcksSignal, state->dupacks);
        sendPendingData();
        return false; // means "drop"
    }
    sendPendingData();
    return true;
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
        //tcpAlgorithm->restartRexmitTimer();
    }
    else // don't measure RTT for retransmitted packets
        tcpAlgorithm->dataSent(old_snd_nxt);

    return true;
}

void TcpPacedConnection::sendPendingData()
{
    if(pace){
        bool dataSent = false;
        if (!paceMsg->isScheduled()){
            if(!retransmitOnePacket){
                if(state->lossRecovery){
                    dataSent = sendDataDuringLossRecovery(dynamic_cast<TcpPacedFamily*>(tcpAlgorithm)->getCwnd());
                    if(!dataSent){
                        dataSent = sendData(dynamic_cast<TcpPacedFamily*>(tcpAlgorithm)->getCwnd());
                    }
                }
                else{
                    dataSent = sendData(dynamic_cast<TcpPacedFamily*>(tcpAlgorithm)->getCwnd());
                }
            }
            else{
                retransmitOneSegment(retransmitAfterTimeout);
                retransmitOnePacket = false;
                retransmitAfterTimeout = false;
                dataSent = false; // We shouldnt pace to retransmissions!
            }

            if(dataSent){
                paceStart = simTime();
                scheduleAfter(intersendingTime, paceMsg);
            }
        }
        else{
            if(retransmitOnePacket){
                retransmitOneSegment(retransmitAfterTimeout);
                retransmitOnePacket = false;
                retransmitAfterTimeout = false;
                dataSent = false; // We shouldnt pace to retransmissions!
            }
        }
    }
    else{
        if(!retransmitOnePacket){
            if(state->lossRecovery){
                sendDataDuringLossRecoveryPhase(dynamic_cast<TcpPacedFamily*>(tcpAlgorithm)->getCwnd());
            }
            else{
                sendData(dynamic_cast<TcpPacedFamily*>(tcpAlgorithm)->getCwnd());
            }
        }
        else{
            retransmitOneSegment(retransmitAfterTimeout);
            retransmitOnePacket = false;
            retransmitAfterTimeout = false;
        }
    }
}

bool TcpPacedConnection::sendDataDuringLossRecovery(uint32_t congestionWindow)
{
    ASSERT(state->sack_enabled && state->lossRecovery);

    // RFC 3517 pages 7 and 8: "(5) In order to take advantage of potential additional available
    // cwnd, proceed to step (C) below.
    // (...)
    // (C) If cwnd - pipe >= 1 SMSS the sender SHOULD transmit one or more
    // segments as follows:
    // (...)
    // (C.5) If cwnd - pipe >= 1 SMSS, return to (C.1)"
    if (((int)congestionWindow - (int)state->pipe) >= (int)state->snd_mss) { // Note: Typecast needed to avoid prohibited transmissions
        // RFC 3517 pages 7 and 8: "(C.1) The scoreboard MUST be queried via NextSeg () for the
        // sequence number range of the next segment to transmit (if any),
        // and the given segment sent.  If NextSeg () returns failure (no
        // data to send) return without sending anything (i.e., terminate
        // steps C.1 -- C.5)."

        uint32_t seqNum;

        if (!nextSeg(seqNum, true)) // if nextSeg() returns false (=failure): terminate steps C.1 -- C.5
            return false;

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
    else{
        return false;
    }
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
//            simtime_t newScheduledTime = paceStart + intersendingTime;
//            if(newScheduledTime >= simTime()){
//                rescheduleAt(newScheduledTime, paceMsg);
//            }
//            else{
////                std::cout << "\n CURRENT SIMTIME: " << simTime() << endl;
////                std::cout << "\n PREV PACING START TIME: " << paceStart << endl;
////                std::cout << "\n PREV INTER SENDING TIME: " << prevIntersendingTime << endl;
////                std::cout << "\n NEW INTER SENDING TIME: " << intersendingTime << endl;
////                std::cout << "\n OLD SCHEDULED TIME: " << paceStart + prevIntersendingTime << endl;
////                std::cout << "\n NEW SCHEDULED TIME: " << paceStart + intersendingTime << endl;
//                rescheduleAt(simTime(), paceMsg);
//            }
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

    if (state && state->ect)
        state->rexmit = false;
}

void TcpPacedConnection::setPipe() {
    ASSERT(state->sack_enabled);
    state->highRxt = rexmitQueue->getHighestRexmittedSeqNum();
    uint32_t currentInFlight = 0;
    uint32_t length = 0; // required for rexmitQueue->checkSackBlock()
    bool sacked; // required for rexmitQueue->checkSackBlock()
    bool rexmitted; // required for rexmitQueue->checkSackBlock()
    auto currIter = rexmitQueue->searchSackBlock(state->snd_una);

    rexmitQueue->updateLost(rexmitQueue->getHighestSackedSeqNum());

    for (uint32_t s1 = state->snd_una; seqLess(s1, state->snd_max); s1 +=
            length) {
        rexmitQueue->checkSackBlockIter(s1, length, sacked, rexmitted, currIter);
        if(length == 0){
            break;
        }
        if (!sacked) {
            //if (isLost(s1) == false){
            const std::tuple<bool, bool> item = rexmitQueue->getLostAndRetransmitted(s1);
            bool isLost = std::get<0>(item);
            bool isRetans = std::get<1>(item);
            if(!isLost || isRetans) {
                currentInFlight += length;
            }
            // RFC 3517, pages 3 and 4: "(b) If S1 <= HighRxt:
            //
            //     Pipe is incremented by 1 octet.
            //
            //     The effect of this condition is that pipe is incremented for
            //     the retransmission of the octet.
            //
            //  Note that octets retransmitted without being considered lost are
            //  counted twice by the above mechanism."
    //            if (seqLess(s1, state->highRxt)){
    //                currentInFlight += length;
    //            }
        }
    }
    state->pipe = currentInFlight;
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

    for (uint32_t s2 = state->highRxt;
         seqLess(s2, state->snd_max) && seqLess(s2, highestSackedSeqNum);
         s2 += shift)
    {
        //rexmitQueue->checkSackBlockIter(s2, shift, sacked, rexmitted, currIter);
        rexmitQueue->checkSackBlock(s2, shift, sacked, rexmitted);

        if (!sacked) {
            //if (isLost(s2)) { // 1.a and 1.b are true, see above "for" statement
            if(rexmitQueue->checkIsLost(s2, highestSackedSeqNum)) {
                //std::cout << "\n HIGHEST SACKED SEQ NUM: " << highestSackedSeqNum << endl;
                //std::cout << "\n FOUND LOST PACKET: " << s2 << endl;
                seqNum = s2;
                return true;
            }
//            else if(seqPerRule3 == 0 && isRecovery)
//            {
//                isSeqPerRule3Valid = true;
//                seqPerRule3 = s2;
//            }

            break; // !isLost(x) --> !isLost(x + d)
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
        for (uint32_t s3 = state->highRxt;
             seqLess(s3, state->snd_max) && seqLess(s3, highestSackedSeqNum);
             s3 += shift)
        {
            //rexmitQueue->checkSackBlockIter(s3, shift, sacked, rexmitted, currIter);
            rexmitQueue->checkSackBlock(s3, shift, sacked, rexmitted);

            if (!sacked) {
                // 1.a and 1.b are true, see above "for" statement
                seqNum = s3;
                return true;
            }
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

void TcpPacedConnection::retransmitNext(bool timeout) {
    retransmitOnePacket = true;
    retransmitAfterTimeout = timeout;
}

void TcpPacedConnection::computeThroughput() {
    EV_TRACE << "Bytes received since last measurement: " << bytesRcvd - lastBytesReceived << "B. Time elapsed since last time measured: " << simTime() - lastThroughputTime << std::endl;
    currThroughput = (bytesRcvd - lastBytesReceived) * 8 / (simTime().dbl() - lastThroughputTime.dbl());
    EV_TRACE << "Throughput computed from application: " << currThroughput << std::endl;
    emit(throughputSignal, currThroughput);
}

simtime_t TcpPacedConnection::getPacingRate() {
    return intersendingTime;
}

void TcpPacedConnection::cancelPaceTimer() {
    cancelEvent(paceMsg);
}

void TcpPacedConnection::enqueueData() {
    Packet *msg = new Packet("Packet");
    const auto & bytes = makeShared<ByteCountChunk>(B(1447));
    msg->insertAtBack(bytes);
    sendQueue->enqueueAppData(msg);
}

}
}
