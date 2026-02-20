//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
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
simsignal_t TcpPacedConnection::retransmissionRateSignal = registerSignal("retransmissionRate");
simsignal_t TcpPacedConnection::paceRateSignal = registerSignal("paceRate");

simsignal_t TcpPacedConnection::mDeliveredSignal = registerSignal("mDelivered");
simsignal_t TcpPacedConnection::mFirstSentTimeSignal = registerSignal("mFirstSentTime");
simsignal_t TcpPacedConnection::mLastSentTimeSignal = registerSignal("mLastSentTime");
simsignal_t TcpPacedConnection::msendElapsedSignal = registerSignal("msendElapsed");
simsignal_t TcpPacedConnection::mackElapsedSignal = registerSignal("mackElapsed");
simsignal_t TcpPacedConnection::mbytesInFlightSignal = registerSignal("mbytesInFlight");
simsignal_t TcpPacedConnection::mbytesInFlightTotalSignal = registerSignal("mbytesInFlightTotal");
simsignal_t TcpPacedConnection::mbytesLossSignal = registerSignal("mbytesLoss");

// local helper for sender-side retransmission rate (separate timer from receiver throughput timer)

TcpPacedConnection::TcpPacedConnection()
{
}

TcpPacedConnection::~TcpPacedConnection()
{
    cancelEvent(paceMsg);
    delete paceMsg;
    cancelEvent(throughputTimer);
    delete throughputTimer;
    cancelEvent(rackTimer);
    delete rackTimer;

    cancelEvent(retransmissionRateTimer);
    delete retransmissionRateTimer;
}

void TcpPacedConnection::initConnection(TcpOpenCommand *openCmd)
{
    TcpConnection::initConnection(openCmd);

    m_delivered = 0;
    paceMsg = new cMessage("pacing message");
    throughputTimer = new cMessage("throughputTimer");
    rackTimer = new cMessage("rackTimer");
    retransmissionRateTimer = new cMessage("retransmissionRateTimer"); // NEW
    intersendingTime = 0.0000001;
    paceValueVec.setName("paceValue");
    retransmitOnePacket = false;
    retransmitAfterTimeout = false;
    throughputInterval = check_and_cast<TcpPaced*>(tcpMain)->par("throughputInterval");
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

    // sender-side retransmission accounting
    prevLastTotalRetransmittedBytes = 0;
    lastTotalRetransmittedBytes = 0;
    totalRetransmittedBytesCounter = 0;
    currRetransmissionRate = 0;
    nextSegSelectedRetransmission = false;
    lastRetransmissionRateTime = simTime();
    scheduleAt(throughputInterval, retransmissionRateTimer);
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
    retransmissionRateTimer = new cMessage("retransmissionRateTimer"); // NEW
    intersendingTime = 0.0000001;
    paceValueVec.setName("paceValue");
    pace = false;
    retransmitOnePacket = false;
    retransmitAfterTimeout = false;
    lastBytesReceived = 0;
    prevLastBytesReceived = 0;
    m_rack = new TcpRack();

    // sender-side retransmission accounting
    prevLastTotalRetransmittedBytes = 0;
    lastTotalRetransmittedBytes = 0;
    totalRetransmittedBytesCounter = 0;
    currRetransmissionRate = 0;
    nextSegSelectedRetransmission = false;
    lastRetransmissionRateTime = simTime();

    lastThroughputTime = simTime();
    prevLastThroughputTime = simTime();

    // Keep separate timers: throughput (receiver-side bytesRcvd) and retransmissionRate (sender-side send counting)
    scheduleAt(simTime() + throughputInterval, throughputTimer);

    TcpConnection::initClonedConnection(listenerConn);
}

void TcpPacedConnection::configureStateVariables()
{
    state->dupthresh = tcpMain->par("dupthresh");
    long advertisedWindowPar = tcpMain->par("advertisedWindow");
    state->ws_support = tcpMain->par("windowScalingSupport");
    state->ws_manual_scale = tcpMain->par("windowScalingFactor");
    state->ecnWillingness = tcpMain->par("ecnWillingness");
    if ((!state->ws_support && advertisedWindowPar > TCP_MAX_WIN) || advertisedWindowPar <= 0 || advertisedWindowPar > TCP_MAX_WIN_SCALED)
        throw cRuntimeError("Invalid advertisedWindow parameter: %ld", advertisedWindowPar);

    state->rcv_wnd = advertisedWindowPar;
    state->rcv_adv = advertisedWindowPar;

    if (state->ws_support && advertisedWindowPar > TCP_MAX_WIN) {
        state->rcv_wnd = TCP_MAX_WIN;
        state->rcv_adv = TCP_MAX_WIN;
    }

    state->maxRcvBuffer = advertisedWindowPar;
    state->delayed_acks_enabled = tcpMain->par("delayedAcksEnabled");
    state->nagle_enabled = tcpMain->par("nagleEnabled");
    state->limited_transmit_enabled = tcpMain->par("limitedTransmitEnabled");
    state->increased_IW_enabled = tcpMain->par("increasedIWEnabled");
    state->snd_mss = tcpMain->par("mss");
    state->ts_support = tcpMain->par("timestampSupport");
    state->sack_support = tcpMain->par("sackSupport");
}

bool TcpPacedConnection::processAckInEstabEtc(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader)
{
    EV_DETAIL << "Processing ACK in a data transfer state\n";
    uint64_t previousDelivered = m_delivered;
    uint32_t previousLost = m_bytesLoss;
    uint32_t priorInFlight = m_bytesInFlight;
    int payloadLength = tcpSegment->getByteLength() - B(tcpHeader->getHeaderLength()).get();

    TcpStateVariables *state = getState();
    if (state && state->ect) {
        if (tcpHeader->getEceBit() == true)
            EV_INFO << "Received packet with ECE\n";
        state->gotEce = tcpHeader->getEceBit();
    }

    if (seqGE(state->snd_una, tcpHeader->getAckNo())) {
        if (state->snd_una == tcpHeader->getAckNo() && payloadLength == 0 && state->snd_una != state->snd_max) {
            state->dupacks++;
            emit(dupAcksSignal, state->dupacks);

            if (rack_enabled)
            {
                uint32_t tser = state->ts_recent;
                simtime_t rtt = dynamic_cast<TcpPacedFamily*>(tcpAlgorithm)->getRtt();

                if (!scoreboardUpdated && rexmitQueue->findRegion(tcpHeader->getAckNo()))
                {
                    TcpSackRexmitQueue::Region& skbRegion = rexmitQueue->getRegion(tcpHeader->getAckNo());
                    m_rack->updateStats(tser, skbRegion.rexmitted, skbRegion.m_lastSentTime, tcpHeader->getAckNo(), state->snd_nxt, rtt);
                }
                else
                {
                    uint32_t highestSacked = rexmitQueue->getHighestSackedSeqNum();
                    if (rexmitQueue->findRegion(highestSacked)) {
                        TcpSackRexmitQueue::Region& skbRegion = rexmitQueue->getRegion(highestSacked);
                        m_rack->updateStats(tser, skbRegion.rexmitted,  skbRegion.m_lastSentTime, highestSacked, state->snd_nxt, rtt);
                    }
                }

                bool exiting = false;
                if (state->lossRecovery && dynamic_cast<TcpPacedFamily*>(tcpAlgorithm)->getRecoveryPoint() <= tcpHeader->getAckNo())
                    exiting = true;

                m_rack->updateReoWnd(m_reorder, m_dsackSeen, state->snd_nxt, tcpHeader->getAckNo(),
                                     rexmitQueue->getTotalAmountOfSackedBytes(), 3, exiting, state->lossRecovery);
            }
            scoreboardUpdated = false;

            updateWndInfo(tcpHeader);

            std::list<uint32_t> skbDeliveredList = rexmitQueue->getDiscardList(tcpHeader->getAckNo());
            for (uint32_t endSeqNo : skbDeliveredList)
                skbDelivered(endSeqNo);

            uint32_t currentDelivered  = m_delivered - previousDelivered;
            m_lastAckedSackedBytes = currentDelivered;

            updateInFlight();

            uint32_t currentLost = m_bytesLoss;
            uint32_t lost = (currentLost > previousLost) ? currentLost - previousLost : previousLost - currentLost;

            updateSample(currentDelivered, lost, false, priorInFlight, connMinRtt);

            tcpAlgorithm->receivedDuplicateAck();
            isRetransDataAcked = false;
            sendPendingData();

            m_reorder = false;
            if (fack_enabled || rack_enabled)
            {
                if (tcpHeader->getAckNo() > m_sndFack)
                    m_sndFack = tcpHeader->getAckNo();
                else if (tcpHeader->getAckNo() < m_sndFack)
                    m_reorder = true;
            }
        }
        else {
            if (payloadLength == 0) {
                if (state->snd_una != tcpHeader->getAckNo())
                    EV_DETAIL << "Old ACK: ackNo < snd_una\n";
                else if (state->snd_una == state->snd_max)
                    EV_DETAIL << "ACK looks duplicate but we have currently no unacked data (snd_una == snd_max)\n";
            }
            state->dupacks = 0;
            emit(dupAcksSignal, state->dupacks);
        }
    }
    else if (seqLE(tcpHeader->getAckNo(), state->snd_max)) {
        uint32_t old_snd_una = state->snd_una;
        state->snd_una = tcpHeader->getAckNo();

        emit(unackedSignal, state->snd_max - state->snd_una);

        if (seqLess(state->snd_nxt, state->snd_una))
            state->snd_nxt = state->snd_una;

        if (state->ts_enabled)
            tcpAlgorithm->rttMeasurementCompleteUsingTS(getTSecr(tcpHeader));

        uint32_t discardUpToSeq = state->snd_una;
        if (state->send_fin && tcpHeader->getAckNo() == state->snd_fin_seq + 1) {
            EV_DETAIL << "ACK acks our FIN\n";
            state->fin_ack_rcvd = true;
            discardUpToSeq--;
        }

        if (rack_enabled)
        {
            uint32_t tser = state->ts_recent;
            simtime_t rtt = dynamic_cast<TcpPacedFamily*>(tcpAlgorithm)->getRtt();

            if (!scoreboardUpdated && rexmitQueue->findRegion(tcpHeader->getAckNo()))
            {
                TcpSackRexmitQueue::Region& skbRegion = rexmitQueue->getRegion(tcpHeader->getAckNo());
                m_rack->updateStats(tser, skbRegion.rexmitted, skbRegion.m_lastSentTime, tcpHeader->getAckNo(), state->snd_nxt, rtt);
            }
            else
            {
                uint32_t highestSacked = rexmitQueue->getHighestSackedSeqNum();
                if (rexmitQueue->findRegion(highestSacked)) {
                    TcpSackRexmitQueue::Region& skbRegion = rexmitQueue->getRegion(highestSacked);
                    m_rack->updateStats(tser, skbRegion.rexmitted,  skbRegion.m_lastSentTime, highestSacked, state->snd_nxt, rtt);
                }
            }

            bool exiting = false;
            if (state->lossRecovery && dynamic_cast<TcpPacedFamily*>(tcpAlgorithm)->getRecoveryPoint() <= tcpHeader->getAckNo())
                exiting = true;

            m_rack->updateReoWnd(m_reorder, m_dsackSeen, state->snd_nxt, old_snd_una,
                                 rexmitQueue->getTotalAmountOfSackedBytes(), 3, exiting, state->lossRecovery);
        }
        scoreboardUpdated = false;

        std::list<uint32_t> skbDeliveredList = rexmitQueue->getDiscardList(discardUpToSeq);
        for (uint32_t endSeqNo : skbDeliveredList) {
            skbDelivered(endSeqNo);
            if (state->lossRecovery && rexmitQueue->isRetransmittedDataAcked(endSeqNo))
                isRetransDataAcked = true;
        }

        sendQueue->discardUpTo(discardUpToSeq);
        enqueueData();

        if (state->sack_enabled)
            rexmitQueue->discardUpTo(discardUpToSeq);

        updateWndInfo(tcpHeader);

        if (payloadLength == 0 && fsm.getState() != TCP_S_SYN_RCVD) {
            uint32_t currentDelivered  = m_delivered - previousDelivered;
            m_lastAckedSackedBytes = currentDelivered;

            updateInFlight();

            uint32_t currentLost = m_bytesLoss;
            uint32_t lost = (currentLost > previousLost) ? currentLost - previousLost : previousLost - currentLost;

            updateSample(currentDelivered, lost, false, priorInFlight, connMinRtt);

            tcpAlgorithm->receivedDataAck(old_snd_una);
            isRetransDataAcked = false;
            state->dupacks = 0;

            sendPendingData();

            m_reorder = false;
            if (fack_enabled || rack_enabled)
            {
                if (tcpHeader->getAckNo() > m_sndFack)
                    m_sndFack = tcpHeader->getAckNo();
                else if (tcpHeader->getAckNo() < m_sndFack)
                    m_reorder = true;
            }

            emit(dupAcksSignal, state->dupacks);
            emit(mDeliveredSignal, m_delivered);
        }
    }
    else {
        ASSERT(seqGreater(tcpHeader->getAckNo(), state->snd_max));
        tcpAlgorithm->receivedAckForDataNotYetSent(tcpHeader->getAckNo());
        state->dupacks = 0;
        emit(dupAcksSignal, state->dupacks);
        return false;
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

    TcpEventCode event;

    if (fsm.getState() == TCP_S_LISTEN) {
        event = processSegmentInListen(tcpSegment, tcpHeader, src, dest);
    }
    else if (fsm.getState() == TCP_S_SYN_SENT) {
        event = processSegmentInSynSent(tcpSegment, tcpHeader, src, dest);
    }
    else {
        bytesRcvd += tcpSegment->getByteLength(); // receiver-side throughput accounting
        event = processSegment1stThru8th(tcpSegment, tcpHeader);
    }

    delete tcpSegment;
    return event;
}

bool TcpPacedConnection::processTimer(cMessage *msg)
{
    printConnBrief();
    EV_DETAIL << msg->getName() << " timer expired\n";

    TcpEventCode event = TCP_E_IGNORE;

    if (msg == paceMsg) {
        sendPendingData();
    }
    else if (msg == rackTimer) {
        checkRackLoss();
    }
    else if (msg == throughputTimer) {
        // receiver-side goodput/throughput timer
        EV_TRACE << "Throughput timer at: " << simTime() << std::endl;
        computeThroughput();

        prevLastBytesReceived = lastBytesReceived;
        lastBytesReceived = bytesRcvd;
        prevLastThroughputTime = lastThroughputTime;
        lastThroughputTime = simTime();

        scheduleAt(simTime() + throughputInterval, throughputTimer);
    }
    else if (msg == retransmissionRateTimer) {
        // sender-side retransmission-rate timer (separate from throughputTimer)
        EV_TRACE << "Retransmission-rate timer at: " << simTime() << std::endl;
        computeRetransmissionRate();
        scheduleAt(simTime() + throughputInterval, retransmissionRateTimer);
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

    return performStateTransition(event);
}

bool TcpPacedConnection::sendData(uint32_t congestionWindow)
{
    if (!state->afterRto)
        state->snd_nxt = state->snd_max;

    uint32_t old_highRxt = 0;
    if (state->sack_enabled)
        old_highRxt = rexmitQueue->getHighestRexmittedSeqNum();

    uint32_t buffered = sendQueue->getBytesAvailable(state->snd_nxt);
    if (buffered == 0)
        return false;

    uint32_t maxWindow = std::min(state->snd_wnd, congestionWindow);
    int64_t effectiveWin = (int64_t)maxWindow - (state->snd_nxt - state->snd_una);

    if (effectiveWin <= 0) {
        EV_WARN << "Effective window is zero (advertised window " << state->snd_wnd
                << ", congestion window " << congestionWindow << "), cannot send.\n";
        return false;
    }

    uint32_t bytesToSend = std::min(buffered, (uint32_t)effectiveWin);

    const auto& tmpTcpHeader = makeShared<TcpHeader>();
    tmpTcpHeader->setAckBit(true);
    writeHeaderOptions(tmpTcpHeader);
    uint options_len = B(tmpTcpHeader->getHeaderLength() - TCP_MIN_HEADER_LENGTH).get();
    ASSERT(options_len < state->snd_mss);
    uint32_t effectiveMss = state->snd_mss;

    uint32_t old_snd_nxt = state->snd_nxt;

    EV_INFO << "May send " << bytesToSend << " bytes (effectiveWindow " << effectiveWin
            << ", in buffer " << buffered << " bytes)\n";

    if (bytesToSend >= effectiveMss) {
        uint32_t sentBytes = sendSegment(effectiveMss);
        bytesToSend -= sentBytes;
    }

    if (old_snd_nxt == state->snd_nxt)
        return false;

    emit(unackedSignal, state->snd_max - state->snd_una);
    tcpAlgorithm->ackSent();

    if (state->sack_enabled && state->lossRecovery && old_highRxt != state->highRxt) {
        EV_DETAIL << "Retransmission sent during recovery, restarting REXMIT timer.\n";
        tcpAlgorithm->restartRexmitTimer();
    }
    else
        tcpAlgorithm->dataSent(old_snd_nxt);

    return true;
}

uint32_t TcpPacedConnection::sendSegment(uint32_t bytes)
{
    if (state->sack_enabled && state->afterRto) {
        uint32_t forward = rexmitQueue->checkRexmitQueueForSackedOrRexmittedSegments(state->snd_nxt);

        if (forward > 0) {
            EV_INFO << "sendSegment(" << bytes << ") forwarded " << forward
                    << " bytes of snd_nxt from " << state->snd_nxt;
            state->snd_nxt += forward;
            EV_INFO << " to " << state->snd_nxt << endl;
            EV_DETAIL << rexmitQueue->detailedInfo();
        }
    }

    uint32_t buffered = sendQueue->getBytesAvailable(state->snd_nxt);
    if (bytes > buffered)
        bytes = buffered;

    const auto& tmpTcpHeader = makeShared<TcpHeader>();
    tmpTcpHeader->setAckBit(true);
    writeHeaderOptions(tmpTcpHeader);

    bytes = state->snd_mss;
    uint32_t sentBytes = bytes;

    Packet *tcpSegment = sendQueue->createSegmentWithBytes(state->snd_nxt, bytes);
    const auto& tcpHeader = makeShared<TcpHeader>();
    tcpHeader->setSequenceNo(state->snd_nxt);
    ASSERT(tcpHeader != nullptr);

    uint32_t old_snd_nxt = state->snd_nxt;

    tcpHeader->setAckNo(state->rcv_nxt);
    tcpHeader->setAckBit(true);
    tcpHeader->setWindow(updateRcvWnd());

    if (state->ect && state->sndCwr) {
        tcpHeader->setCwrBit(true);
        EV_INFO << "\nDCTCPInfo - sending TCP segment. Set CWR bit. Setting sndCwr to false\n";
        state->sndCwr = false;
    }

    ASSERT(bytes == tcpSegment->getByteLength());
    state->snd_nxt += bytes;

    if (state->afterRto && seqGE(state->snd_nxt, state->snd_max))
        state->afterRto = false;

    if (state->send_fin && state->snd_nxt == state->snd_fin_seq) {
        EV_DETAIL << "Setting FIN on segment\n";
        tcpHeader->setFinBit(true);
        state->snd_nxt = state->snd_fin_seq + 1;
    }

    if (state->sack_enabled) {
        rexmitQueue->enqueueSentData(old_snd_nxt, state->snd_nxt);
        if (pace) {
            rexmitQueue->skbSent(state->snd_nxt, m_firstSentTime, simTime(), m_deliveredTime, false, m_delivered, m_appLimited);
        }
    }

    for (uint i = 0; i < tmpTcpHeader->getHeaderOptionArraySize(); i++)
        tcpHeader->appendHeaderOption(tmpTcpHeader->getHeaderOption(i)->dup());
    tcpHeader->setHeaderLength(TCP_MIN_HEADER_LENGTH + tcpHeader->getHeaderOptionArrayLength());
    tcpHeader->setChunkLength(B(tcpHeader->getHeaderLength()));

    ASSERT(tcpHeader->getHeaderLength() == tmpTcpHeader->getHeaderLength());

    calculateAppLimited();
    sendToIP(tcpSegment, tcpHeader);

    const uint32_t alreadyQueued = sendQueue->getBytesAvailable(sendQueue->getBufferStartSeq());
    const uint32_t abated = (state->sendQueueLimit > alreadyQueued) ? state->sendQueueLimit - alreadyQueued : 0;
    if ((state->sendQueueLimit > 0) && !state->queueUpdate && (abated >= state->snd_mss)) {
        sendIndicationToApp(TCP_I_SEND_MSG, abated);
        state->queueUpdate = true;
    }

    if (seqGreater(state->snd_nxt, state->snd_max))
        state->snd_max = state->snd_nxt;

    updateInFlight();
    return sentBytes;
}

bool TcpPacedConnection::sendPendingData()
{
    bool dataSent = false;
    if (pace) {
        if (!paceMsg->isScheduled()) {
            if (state->lossRecovery)
                dataSent = sendDataDuringLossRecovery(dynamic_cast<TcpPacedFamily*>(tcpAlgorithm)->getCwnd());
            else
                dataSent = sendDataDuringLossRecovery(dynamic_cast<TcpPacedFamily*>(tcpAlgorithm)->getCwnd());

            if (dataSent) {
                EV_INFO << "sendPendingData: Data sent! Scheduling pacing timer for " << simTime() + intersendingTime << "\n";
                if (intersendingTime > 0)
                    scheduleAt(simTime() + intersendingTime, paceMsg);
            }
            else {
                EV_INFO << "sendPendingData: no data sent!\n";
            }
        }
    }
    return dataSent;
}

bool TcpPacedConnection::sendDataDuringLossRecovery(uint32_t congestionWindow)
{
    uint32_t availableWindow = (state->pipe > congestionWindow) ? 0 : congestionWindow - state->pipe;
    if (availableWindow >= (int)state->snd_mss) {
        uint32_t seqNum;

        // nextSeg communicates whether selection is retransmission via member flag
        nextSegSelectedRetransmission = false;
        if (!nextSeg(seqNum, state->lossRecovery))
            return false;

        const bool isRetransmission = nextSegSelectedRetransmission;
        uint32_t sentBytes = sendSegmentDuringLossRecoveryPhase(seqNum);

        if (sentBytes > 0) {
            if (isRetransmission)
                totalRetransmittedBytesCounter += sentBytes; // sender-side count at send time
            return true;
        }
        return false;
    }
    return false;
}

bool TcpPacedConnection::doRetransmit()
{
    uint32_t seqNum;
    if (rexmitQueue->isRetransmittedDataAcked(state->snd_una + state->snd_mss))
        return false;

    nextSegSelectedRetransmission = false;
    if (!nextSeg(seqNum, state->lossRecovery))
        return false;

    const bool isRetransmission = nextSegSelectedRetransmission;
    uint32_t sentBytes = sendSegmentDuringLossRecoveryPhase(seqNum);

    if (sentBytes > 0) {
        if (isRetransmission)
            totalRetransmittedBytesCounter += sentBytes; // sender-side count at send time

        if (!paceMsg->isScheduled()) {
            paceStart = simTime();
            scheduleAt(simTime() + intersendingTime, paceMsg);
        }
        return true;
    }
    return false;
}

void TcpPacedConnection::changeIntersendingTime(simtime_t _intersendingTime)
{
    if (pace) {
        ASSERT(_intersendingTime > 0);
        if (_intersendingTime != intersendingTime) {
            simtime_t prevIntersendingTime = intersendingTime;
            intersendingTime = _intersendingTime;
            EV_TRACE << "New pace: " << intersendingTime << "s\n";
            paceValueVec.record(intersendingTime);
            emit(paceRateSignal, ((1 / intersendingTime) * state->snd_mss) / 125000);
        }
    }
}

void TcpPacedConnection::retransmitOneSegment(bool called_at_rto)
{
    if (state && state->ect)
        state->rexmit = true;

    uint32_t old_snd_nxt = state->snd_nxt;
    state->snd_nxt = state->snd_una;

    uint32_t bytes = std::min(std::min(state->snd_mss, state->snd_max - state->snd_nxt),
                sendQueue->getBytesAvailable(state->snd_nxt));

    if (bytes == 0 && state->send_fin && state->snd_fin_seq == sendQueue->getBufferEndSeq()) {
        state->snd_max = sendQueue->getBufferEndSeq();
        EV_DETAIL << "No outstanding DATA, resending FIN, advancing snd_nxt over the FIN\n";
        state->snd_nxt = state->snd_max;
        sendFin();
        tcpAlgorithm->segmentRetransmitted(state->snd_nxt, state->snd_nxt + 1);
        state->snd_max = ++state->snd_nxt;

        totalRetransmittedBytesCounter += 1; // FIN retransmit as 1 byte sequence space

        emit(unackedSignal, state->snd_max - state->snd_una);
    }
    else {
        ASSERT(bytes != 0);
        sendSegment(bytes);
        tcpAlgorithm->segmentRetransmitted(state->snd_una, state->snd_nxt);

        totalRetransmittedBytesCounter += bytes; // sender-side count at send time

        if (!called_at_rto) {
            if (seqGreater(old_snd_nxt, state->snd_nxt))
                state->snd_nxt = old_snd_nxt;
        }

        tcpAlgorithm->ackSent();

        if (state->sack_enabled)
            state->highRxt = rexmitQueue->getHighestRexmittedSeqNum();
    }

    if (state && state->ect)
        state->rexmit = false;
}

bool TcpPacedConnection::nextSeg(uint32_t& seqNum, bool isRecovery)
{
    ASSERT(state->sack_enabled);

    // preserve override signature; communicate type via member flag
    nextSegSelectedRetransmission = false;
    seqNum = 0;

    state->highRxt = rexmitQueue->getHighestRexmittedSeqNum();
    uint32_t highestSackedSeqNum = rexmitQueue->getHighestSackedSeqNum();
    uint32_t shift = state->snd_mss;
    bool sacked = false;
    bool rexmitted = false;
    bool lost = false;

    uint32_t seqPerRule3 = 0;
    bool isSeqPerRule3Valid = false;

    for (uint32_t s2 = rexmitQueue->getBufferStartSeq();
         seqLess(s2, state->snd_max) && seqLess(s2, highestSackedSeqNum);
         s2 += shift)
    {
        rexmitQueue->checkSackBlockLost(s2, shift, sacked, rexmitted, lost);

        if (!sacked) {
            if (lost && !rexmitted) {
                seqNum = s2;
                nextSegSelectedRetransmission = true; // retransmission candidate
                return true;
            }
            else if (seqPerRule3 == 0 && isRecovery) {
                isSeqPerRule3Valid = true;
                seqPerRule3 = s2; // rescue retransmission candidate
            }
        }
    }

    {
        uint32_t buffered = sendQueue->getBytesAvailable(state->snd_max);
        uint32_t maxWindow = state->snd_wnd;
        uint32_t effectiveWin = maxWindow - state->pipe;

        if (buffered > 0 && effectiveWin >= state->snd_mss) {
            seqNum = state->snd_max;                   // new data
            nextSegSelectedRetransmission = false;
            return true;
        }
    }

    if (isSeqPerRule3Valid)
    {
        std::cout << "\n WEIRD EDGE CASE HAPPENING" << endl;
        seqNum = seqPerRule3;
        nextSegSelectedRetransmission = true;          // rescue retransmission
        return true;
    }

    seqNum = 0;
    nextSegSelectedRetransmission = false;
    return false;
}

void TcpPacedConnection::computeThroughput()
{
    EV_TRACE << "Bytes received since last measurement: " << bytesRcvd - lastBytesReceived
             << "B. Time elapsed since last time measured: " << simTime() - lastThroughputTime << std::endl;
    currThroughput = (bytesRcvd - lastBytesReceived) * 8 / (simTime().dbl() - lastThroughputTime.dbl());
    EV_TRACE << "Throughput computed from application: " << currThroughput << std::endl;
    emit(throughputSignal, currThroughput);
}

simtime_t TcpPacedConnection::getPacingRate()
{
    return intersendingTime;
}

void TcpPacedConnection::cancelPaceTimer()
{
    cancelEvent(paceMsg);
}

void TcpPacedConnection::enqueueData()
{
    if (sendQueue->getBufferEndSeq() - sendQueue->getBufferStartSeq() < (2000000000)) {
        Packet *msg = new Packet("Packet");
        const uint32_t packetSize = (2000000000 - (sendQueue->getBufferEndSeq() - sendQueue->getBufferStartSeq()));
        Ptr<Chunk> bytes = makeShared<ByteCountChunk>(B(packetSize));
        msg->insertAtBack(bytes);
        sendQueue->enqueueAppData(msg);
    }
}

void TcpPacedConnection::setSackedHeadLost()
{
    if (!rexmitQueue->checkHeadIsLost())
        rexmitQueue->markHeadAsLost();
}

void TcpPacedConnection::setAllSackedLost()
{
    rexmitQueue->setAllLost();
    state->highRxt = rexmitQueue->getHighestRexmittedSeqNum();
}

bool TcpPacedConnection::checkIsLost(uint32_t seqNo)
{
    return rexmitQueue->checkIsLost(seqNo, rexmitQueue->getHighestSackedSeqNum());
}

uint32_t TcpPacedConnection::getHighestRexmittedSeqNum()
{
    return rexmitQueue->getHighestRexmittedSeqNum();
}

void TcpPacedConnection::skbDelivered(uint32_t seqNum)
{
    if (rexmitQueue->findRegion(seqNum)) {
        TcpSackRexmitQueue::Region& skbRegion = rexmitQueue->getRegion(seqNum);
        if (skbRegion.m_deliveredTime != SIMTIME_MAX) {
            m_delivered += skbRegion.endSeqNum - skbRegion.beginSeqNum;
            if ((skbRegion.endSeqNum - skbRegion.beginSeqNum) != 1448)
                std::cout << "\n AMOUNT DELIVERED" << skbRegion.endSeqNum - skbRegion.beginSeqNum << endl;

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
    else {
        std::cout << "\n SKB NOT FOUND" << endl;
        EV_DETAIL << "\n SkbDelivered cant find segment!: " << seqNum << endl;
        EV_DETAIL << rexmitQueue->str() << endl;
    }
}

void TcpPacedConnection::updateInFlight()
{
    ASSERT(state->sack_enabled);

    state->highRxt = rexmitQueue->getHighestRexmittedSeqNum();

    m_bytesInFlight = rexmitQueue->getInFlight();
    m_bytesLoss = rexmitQueue->getLost();
    state->pipe = m_bytesInFlight;

    emit(mbytesInFlightSignal, m_bytesInFlight);
    emit(mbytesLossSignal, m_bytesLoss);
}

void TcpPacedConnection::updateSample(uint32_t delivered, uint32_t lost, bool is_sack_reneg, uint32_t priorInFlight, simtime_t minRtt)
{
    if (m_appLimited != 0 && m_delivered > m_appLimited)
        m_appLimited = 0;

    m_rateSample.m_ackedSacked = delivered;
    m_rateSample.m_bytesLoss = lost;
    m_rateSample.m_priorInFlight = priorInFlight;

    if (m_rateSample.m_priorTime == 0 || is_sack_reneg) {
        m_rateSample.m_delivered = -1;
        m_rateSample.m_interval = 0;
        return;
    }

    m_rateSample.m_interval = std::max(m_rateSample.m_sendElapsed, m_rateSample.m_ackElapsed);
    m_rateSample.m_delivered = m_delivered - m_rateSample.m_priorDelivered;

    if (m_rateSample.m_interval < minRtt) {
        m_rateSample.m_interval = 0;
        m_rateSample.m_priorTime = 0;
        return;
    }

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

    if (n > 0) {
        EV_INFO << n << " SACK(s) received:\n";
        for (uint i = 0; i < n; i++) {
            Sack tmp;
            tmp.setStart(option.getSackItem(i).getStart());
            tmp.setEnd(option.getSackItem(i).getEnd());

            EV_INFO << (i + 1) << ". SACK: " << tmp.str() << endl;

            if (i == 0 && seqLE(tmp.getEnd(), tcpHeader->getAckNo())) {
                if (rack_enabled) {
                    m_dsackSeen = true;
                    if (rexmitQueue->isRetransmitted(tmp.getEnd()))
                        m_reorder = true;
                }
                EV_DETAIL << "Received D-SACK below cumulative ACK=" << tcpHeader->getAckNo()
                          << " D-SACK: " << tmp.str() << endl;
            }
            else if (i == 0 && n > 1 && seqGreater(tmp.getEnd(), tcpHeader->getAckNo())) {
                m_dsackSeen = false;
                Sack tmp2(option.getSackItem(1).getStart(), option.getSackItem(1).getEnd());

                if (tmp2.contains(tmp)) {
                    EV_DETAIL << "Received D-SACK above cumulative ACK=" << tcpHeader->getAckNo()
                              << " D-SACK: " << tmp.str()
                              << ", SACK: " << tmp2.str() << endl;
                }
            }

            if (seqGreater(tmp.getEnd(), tcpHeader->getAckNo()) && seqGreater(tmp.getEnd(), state->snd_una)) {
                std::list<uint32_t> skbDeliveredList = rexmitQueue->setSackedBitList(tmp.getStart(), tmp.getEnd());
                scoreboardUpdated = true;
                for (uint32_t endSeqNo : skbDeliveredList) {
                    if (fack_enabled || rack_enabled) {
                        if (endSeqNo > m_sndFack)
                            m_sndFack = endSeqNo;
                        else
                            m_reorder = true;
                    }
                    skbDelivered(endSeqNo);
                }
            }
            else {
                EV_DETAIL << "Received SACK below total cumulative ACK snd_una=" << state->snd_una << "\n";
            }
        }

        if (rexmitQueue->updateLost(rexmitQueue->getHighestSackedSeqNum()))
            dynamic_cast<TcpPacedFamily*>(tcpAlgorithm)->notifyLost();

        state->rcv_sacks += n;
        emit(rcvSacksSignal, state->rcv_sacks);

        state->sackedBytes_old = state->sackedBytes;
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
    if (fack_enabled) {
        uint32_t fack_diff = std::max((uint32_t)0, (m_sndFack - rexmitQueue->getBufferStartSeq()));
        return fack_diff > state->snd_mss * 3;
    }
    else {
        return false;
    }
}

bool TcpPacedConnection::checkRackLoss()
{
    double timeout = 0.0;
    bool enterRecovery = false;
    if (rexmitQueue->checkRackLoss(m_rack, timeout))
        dynamic_cast<TcpPacedFamily*>(tcpAlgorithm)->notifyLost();

    if (rexmitQueue->getLost() != 0 && !state->lossRecovery)
        enterRecovery = true;

    if (timeout > 0) {
        if ((simTime() + timeout) > simTime())
            rescheduleAt(simTime() + timeout, rackTimer);
        tcpAlgorithm->restartRexmitTimer();
    }
    return enterRecovery;
}

void TcpPacedConnection::computeRetransmissionRate()
{
    const double dt = simTime().dbl() - lastRetransmissionRateTime.dbl();
    if (dt <= 0)
        return;

    const uint64_t totalRtxBytes = totalRetransmittedBytesCounter;
    const uint64_t deltaRtxBytes = totalRtxBytes - lastTotalRetransmittedBytes;

    currRetransmissionRate = (double)deltaRtxBytes * 8.0 / dt; // bits/s
    emit(retransmissionRateSignal, currRetransmissionRate);

    prevLastTotalRetransmittedBytes = lastTotalRetransmittedBytes;
    lastTotalRetransmittedBytes = totalRtxBytes;
    lastRetransmissionRateTime = simTime();
}

} // namespace tcp
} // namespace inet
