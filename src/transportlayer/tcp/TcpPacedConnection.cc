//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//

#include "TcpPacedConnection.h"
#include "TcpPaced.h"
#include <algorithm>
#include <limits>
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

TcpPacedFamily *TcpPacedConnection::getPacedAlgorithm() const
{
    auto *pacedAlgorithm = dynamic_cast<TcpPacedFamily *>(tcpAlgorithm);
    if (pacedAlgorithm == nullptr)
        throw cRuntimeError("TcpPacedConnection requires a TcpPacedFamily-compatible tcpAlgorithmClass");
    return pacedAlgorithm;
}

void TcpPacedConnection::configureMechanismParameters()
{
    const bool updatedSackEnabled = tcpMain->hasPar("updatedSackEnabled") ? (bool)tcpMain->par("updatedSackEnabled") : true;
    const bool requestedPacingEnabled = tcpMain->hasPar("pacingEnabled") ? (bool)tcpMain->par("pacingEnabled") : true;
    const bool requestedRackEnabled = tcpMain->hasPar("rackEnabled") ? (bool)tcpMain->par("rackEnabled") : true;

    pace = updatedSackEnabled && requestedPacingEnabled;
    rack_enabled = updatedSackEnabled && requestedRackEnabled;
    fack_enabled = updatedSackEnabled;

    if (rexmitQueue != nullptr)
        rexmitQueue->setUpdatedSackEnabled(updatedSackEnabled);

    if (!updatedSackEnabled && requestedRackEnabled)
        EV_WARN << "rackEnabled requires updatedSackEnabled; disabling RACK for this connection.\n";
    if (!updatedSackEnabled && requestedPacingEnabled)
        EV_WARN << "pacingEnabled requires updatedSackEnabled; disabling pacing for this connection.\n";
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
    m_appLimited = false;
    m_rateAppLimited = false;
    m_txItemDelivered = 0;

    m_bytesInFlight = 0;
    m_bytesLoss = 0;

    lastThroughputTime = simTime();
    prevLastThroughputTime = simTime();

    m_firstSentTime = simTime();
    m_deliveredTime = simTime();

    m_rack = new TcpRack();
    m_sndFack = state->snd_una;
    m_reorder = false;
    m_dsackSeen = false;
    isRetransDataAcked = false;

    m_rateInterval = 0;
    m_rateDelivered = 0;

    m_lastAckedSackedBytes = 0;
    m_newlySackedBytesForAck = 0;
    bytesRcvd = 0;

    m_rateSample.m_ackElapsed = 0;
    m_rateSample.m_ackedSacked = 0;
    m_rateSample.m_bytesLoss = 0;
    m_rateSample.m_delivered = 0;
    m_rateSample.m_deliveryRate = 0;
    m_rateSample.m_interval = 0;
    m_rateSample.m_isAppLimited = false;
    m_rateSample.m_priorDelivered = 0;
    m_rateSample.m_txInFlight = 0;
    m_rateSample.m_priorInFlight = 0;
    m_rateSample.m_priorTime = 0;
    m_rateSample.m_sendElapsed = 0;
    m_rateSample.m_lastSentTime = 0;
    m_rateSample.m_lastEndSeq = 0;
    m_lossNotificationSample = {};

    // sender-side retransmission accounting
    prevLastTotalRetransmittedBytes = 0;
    lastTotalRetransmittedBytes = 0;
    totalRetransmittedBytesCounter = 0;
    currRetransmissionRate = 0;
    nextSegSelectedRetransmission = false;
    lastRetransmissionRateTime = simTime();
    scheduleAt(simTime() + throughputInterval, retransmissionRateTimer);
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
    m_rateSample.m_txInFlight = 0;
    m_rateSample.m_lastSentTime = 0;
    m_rateSample.m_lastEndSeq = 0;
    m_lossNotificationSample = {};

    // Keep separate timers: throughput (receiver-side bytesRcvd) and retransmissionRate (sender-side send counting)
    scheduleAt(simTime() + throughputInterval, throughputTimer);

    TcpConnection::initClonedConnection(listenerConn);
    configureMechanismParameters();
    m_sndFack = state->snd_una;
    m_reorder = false;
    m_dsackSeen = false;
    isRetransDataAcked = false;
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
    configureMechanismParameters();
}

bool TcpPacedConnection::processAckInEstabEtc(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader)
{
    EV_DETAIL << "Processing ACK in a data transfer state\n";
    // Options are parsed before this callback. Preserve delivery recorded
    // while parsing this ACK's SACK blocks for rate sampling and PRR.
    const uint32_t newlySackedBytes = m_newlySackedBytesForAck;
    m_newlySackedBytesForAck = 0;
    uint64_t previousDelivered = m_delivered;
    uint64_t previousTotalDetectedLostBytes = getTotalDetectedLostBytes();
    uint32_t priorInFlight = m_bytesInFlight;
    int payloadLength = tcpSegment->getByteLength() - B(tcpHeader->getHeaderLength()).get();
    beginRateSample();

    TcpStateVariables *state = getState();
    if (state && state->ect) {
        if (tcpHeader->getEceBit() == true)
            EV_INFO << "Received packet with ECE\n";
        state->gotEce = tcpHeader->getEceBit();
    }

    const bool sackOptionSeen = m_sackOptionSeenForAck;
    const bool tlpDsackSeen = m_tlpDsackSeenForProbe;
    m_sackOptionSeenForAck = false;
    m_tlpDsackSeenForProbe = false;

    const bool pureDuplicateAck = state->snd_una == tcpHeader->getAckNo() &&
            payloadLength == 0 && !sackOptionSeen;
    const bool tlpRecoveredLoss =
            processTailLossProbeAck(tcpHeader->getAckNo(), pureDuplicateAck, tlpDsackSeen);

    if (seqGE(state->snd_una, tcpHeader->getAckNo())) {
        if (state->snd_una == tcpHeader->getAckNo() && payloadLength == 0 && state->snd_una != state->snd_max) {
            state->dupacks++;
            emit(dupAcksSignal, state->dupacks);

            if (rack_enabled)
            {
                const bool inLossState = state->lossRecovery || isInRtoRecovery();
                const bool exiting = inLossState &&
                        seqGE(tcpHeader->getAckNo(), getPacedAlgorithm()->getRecoveryPoint());

                m_rack->updateReoWnd(m_reorder, m_dsackSeen, state->snd_nxt, tcpHeader->getAckNo(),
                                     rexmitQueue->getTotalAmountOfSackedBytes(), 3, state->snd_mss,
                                     exiting, inLossState);
            }
            updateWndInfo(tcpHeader);

            if (rexmitQueue->isUpdatedSackEnabled()) {
                std::list<uint32_t> skbDeliveredList = rexmitQueue->getDiscardList(tcpHeader->getAckNo());
                for (uint32_t endSeqNo : skbDeliveredList) {
                    rackAdvance(endSeqNo, tcpHeader);
                    skbDelivered(endSeqNo);
                }
            }

            uint32_t currentDelivered = newlySackedBytes + (m_delivered - previousDelivered);
            m_lastAckedSackedBytes = currentDelivered;

            bool newRackLoss = false;
            bool rackRecovery = checkRackLoss(&newRackLoss);
            updateInFlight();

            uint32_t lost = getNewlyDetectedLostBytes(
                    previousTotalDetectedLostBytes, newRackLoss || tlpRecoveredLoss);
            updateSample(currentDelivered, lost, false, priorInFlight, connMinRtt);

            if (shouldApplyRackCongestionResponse() &&
                    (rackRecovery || newRackLoss || tlpRecoveredLoss))
                getPacedAlgorithm()->rackLossDetected();
            tcpAlgorithm->receivedDuplicateAck();
            isRetransDataAcked = false;
            sendPendingData();
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
            const bool inLossState = state->lossRecovery || isInRtoRecovery();
            const bool exiting = inLossState &&
                    seqGE(state->snd_una, getPacedAlgorithm()->getRecoveryPoint());

            m_rack->updateReoWnd(m_reorder, m_dsackSeen, state->snd_nxt, state->snd_una,
                                 rexmitQueue->getTotalAmountOfSackedBytes(), 3, state->snd_mss,
                                 exiting, inLossState);
        }
        if (rexmitQueue->isUpdatedSackEnabled()) {
            std::list<uint32_t> skbDeliveredList = rexmitQueue->getDiscardList(discardUpToSeq);
            for (uint32_t endSeqNo : skbDeliveredList) {
                bool wasRetransmitted = rexmitQueue->isRetransmitted(endSeqNo);
                rackAdvance(endSeqNo, tcpHeader);
                skbDelivered(endSeqNo);
                if (state->lossRecovery && rexmitQueue->isRetransmittedDataAcked(endSeqNo))
                    isRetransDataAcked = true;
                if ((fack_enabled || rack_enabled) && seqLess(endSeqNo, m_sndFack) && !wasRetransmitted)
                    m_reorder = true;
            }
        }

        sendQueue->discardUpTo(discardUpToSeq);
        enqueueData();

        if (state->sack_enabled)
            rexmitQueue->discardUpTo(discardUpToSeq);

        updateWndInfo(tcpHeader);

        if (payloadLength == 0 && fsm.getState() != TCP_S_SYN_RCVD) {
            uint32_t currentDelivered = newlySackedBytes + (m_delivered - previousDelivered);
            m_lastAckedSackedBytes = currentDelivered;

            bool newRackLoss = false;
            bool rackRecovery = checkRackLoss(&newRackLoss);
            updateInFlight();

            uint32_t lost = getNewlyDetectedLostBytes(
                    previousTotalDetectedLostBytes, newRackLoss || tlpRecoveredLoss);
            updateSample(currentDelivered, lost, false, priorInFlight, connMinRtt);

            if (shouldApplyRackCongestionResponse() &&
                    (rackRecovery || newRackLoss || tlpRecoveredLoss))
                getPacedAlgorithm()->rackLossDetected();
            tcpAlgorithm->receivedDataAck(old_snd_una);
            isRetransDataAcked = false;
            state->dupacks = 0;

            sendPendingData();

            if (fack_enabled || rack_enabled)
            {
                if (tcpHeader->getAckNo() > m_sndFack)
                    m_sndFack = tcpHeader->getAckNo();
            }

            emit(dupAcksSignal, state->dupacks);
            emit(mDeliveredSignal, m_delivered);
        }
        scheduleTailLossProbe();
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
        RackTimerMode expiredMode = m_rackTimerMode;
        m_rackTimerMode = RackTimerMode::NONE;
        if (rack_enabled && expiredMode == RackTimerMode::REORDERING) {
            bool newRackLoss = false;
            bool rackRecovery = checkRackLoss(&newRackLoss, true);
            if (shouldApplyRackCongestionResponse() && (rackRecovery || newRackLoss)) {
                m_rackTimerLossDetection = true;
                getPacedAlgorithm()->rackLossDetected();
                m_rackTimerLossDetection = false;
            }
        }
        else if (rack_enabled && expiredMode == RackTimerMode::LOSS_PROBE)
            sendTailLossProbe();
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
        if (getPacedAlgorithm()->isRexmitTimer(msg))
            resetRackTimersForRto();
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

    scheduleTailLossProbe();
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

    bytes = std::min(bytes, state->snd_mss);
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
        if ((pace || rack_enabled) && rexmitQueue->isUpdatedSackEnabled()) {
            rexmitQueue->skbSent(state->snd_nxt, m_firstSentTime, simTime(), m_deliveredTime,
                    m_bytesInFlight + sentBytes, false, m_delivered, m_appLimited);
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

void TcpPacedConnection::sendOneNewSegment(bool fullSegmentsOnly, uint32_t congestionWindow)
{
    uint32_t oldSndMax = state->snd_max;
    TcpConnection::sendOneNewSegment(fullSegmentsOnly, congestionWindow);
    if (seqGreater(state->snd_max, oldSndMax))
        scheduleTailLossProbe();
}

bool TcpPacedConnection::sendPendingData()
{
    if (!pace && state->lossRecovery) {
        bool dataSent = false;
        while (sendDataDuringLossRecovery(getPacedAlgorithm()->getCwnd()))
            dataSent = true;
        return dataSent;
    }

    if (!pace)
        return sendData(getPacedAlgorithm()->getCwnd());

    bool dataSent = false;

    if (!paceMsg->isScheduled()) {
        if (state->lossRecovery)
            dataSent = sendDataDuringLossRecovery(getPacedAlgorithm()->getCwnd());
        else
            dataSent = sendDataDuringLossRecovery(getPacedAlgorithm()->getCwnd());

        if (dataSent) {
            EV_INFO << "sendPendingData: Data sent! Scheduling pacing timer for " << simTime() + intersendingTime << "\n";
            if (intersendingTime > 0)
                scheduleAt(simTime() + intersendingTime, paceMsg);
        }
        else {
            EV_INFO << "sendPendingData: no data sent!\n";
        }
    }
    return dataSent;
}

bool TcpPacedConnection::isCwndLimited(uint32_t congestionWindow) const
{
    if (state == nullptr || sendQueue == nullptr)
        return false;

    if (sendQueue->getBytesAvailable(state->snd_max) == 0)
        return false;

    return m_bytesInFlight + state->snd_mss >= congestionWindow;
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
            else
                scheduleTailLossProbe();
            return true;
        }
        return false;
    }
    return false;
}

uint32_t TcpPacedConnection::sendSegmentDuringLossRecoveryPhase(uint32_t seqNum)
{
    const uint32_t sentBytes = TcpConnection::sendSegmentDuringLossRecoveryPhase(seqNum);
    if (sentBytes > 0)
        getPacedAlgorithm()->recoveryDataSent(sentBytes);
    return sentBytes;
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

        if (pace && !paceMsg->isScheduled()) {
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
    // RFC 6675 section 5.1 says NextSeg is inappropriate after an RTO. Walk
    // all pre-RTO outstanding data so the oldest missing range is repaired
    // before new data is selected, while still honoring fresh SACKs.
    uint32_t retransmitSearchEnd = state->afterRto ? state->snd_max : highestSackedSeqNum;
    uint32_t shift = state->snd_mss;
    bool sacked = false;
    bool rexmitted = false;
    bool lost = false;

    uint32_t seqPerRule3 = 0;
    bool isSeqPerRule3Valid = false;

    for (uint32_t s2 = rexmitQueue->getBufferStartSeq();
         seqLess(s2, state->snd_max) && seqLess(s2, retransmitSearchEnd);
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
    if (!rexmitQueue->isUpdatedSackEnabled())
        return;

    if (!rexmitQueue->checkHeadIsLost())
        rexmitQueue->markHeadAsLost();
}

void TcpPacedConnection::setSackedHeadLostIfRackDisabled()
{
    if (!rack_enabled)
        rexmitQueue->markHeadAsLostIfUnsacked();
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

bool TcpPacedConnection::isHeadLost() const
{
    return rexmitQueue != nullptr && rexmitQueue->checkHeadIsLost();
}

uint32_t TcpPacedConnection::getHighestRexmittedSeqNum()
{
    return rexmitQueue->getHighestRexmittedSeqNum();
}

void TcpPacedConnection::skbDelivered(uint32_t seqNum)
{
    if (!rexmitQueue->isUpdatedSackEnabled())
        return;

    if (rexmitQueue->findRegion(seqNum)) {
        TcpSackRexmitQueue::Region& skbRegion = rexmitQueue->getRegion(seqNum);
        if (skbRegion.m_deliveredTime != SIMTIME_MAX) {
            m_delivered += skbRegion.endSeqNum - skbRegion.beginSeqNum;
            m_deliveredTime = simTime();

            const bool isMostRecentDeliveredSkb = m_rateSample.m_priorDelivered == 0 ||
                    skbRegion.m_lastSentTime > m_rateSample.m_lastSentTime ||
                    (skbRegion.m_lastSentTime == m_rateSample.m_lastSentTime && seqNum > m_rateSample.m_lastEndSeq);

            if (isMostRecentDeliveredSkb)
            {
                m_rateSample.m_ackElapsed = simTime() - skbRegion.m_deliveredTime;
                m_rateSample.m_priorDelivered = skbRegion.m_delivered;
                m_rateSample.m_priorTime = skbRegion.m_deliveredTime;
                m_rateSample.m_isAppLimited = skbRegion.m_isAppLimited;
                m_rateSample.m_txInFlight = skbRegion.m_txInFlight;
                m_rateSample.m_sendElapsed = skbRegion.m_lastSentTime - skbRegion.m_firstSentTime;
                m_rateSample.m_lastSentTime = skbRegion.m_lastSentTime;
                m_rateSample.m_lastEndSeq = seqNum;

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

uint64_t TcpPacedConnection::getTotalDetectedLostBytes() const
{
    return rexmitQueue == nullptr ? 0 : rexmitQueue->getTotalDetectedLostBytes();
}

uint32_t TcpPacedConnection::getNewlyDetectedLostBytes(
        uint64_t previousTotalDetectedLostBytes, bool lossDetected) const
{
    const uint64_t currentTotalDetectedLostBytes = getTotalDetectedLostBytes();
    uint64_t newlyDetectedLostBytes =
            currentTotalDetectedLostBytes > previousTotalDetectedLostBytes ?
            currentTotalDetectedLostBytes - previousTotalDetectedLostBytes : 0;

    // A retransmission can be declared lost while its region is already marked
    // lost. Preserve Linux's non-zero newly_lost signal for PRR-SSRB in that case.
    if (newlyDetectedLostBytes == 0 && lossDetected)
        newlyDetectedLostBytes = state != nullptr ? std::max(state->snd_mss, 1U) : 1U;

    return static_cast<uint32_t>(std::min(
            newlyDetectedLostBytes,
            static_cast<uint64_t>(std::numeric_limits<uint32_t>::max())));
}

void TcpPacedConnection::updateLossNotificationSample()
{
    m_lossNotificationSample = {};

    uint32_t txInFlight = 0;
    uint32_t lostBytes = 0;
    bool isAppLimited = false;
    if (rexmitQueue->getRecentLossSample(txInFlight, lostBytes, isAppLimited)) {
        m_lossNotificationSample.m_valid = true;
        m_lossNotificationSample.m_bytesLoss = lostBytes;
        m_lossNotificationSample.m_txInFlight = txInFlight;
        m_lossNotificationSample.m_isAppLimited = isAppLimited;
    }
}

void TcpPacedConnection::rackAdvance(uint32_t endSeqNo, const Ptr<const TcpHeader>& tcpHeader)
{
    if (!rack_enabled || !rexmitQueue->isUpdatedSackEnabled())
        return;

    if (!rexmitQueue->findRegion(endSeqNo))
        return;

    TcpSackRexmitQueue::Region& skbRegion = rexmitQueue->getRegion(endSeqNo);
    // Linux advances RACK only when this ACK newly delivers the packet.
    if (skbRegion.m_deliveredTime == SIMTIME_MAX)
        return;

    if (m_rack->updateStats(getTSecr(tcpHeader), skbRegion.everRetransmitted, skbRegion.m_lastSentTime,
            endSeqNo, state->snd_nxt, getPacedAlgorithm()->getRtt()))
        m_rttSampleGeneration++;
}

void TcpPacedConnection::beginRateSample()
{
    m_rateSample.m_deliveryRate = 0;
    m_rateSample.m_interval = 0;
    m_rateSample.m_delivered = 0;
    m_rateSample.m_priorDelivered = 0;
    m_rateSample.m_priorTime = 0;
    m_rateSample.m_sendElapsed = 0;
    m_rateSample.m_ackElapsed = 0;
    m_rateSample.m_lastSentTime = 0;
    m_rateSample.m_bytesLoss = 0;
    m_rateSample.m_txInFlight = 0;
    m_rateSample.m_priorInFlight = 0;
    m_rateSample.m_ackedSacked = 0;
    m_rateSample.m_lastEndSeq = 0;
    m_rateSample.m_isAppLimited = false;
}

void TcpPacedConnection::updateSample(uint32_t delivered, uint32_t lost, bool is_sack_reneg, uint32_t priorInFlight, simtime_t minRtt)
{
    if (m_appLimited != 0 && m_delivered > m_appLimited)
        m_appLimited = 0;

    m_rateSample.m_ackedSacked = delivered;
    m_rateSample.m_bytesLoss = lost;
    if (delivered == 0 || m_rateSample.m_txInFlight == 0)
        m_rateSample.m_txInFlight = priorInFlight;
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

    m_rateSample.m_deliveryRate = m_rateSample.m_delivered / m_rateSample.m_interval;

    if (!m_rateSample.m_isAppLimited || (m_rateSample.m_delivered * m_rateInterval >= m_rateDelivered * m_rateSample.m_interval)) {
        m_rateDelivered = m_rateSample.m_delivered;
        m_rateInterval = m_rateSample.m_interval;
        m_rateAppLimited = m_rateSample.m_isAppLimited;
    }
}

TcpPacedConnection::LossNotificationSample TcpPacedConnection::consumeLossNotificationSample()
{
    auto sample = m_lossNotificationSample;
    m_lossNotificationSample = {};
    return sample;
}

bool TcpPacedConnection::processSACKOption(const Ptr<const TcpHeader>& tcpHeader, const TcpOptionSack& option)
{
    m_sackOptionSeenForAck = true;

    if (!rexmitQueue->isUpdatedSackEnabled())
        return TcpConnection::processSACKOption(tcpHeader, option);

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

    const uint32_t deliveredBeforeSack = m_delivered;

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
                if (m_tlpProbeOutstanding && m_tlpIsRetransmission && tmp.getEnd() == m_tlpEndSeq)
                    m_tlpDsackSeenForProbe = true;
                EV_DETAIL << "Received D-SACK below cumulative ACK=" << tcpHeader->getAckNo()
                          << " D-SACK: " << tmp.str() << endl;
            }
            else if (i == 0 && n > 1 && seqGreater(tmp.getEnd(), tcpHeader->getAckNo())) {
                m_dsackSeen = false;
                Sack tmp2(option.getSackItem(1).getStart(), option.getSackItem(1).getEnd());

                if (tmp2.contains(tmp)) {
                    if (m_tlpProbeOutstanding && m_tlpIsRetransmission && tmp.getEnd() == m_tlpEndSeq)
                        m_tlpDsackSeenForProbe = true;
                    EV_DETAIL << "Received D-SACK above cumulative ACK=" << tcpHeader->getAckNo()
                              << " D-SACK: " << tmp.str()
                              << ", SACK: " << tmp2.str() << endl;
                }
            }

            if (seqGreater(tmp.getEnd(), tcpHeader->getAckNo()) && seqGreater(tmp.getEnd(), state->snd_una)) {
                std::list<uint32_t> skbDeliveredList = rexmitQueue->setSackedBitList(tmp.getStart(), tmp.getEnd());
                for (uint32_t endSeqNo : skbDeliveredList) {
                    bool wasRetransmitted = rexmitQueue->getRegion(endSeqNo).everRetransmitted;
                    rackAdvance(endSeqNo, tcpHeader);
                    if (fack_enabled || rack_enabled) {
                        if (endSeqNo > m_sndFack)
                            m_sndFack = endSeqNo;
                        else if (endSeqNo < m_sndFack && !wasRetransmitted)
                            m_reorder = true;
                    }
                    skbDelivered(endSeqNo);
                }
            }
            else {
                EV_DETAIL << "Received SACK below total cumulative ACK snd_una=" << state->snd_una << "\n";
            }
        }

        rexmitQueue->clearRecentLossSample();
        if (!rack_enabled && rexmitQueue->updateLost(rexmitQueue->getHighestSackedSeqNum())) {
            updateLossNotificationSample();
            getPacedAlgorithm()->notifyLost();
        }

        state->rcv_sacks += n;
        emit(rcvSacksSignal, state->rcv_sacks);

        state->sackedBytes_old = state->sackedBytes;
        state->sackedBytes = rexmitQueue->getTotalAmountOfSackedBytes();

        emit(sackedBytesSignal, state->sackedBytes);
    }

    // processAckInEstabEtc() snapshots m_delivered after TCP options have
    // already been handled, so carry this ACK's newly SACKed bytes across.
    m_newlySackedBytesForAck += m_delivered - deliveredBeforeSack;
    return true;
}

void TcpPacedConnection::calculateAppLimited()
{
    if (m_appLimited != 0)
        return;

    const uint32_t unsentBytes = sendQueue->getBytesAvailable(state->snd_max);
    const uint32_t congestionWindow = getPacedAlgorithm()->getCwnd();
    const bool hasLessThanOneMssToSend = unsentBytes < state->snd_mss;
    const bool isNotCwndLimited = m_bytesInFlight < congestionWindow;
    const bool hasNoLostDataToRetransmit = m_bytesLoss == 0;

    if (hasLessThanOneMssToSend && isNotCwndLimited && hasNoLostDataToRetransmit)
        m_appLimited = (m_delivered + m_bytesInFlight) ? (m_delivered + m_bytesInFlight) : 1;
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
    if (!fack_enabled || !rexmitQueue->isUpdatedSackEnabled())
        return false;

    uint32_t fack_diff = std::max((uint32_t)0, (m_sndFack - rexmitQueue->getBufferStartSeq()));
    return fack_diff > state->snd_mss * 3;
}

void TcpPacedConnection::armRackTimer(RackTimerMode mode, simtime_t delay)
{
    if (delay <= SIMTIME_ZERO)
        return;

    simtime_t expiry = simTime() + delay;
    if (rackTimer->isScheduled())
        rescheduleAt(expiry, rackTimer);
    else
        scheduleAt(expiry, rackTimer);
    m_rackTimerMode = mode;
}

void TcpPacedConnection::clearRackTimer(RackTimerMode mode)
{
    if (m_rackTimerMode != mode)
        return;

    if (rackTimer->isScheduled())
        cancelEvent(rackTimer);
    m_rackTimerMode = RackTimerMode::NONE;
}

void TcpPacedConnection::clearTailLossProbe(bool cancelProbeTimer)
{
    if (cancelProbeTimer)
        clearRackTimer(RackTimerMode::LOSS_PROBE);

    m_tlpProbeOutstanding = false;
    m_tlpIsRetransmission = false;
    m_tlpProbeBeginSeq = 0;
    m_tlpEndSeq = 0;
    m_tlpDsackSeenForProbe = false;
}

void TcpPacedConnection::resetTailLossProbe()
{
    clearTailLossProbe(true);
}

void TcpPacedConnection::resetRackTimersForRto()
{
    m_rackTimerLossDetection = false;
    clearRackTimer(RackTimerMode::REORDERING);
    clearTailLossProbe(true);
}

void TcpPacedConnection::scheduleTailLossProbe()
{
    if (!rack_enabled || !state->sack_enabled || !rexmitQueue->isUpdatedSackEnabled() ||
            state->lossRecovery || isInRtoRecovery() || state->afterRto ||
            state->snd_una == state->snd_max ||
            state->snd_wnd == 0 || m_tlpProbeOutstanding)
        return;

    if (rexmitQueue->getTotalAmountOfSackedBytes() != 0) {
        clearRackTimer(RackTimerMode::LOSS_PROBE);
        return;
    }

    if (m_rackTimerMode == RackTimerMode::REORDERING)
        return;

    const simtime_t srtt = getPacedAlgorithm()->getRtt();
    simtime_t pto = srtt > SIMTIME_ZERO ? srtt * 2 : SimTime(1, SIMTIME_S);
    const uint32_t flightSize = state->snd_max - state->snd_una;
    if (flightSize <= state->snd_mss)
        pto += SimTime(200, SIMTIME_MS);
    else
        pto += SimTime(2, SIMTIME_MS);

    simtime_t expiry = simTime() + pto;
    simtime_t rtoExpiry = getPacedAlgorithm()->getRexmitTimerExpiry();
    if (rtoExpiry != SIMTIME_MAX && rtoExpiry <= expiry) {
        const simtime_t timerEpsilon(1, SIMTIME_NS);
        if (rtoExpiry <= simTime() + timerEpsilon)
            return;
        expiry = rtoExpiry - timerEpsilon;
    }

    armRackTimer(RackTimerMode::LOSS_PROBE, expiry - simTime());
}

void TcpPacedConnection::sendTailLossProbe()
{
    if (!rack_enabled || !state->sack_enabled || state->lossRecovery || isInRtoRecovery() ||
            state->afterRto || state->snd_una == state->snd_max ||
            rexmitQueue->getTotalAmountOfSackedBytes() != 0 ||
            m_tlpProbeOutstanding) {
        return;
    }

    if (m_tlpHasSentProbe && m_rttSampleGeneration <= m_tlpLastProbeRttGeneration) {
        getPacedAlgorithm()->restartRexmitTimer();
        return;
    }

    uint32_t probeBegin = 0;
    uint32_t probeEnd = 0;
    uint32_t sentBytes = 0;
    bool retransmission = false;

    const uint32_t unsentBytes = sendQueue->getBytesAvailable(state->snd_max);
    const uint32_t flightSize = state->snd_max - state->snd_una;
    const uint32_t availableRwnd = flightSize < state->snd_wnd ? state->snd_wnd - flightSize : 0;
    const uint32_t newDataBytes = std::min(unsentBytes, state->snd_mss);

    if (newDataBytes > 0 && availableRwnd >= newDataBytes) {
        probeBegin = state->snd_max;
        sentBytes = sendSegmentDuringLossRecoveryPhase(probeBegin);
        probeEnd = probeBegin + sentBytes;
    }
    else {
        probeEnd = rexmitQueue->getBufferEndSeq();
        if (!rexmitQueue->findRegion(probeEnd)) {
            getPacedAlgorithm()->restartRexmitTimer();
            return;
        }

        const auto& tailRegion = rexmitQueue->getRegion(probeEnd);
        probeBegin = tailRegion.endSeqNum - tailRegion.beginSeqNum > state->snd_mss ?
                tailRegion.endSeqNum - state->snd_mss : tailRegion.beginSeqNum;
        sentBytes = sendSegmentDuringLossRecoveryPhase(probeBegin);
        probeEnd = probeBegin + sentBytes;
        retransmission = sentBytes > 0;
        if (retransmission)
            totalRetransmittedBytesCounter += sentBytes;
    }

    if (sentBytes == 0) {
        getPacedAlgorithm()->restartRexmitTimer();
        return;
    }

    m_tlpProbeOutstanding = true;
    m_tlpIsRetransmission = retransmission;
    m_tlpProbeBeginSeq = probeBegin;
    m_tlpEndSeq = probeEnd;
    m_tlpLastProbeRttGeneration = m_rttSampleGeneration;
    m_tlpHasSentProbe = true;

    EV_INFO << "Sent " << (retransmission ? "retransmitted" : "new-data")
            << " TLP probe [" << probeBegin << ".." << probeEnd << ")\n";
    getPacedAlgorithm()->restartRexmitTimer();
}

bool TcpPacedConnection::processTailLossProbeAck(uint32_t ackNo, bool pureDuplicateAck, bool dsackForProbe)
{
    if (!m_tlpProbeOutstanding || seqLess(ackNo, m_tlpEndSeq))
        return false;

    if (!m_tlpIsRetransmission || dsackForProbe) {
        clearTailLossProbe(false);
        return false;
    }

    if (seqGreater(ackNo, m_tlpEndSeq)) {
        rexmitQueue->clearRecentLossSample();
        bool markedLost = rexmitQueue->markRegionLostByEndSeq(m_tlpEndSeq, true);
        if (markedLost) {
            updateLossNotificationSample();
            getPacedAlgorithm()->notifyLost();
        }
        clearTailLossProbe(false);
        return markedLost;
    }

    if (pureDuplicateAck)
        clearTailLossProbe(false);
    return false;
}

bool TcpPacedConnection::checkRackLoss(bool *newLossDetected)
{
    return checkRackLoss(newLossDetected, false);
}

bool TcpPacedConnection::checkRackLoss(bool *newLossDetected, bool forceScan)
{
    if (!rack_enabled || !rexmitQueue->isUpdatedSackEnabled())
        return false;

    // Match Linux tcp_rack_mark_lost(): an ACK-path scan needs newly
    // delivered evidence. Timer expiry calls this with forceScan=true.
    if (!forceScan && !m_rack->consumeAdvanced()) {
        if (newLossDetected)
            *newLossDetected = false;
        return false;
    }

    if (!m_tlpProbeOutstanding && rexmitQueue->getTotalAmountOfSackedBytes() != 0)
        clearRackTimer(RackTimerMode::LOSS_PROBE);

    double timeout = 0.0;
    bool enterRecovery = false;
    bool markedLoss = false;
    rexmitQueue->clearRecentLossSample();
    if (rexmitQueue->checkRackLoss(m_rack, timeout)) {
        markedLoss = true;
        updateLossNotificationSample();
        getPacedAlgorithm()->notifyLost();
        clearTailLossProbe(true);
    }

    if (newLossDetected)
        *newLossDetected = markedLoss;

    if (rexmitQueue->getLost() != 0 && !state->lossRecovery)
        enterRecovery = true;

    if (timeout > 0) {
        if ((simTime() + timeout) > simTime())
            armRackTimer(RackTimerMode::REORDERING, timeout);
    }
    else
        clearRackTimer(RackTimerMode::REORDERING);
    return enterRecovery;
}

bool TcpPacedConnection::isInRtoRecovery() const
{
    return !state->lossRecovery && state->recoveryPoint != 0 &&
            seqLess(state->snd_una, state->recoveryPoint);
}

bool TcpPacedConnection::shouldApplyRackCongestionResponse() const
{
    return !isInRtoRecovery();
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
