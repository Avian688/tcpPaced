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
#include <algorithm>

#include "TcpPrrRecovery.h"

namespace inet {
namespace tcp {


TcpPrrRecovery::TcpPrrRecovery() {
    // TODO Auto-generated constructor stub

}

TcpPrrRecovery::~TcpPrrRecovery() {
    // TODO Auto-generated destructor stub
}

uint32_t TcpPrrRecovery::enterRecovery(uint32_t deliveredBytes)
{
    m_prrOut = 0;
    m_prrDelivered = 0;
    m_recoveryFlightSize = dynamic_cast<TcpPacedConnection*>(conn)->getBytesInFlight(); // RFC 6675 pipe before recovery

    return doRecovery(deliveredBytes, true);
}

uint32_t TcpPrrRecovery::doRecovery(uint32_t deliveredBytes, bool isDupAck)
{
    uint32_t bytesInFlight = dynamic_cast<TcpPacedConnection*>(conn)->getBytesInFlight();
    uint32_t ssthresh = dynamic_cast<TcpPacedFamily*>(conn->getTcpAlgorithm())->getSsthresh();
    uint32_t mss = conn->getState()->snd_mss;
    if (isDupAck && m_prrDelivered < m_recoveryFlightSize)
    {
        deliveredBytes += conn->getState()->snd_mss;
    }
    if (deliveredBytes == 0)
    {
        return  dynamic_cast<TcpPacedFamily*>(conn->getTcpAlgorithm())->getCwnd();
    }

    m_prrDelivered += deliveredBytes;

    int sendCount;
    if (bytesInFlight > ssthresh)
    {
        // Proportional Rate Reductions
        sendCount = std::ceil(m_prrDelivered * ssthresh * 1.0 / m_recoveryFlightSize) - m_prrOut;
    }
    else
    {
        // PRR-CRB by default
        int limit = std::max(m_prrDelivered - m_prrOut, deliveredBytes);

        // safeACK should be true iff ACK advances SND.UNA with no further loss indicated.
        // We approximate that here (given the current lack of RACK-TLP in ns-3)
        bool safeACK = dynamic_cast<TcpPacedConnection*>(conn)->getIsRetransDataAcked();

        if (safeACK)
        {
            // PRR-SSRB when recovery makes good progress
            limit += mss;
        }

        // Attempt to catch up, as permitted
        sendCount = std::min((int)limit, (int)(ssthresh - bytesInFlight));
    }

    /* Force a fast retransmit upon entering fast recovery */
    sendCount = std::max(sendCount, static_cast<int>(m_prrOut > 0 ? 0 : mss));
    return bytesInFlight + sendCount;
}

}
}
