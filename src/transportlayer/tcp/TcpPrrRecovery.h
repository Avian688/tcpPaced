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

#ifndef INET_TRANSPORTLAYER_TCP_FLAVOURS_TCPPRRRECOVERY_H_
#define INET_TRANSPORTLAYER_TCP_FLAVOURS_TCPPRRRECOVERY_H_

#include "TcpPacedConnection.h"

namespace inet {
namespace tcp {

class TcpPrrRecovery
{
protected:
    TcpConnection *conn = nullptr;

public:
    TcpPrrRecovery();
    virtual ~TcpPrrRecovery();

    virtual void setConnection(TcpConnection *_conn) { conn = _conn; }

    uint32_t enterRecovery(uint32_t deliveredBytes);

    uint32_t doRecovery(uint32_t deliveredBytes, bool isDupAck);

    void exitRecovery();

    void updateBytesSent(uint32_t bytesSent);
private:
    uint32_t m_prrDelivered{0};       //!< total bytes delivered during recovery phase
    uint32_t m_prrOut{0};             //!< total bytes sent during recovery phase
    uint32_t m_recoveryFlightSize{0}; //!< value of bytesInFlight at the start of recovery phase
};

} // namespace tcp
} // namespace inet

#endif /* TRANSPORTLAYER_TCP_FLAVOURS_TCPPRRRECOVERY_H_ */
