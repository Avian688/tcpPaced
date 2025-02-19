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

#include "../TcpPacedConnection.h"
#include "inet/transportlayer/tcp/flavours/TcpTahoeRenoFamily.h"

namespace inet {
namespace tcp {
/**
 * Provides utility functions to implement TcpPacedFamily.
 */
class TcpPacedFamily : public TcpTahoeRenoFamily
{
  public:
    /** Ctor */
    TcpPacedFamily();

    virtual bool sendData(bool sendCommandInvoked) override;

    virtual uint32_t getCwnd() { return state->snd_cwnd;};

  protected:

    virtual void processRexmitTimer(TcpEventCode& event) override;
};

} // namespace tcp
} // namespace inet

#endif
