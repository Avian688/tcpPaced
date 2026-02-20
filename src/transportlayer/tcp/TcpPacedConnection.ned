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

package tcppaced.transportlayer.tcp;

import inet.transportlayer.tcp.TcpConnection;

simple TcpPacedConnection extends TcpConnection
{
    parameters:
        @class("inet::tcp::TcpPacedConnection");
         
        @signal[additiveIncrease];
        @signal[minRtt];
        @signal[state];
        @signal[pacingGain];
        @signal[paceRate];
        
        @signal[roundCount];
        @signal[recover];
        @signal[lossRecovery];
        @signal[highRxt];
        @signal[throughput];
        @signal[retransmissionRate];
        
        @signal[mDelivered];
        @signal[mFirstSentTime]; 
        @signal[mLastSentTime]; 
        @signal[mbytesInFlight]; 
        @signal[mbytesInFlightTotal]; 
        @signal[mbytesLoss]; 
        @signal[msendElapsed]; 
        @signal[mackElapsed];

        // Cubic added signals
        @signal[bicTarget];
        @signal[originalPoint];
        @signal[cwndSeg];
        @signal[bicK];
        @signal[cnt];
        @signal[lastMaxWindow];
        @signal[delayMin];
        @signal[concave];
        @signal[convex];
        @signal[friendly];
        @signal[sndUna];
        @signal[recoveryPoint];
        
        
        @statistic[throughput](record=vector; interpolationmode=sample-hold);
        @statistic[retransmissionRate](record=vector; interpolationmode=sample-hold);
        @statistic[additiveIncrease](record=vector; interpolationmode=sample-hold);
        @statistic[state](record=vector; interpolationmode=sample-hold);
        @statistic[pacingGain](record=vector; interpolationmode=sample-hold);
        @statistic[paceRate](record=vector; interpolationmode=sample-hold);
        @statistic[recover](record=vector; interpolationmode=sample-hold);
        @statistic[lossRecovery](record=vector; interpolationmode=sample-hold);
        @statistic[highRxt](record=vector; interpolationmode=sample-hold);
        
        @statistic[mDelivered](record=vector; interpolationmode=sample-hold);
        @statistic[mFirstSentTime](record=vector; interpolationmode=sample-hold);
        @statistic[mLastSentTime](record=vector; interpolationmode=sample-hold);
        @statistic[mbytesInFlight](record=vector; interpolationmode=sample-hold);
        @statistic[mbytesInFlightTotal](record=vector; interpolationmode=sample-hold);
        @statistic[mbytesLoss](record=vector; interpolationmode=sample-hold);
        @statistic[msendElapsed](record=vector; interpolationmode=sample-hold);
        @statistic[mackElapsed](record=vector; interpolationmode=sample-hold);

        // Cubic added statistics
        @statistic[bicTarget](record=vector; interpolationmode=sample-hold);
        @statistic[originalPoint](record=vector; interpolationmode=sample-hold);
        @statistic[cwndSeg](record=vector; interpolationmode=sample-hold);
        @statistic[bicK](record=vector; interpolationmode=sample-hold);
        @statistic[cnt](record=vector; interpolationmode=sample-hold);
        @statistic[lastMaxWindow](record=vector; interpolationmode=sample-hold);
        @statistic[delayMin](record=vector; interpolationmode=sample-hold);
        @statistic[concave](record=vector; interpolationmode=sample-hold);
        @statistic[convex](record=vector; interpolationmode=sample-hold);
        @statistic[friendly](record=vector; interpolationmode=sample-hold);
        @statistic[sndUna](record=vector; interpolationmode=sample-hold);
        @statistic[recoveryPoint](record=vector; interpolationmode=sample-hold);
}
