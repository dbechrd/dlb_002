#scope_module

/**
    Network information for a connection.
    Contains statistics like round trip time (RTT), packet loss %, bandwidth estimates, number of packets sent, received and acked.
    */

struct NetworkInfo
{
    float RTT;                                  ///< Round trip time estimate (milliseconds).
    float packetLoss;                           ///< Packet loss percent.
    float sentBandwidth;                        ///< Sent bandwidth (kbps).
    float receivedBandwidth;                    ///< Received bandwidth (kbps).
    float ackedBandwidth;                       ///< Acked bandwidth (kbps).
    uint64_t numPacketsSent;                    ///< Number of packets sent.
    uint64_t numPacketsReceived;                ///< Number of packets received.
    uint64_t numPacketsAcked;                   ///< Number of packets acked.
};
