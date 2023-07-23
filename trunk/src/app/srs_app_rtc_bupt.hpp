/*
This file contains helper-definitions classes definitions for bupt-srs.
*/

#ifndef SRS_APP_RTC_BUPT_HPP
#define SRS_APP_RTC_BUPT_HPP

#include <stdint.h>
#include <stdio.h>
#include <map>
#include <vector>
#include <srs_kernel_log.hpp>
#include <curl/curl.h>

// helper items
typedef struct ThroughputStat {
    ThroughputStat() {
        total_bytes = 0;
        last_total_bytes = 0;
        last_update_time = 0;
        throughput = 0;
    }
    uint64_t total_bytes;
    uint64_t last_total_bytes;
    uint64_t last_update_time;
    double throughput;
} ThroughputStat;

typedef struct LossRateStat {
    LossRateStat() {
        timestamp =0;
        highest_seq = 0;
        last_highest_seq = 0;
        transmitted_packets = 0;
        last_transmitted_packets =0;
        retrans_packets = 0;
        last_retrans_packets = 0;
        fraction_loss_rate = 0;
    }
    uint64_t timestamp;
    uint32_t highest_seq;
    uint32_t last_highest_seq;
    uint64_t transmitted_packets;
    uint64_t last_transmitted_packets;
    uint64_t retrans_packets;
    uint64_t last_retrans_packets;
    double fraction_loss_rate;
} LossRateStat;


// for performance indicators
// should be binded to SrsRtcConnection(session)
class SrsBuptMonitor {
public:
    SrsBuptMonitor();
    virtual ~SrsBuptMonitor();

    void add_bytes_recv(uint64_t recv);
    void add_bytes_sent(uint64_t sent);
    double get_recv_throughput();
    double get_sent_throughput();

    void update_loss_stat(uint32_t ssrc, uint32_t seq, uint64_t transmitted, uint64_t retrans);
    double get_total_loss_rate(uint32_t ssrc);
    double get_fraction_loss_rate(uint32_t ssrc);

    void update_rtt(uint32_t ssrc, int rtt);
    int get_rtt(uint32_t ssrc);

    void update_jitter(uint32_t ssrc, int jitter);
    int get_jitter(uint32_t ssrc);

    void update_delay(int delay);
    int get_delay();

    void update_inboundRtt(int inboundRtt);
    int get_inboundRtt();

public:
    ThroughputStat recv_tpt_stat;
    ThroughputStat sent_tpt_stat;
    std::map<uint32_t, LossRateStat*> recv_loss_rate;
    std::map<uint32_t, int> recv_rtt;
    std::map<uint32_t, int> ssrc_jitter_map;
    int delay_;
    int inboundRtt_;
    
    void update_throughput(ThroughputStat& stat);
    uint64_t get_timestamp_ms();
};

// For HTTP request
class SrsBuptHttpClient {
public:
    SrsBuptHttpClient();
    virtual ~SrsBuptHttpClient();

    static size_t write_response(void *ptr,
                                 size_t size,
                                 size_t nmemb,
                                 void *user_data);
    static std::string curl_http_request(std::string ip,
                                         int port,
                                         std::string api,
                                         std::string method, std::string data);
};
#endif
