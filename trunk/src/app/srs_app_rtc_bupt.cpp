/*
This file contains helper-classes implementations for bupt-srs.
*/

#include <srs_app_rtc_bupt.hpp>
#include <iostream>
#include <sys/time.h>

#define MIN_TPT_UPDATE_PERIOD 5

using namespace std;

SrsBuptMonitor::SrsBuptMonitor() : recv_tpt_stat(),
                                   sent_tpt_stat(),
                                   recv_loss_rate() {
    delay_ = -1;
    inboundRtt_ = -1;
    // other complex initializations
}

SrsBuptMonitor::~SrsBuptMonitor() {
    for (auto& it : recv_loss_rate) {
        delete it.second;
        it.second = NULL;
    }
}

// NOTE: may be optimized via inline functions.
void SrsBuptMonitor::add_bytes_recv(uint64_t recv) {
    recv_tpt_stat.total_bytes += recv;
}

void SrsBuptMonitor::add_bytes_sent(uint64_t sent) {
    sent_tpt_stat.total_bytes += sent;
}

double SrsBuptMonitor::get_recv_throughput() {
    update_throughput(recv_tpt_stat);
    return recv_tpt_stat.throughput;
}

double SrsBuptMonitor::get_sent_throughput() {
    update_throughput(sent_tpt_stat);
    return sent_tpt_stat.throughput;
}

void SrsBuptMonitor::update_loss_stat(uint32_t ssrc, uint32_t seq, uint64_t transmitted, uint64_t retrans) {
    if(recv_loss_rate.find(ssrc) == recv_loss_rate.end()){
        if(seq == 4294967295)
            return;
        LossRateStat* loss =new LossRateStat();
        loss->highest_seq = seq;
        loss->last_highest_seq = loss->highest_seq;
        loss->transmitted_packets = transmitted;
        loss->last_transmitted_packets = loss->transmitted_packets;
        loss->retrans_packets = retrans;
        loss->last_retrans_packets = loss->retrans_packets;
        loss->timestamp = get_timestamp_ms();
        recv_loss_rate.insert(make_pair(ssrc, loss));
        
        return;
    }
    LossRateStat* loss = recv_loss_rate.find(ssrc)->second;
    loss->highest_seq = seq;
    loss->transmitted_packets = transmitted;
    loss->retrans_packets = retrans;
}

double SrsBuptMonitor::get_total_loss_rate(uint32_t ssrc) {
    //放弃计算总均值，仅保留接口
    return -1;
    // if(recv_loss_rate.find(ssrc) != recv_loss_rate.end())
    //     return recv_loss_rate.find(ssrc)->second->total_loss_rate;
    // else
    //     return -1;
}

double SrsBuptMonitor::get_fraction_loss_rate(uint32_t ssrc) {
    if(recv_loss_rate.find(ssrc) == recv_loss_rate.end())
        return -1;
    LossRateStat* loss = recv_loss_rate.find(ssrc)->second;
    uint64_t expect_total_trans = loss->highest_seq > loss->last_highest_seq ? 
                                    loss->highest_seq - loss->last_highest_seq : 0;
    uint64_t transmitted = loss->transmitted_packets > loss->last_transmitted_packets ? 
                            loss->transmitted_packets - loss->last_transmitted_packets : 0;
    uint64_t retrans = loss->retrans_packets > loss->last_retrans_packets ? 
                        loss->retrans_packets - loss->last_retrans_packets : 0;
    uint64_t pure_trans = transmitted - retrans;
    uint64_t lost_packets = expect_total_trans > pure_trans ? expect_total_trans - pure_trans : 0;
    if(expect_total_trans == 0)
        loss->fraction_loss_rate = 0;
    else
        loss->fraction_loss_rate = (double)lost_packets / (double)expect_total_trans;
    loss->timestamp = get_timestamp_ms();
    loss->last_highest_seq = loss->highest_seq;
    loss->last_transmitted_packets = loss->transmitted_packets;
    loss->last_retrans_packets = loss->retrans_packets;
    return loss->fraction_loss_rate;
}

void SrsBuptMonitor::update_rtt(uint32_t ssrc, int rtt) {
    recv_rtt[ssrc] = rtt;
}

int SrsBuptMonitor::get_rtt(uint32_t ssrc) {
    if (recv_rtt.find(ssrc) != recv_rtt.end())
        return recv_rtt.find(ssrc)->second;
    else
        return -1;
}

void SrsBuptMonitor::update_delay(int delay) {
    delay_ = delay;
}

int SrsBuptMonitor::get_delay() {
    return delay_;
}

void SrsBuptMonitor::update_inboundRtt(int inboundRtt) {
    inboundRtt_ = inboundRtt;
}

int SrsBuptMonitor::get_inboundRtt() {
    return inboundRtt_;
}

void SrsBuptMonitor::update_jitter(uint32_t ssrc, int jitter) {
    ssrc_jitter_map[ssrc] = jitter;
}

int SrsBuptMonitor::get_jitter(uint32_t ssrc) {
    return ssrc_jitter_map.find(ssrc) != ssrc_jitter_map.end() ? ssrc_jitter_map[ssrc] : -1;
}

void SrsBuptMonitor::update_throughput(ThroughputStat& stat) {
    uint64_t cur_timestamp_ms = get_timestamp_ms();

    if (stat.last_update_time > 0) {
        if (cur_timestamp_ms - stat.last_update_time < MIN_TPT_UPDATE_PERIOD) {
            return ;
        } else {
            // Kbps
            stat.throughput =
                (double)(stat.total_bytes - stat.last_total_bytes) / (cur_timestamp_ms - stat.last_update_time) * 8;
        }
    }

    stat.last_update_time = cur_timestamp_ms;
    stat.last_total_bytes = stat.total_bytes;
}

uint64_t SrsBuptMonitor::get_timestamp_ms() {
    struct timeval tv;    
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;  
}

size_t SrsBuptHttpClient::write_response(void *ptr, size_t size, size_t nmemb, void *user_data)
{
    string* pBuffer = (string*)user_data;
    size_t length = size * nmemb;
    pBuffer->append((char*)ptr, length);

    return length;
}

std::string SrsBuptHttpClient::curl_http_request(string ip,
                                                 int port,
                                                 string api,
                                                 string method,
                                                 string data) {
    CURL *curl;
    CURLcode res;
    string strResponse;
    string req_url = "http://" + ip + ":"+ to_string(port) + api;
    srs_trace("[BUPT DEBUG] http_request url: %s",req_url.c_str());
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method.c_str());
        curl_easy_setopt(curl, CURLOPT_URL, req_url.c_str());
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Pragma: no-cache");
        headers = curl_slist_append(headers, "Cache-Control: no-cache");
        headers = curl_slist_append(headers, "sec-ch-ua-mobile: ?0");
        headers = curl_slist_append(headers, "Origin: http://localhost:8080");
        headers = curl_slist_append(headers, "Sec-Fetch-Site: same-site");
        headers = curl_slist_append(headers, "Sec-Fetch-Mode: cors");
        headers = curl_slist_append(headers, "Sec-Fetch-Dest: empty");
        headers = curl_slist_append(headers, "Referer: http://localhost:8080/");
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        if(method == "POST"){
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
            srs_trace("[BUPT DEBUG] http_request data: %s",data.c_str());
        }
        srs_trace("[BUPT DEBUG] http_request2: %s",method.c_str());
	    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response);
	    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &strResponse);
        res = curl_easy_perform(curl);
    }
    if(res != 0){
        strResponse = "";
    }
    curl_easy_cleanup(curl);
    return strResponse;
}

