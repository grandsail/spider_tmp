#ifndef SRS_APP_RTC_FEC_HPP
#define SRS_APP_RTC_FEC_HPP

#include <srs_app_rtc_queue.hpp>
#include <srs_kernel_log.hpp>
#include <srs_kernel_rtc_rtp.hpp>
#include <srs_kernel_buffer.hpp>
#include <srs_kernel_error.hpp>
#include "../../3rdparty/schifra/schifra_rs_fec_source.hpp"

class SrsRtpPacket;
class SrsRtpRingBuffer;
class SrsBuffer;

using namespace std;

enum FecMethod
{
    RSFEC,
    SIMPLEXOR,
    NONEMETHOD
};

const int DEFAULT_ORIGIN_NUM = 2;
const int DEFAULT_REDUNDANT_NUM = 1;
const int DEFAULT_FEC_BUFFER_SIZE = (DEFAULT_ORIGIN_NUM + DEFAULT_REDUNDANT_NUM) * 100;
const FecMethod DEFAULT_FEC_METHOD = SIMPLEXOR;
const char EMPTY_CHAR = 0;
const int PF_ID = 10;
const int SendTime_ID = 11;

class SrsFecDecoder
{
public:
    SrsRtpRingBuffer *origin_pkt_buffer_;
    SrsRtpRingBuffer *redundant_pkt_buffer_;
    int origin_num_;
    int redundant_num_;
    uint16_t base_seq_;
    uint16_t convert_seq_;
    FecMethod method_;

public:
    SrsFecDecoder(int queue_size, FecMethod method);
    virtual ~SrsFecDecoder();

private:
    bool check_ready(uint16_t seq);
    // void get_size_list(vector<int> &size_list, int &packet_max_len);

public:
    bool should_decode(SrsRtpPacket *pkt);
    SrsRtpPacket *xor_decode(SrsRtpPacket *pkt);
    srs_error_t put_decode_buffer(SrsRtpPacket *pkt);
};

class SrsFecEncoder
{
public:
    SrsRtpRingBuffer *encode_buffer_;
    int origin_num_;
    int redundant_num_;
    uint16_t base_seq_;
    bool base_is_set_;
    FecMethod method_;

public:
    SrsFecEncoder(int queue_size, FecMethod method);
    virtual ~SrsFecEncoder();

private:
    void get_size_list(vector<int> &size_list, int &packet_max_len);
    bool encode_size_info(vector<int> size_list, char *redundant_pkt_payload);
    void check_init_base_seq(uint16_t seq);

private:
    SrsRtpPacket* simple_xor_encode();

public:
    SrsRtpPacket *put_and_encode(SrsRtpPacket *pkt);
};

#endif