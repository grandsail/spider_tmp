//
// Copyright (c) 2013-2021 Winlin
//
// SPDX-License-Identifier: MIT
//

#ifndef SRS_KERNEL_RTC_RTP_HPP
#define SRS_KERNEL_RTC_RTP_HPP

#include <srs_core.hpp>

#include <srs_kernel_buffer.hpp>
#include <srs_kernel_codec.hpp>

#include <string>
#include <list>
#include <vector>

class SrsRtpPacket;

// The RTP packet max size, should never exceed this size.
const int kRtpPacketSize        = 1500;

const int kRtpHeaderFixedSize   = 12;
const uint8_t kRtpMarker        = 0x80;

// H.264 nalu header type mask.
const uint8_t kNalTypeMask      = 0x1F;

// @see: https://tools.ietf.org/html/rfc6184#section-5.2
const uint8_t kStapA            = 24;

// @see: https://tools.ietf.org/html/rfc6184#section-5.2
const uint8_t kFuA              = 28;

// @see: https://tools.ietf.org/html/rfc6184#section-5.8
const uint8_t kStart            = 0x80; // Fu-header start bit
const uint8_t kEnd              = 0x40; // Fu-header end bit


class SrsBuffer;
class SrsRtpRawPayload;
class SrsRtpFUAPayload2;
class SrsSharedPtrMessage;
class SrsRtpExtensionTypes;

// Fast parse the SSRC from RTP packet. Return 0 if invalid.
uint32_t srs_rtp_fast_parse_ssrc(char* buf, int size);
uint8_t srs_rtp_fast_parse_pt(char* buf, int size);
srs_error_t srs_rtp_fast_parse_twcc(char* buf, int size, uint8_t twcc_id, uint16_t& twcc_sn);

// NOTEG 以下注释有误
// The "distance" between two uint16 number, for example:
//      distance(prev_value=3, value=5) === (int16_t)(uint16_t)((uint16_t)3-(uint16_t)5) === -2
//      distance(prev_value=3, value=65534) === (int16_t)(uint16_t)((uint16_t)3-(uint16_t)65534) === 5
//      distance(prev_value=65532, value=65534) === (int16_t)(uint16_t)((uint16_t)65532-(uint16_t)65534) === -2
// For RTP sequence, it's only uint16 and may flip back, so 3 maybe 3+0xffff.
// @remark Note that srs_rtp_seq_distance(0, 32768)>0 is TRUE by https://mp.weixin.qq.com/s/JZTInmlB9FUWXBQw_7NYqg
//      but for WebRTC jitter buffer it's FALSE and we follow it.
// @remark For srs_rtp_seq_distance(32768, 0)>0, it's FALSE definitely.

// value在序号上在pre_value之后，则返回值大于0
inline int16_t srs_rtp_seq_distance(const uint16_t& prev_value, const uint16_t& value)
{
    return (int16_t)(value - prev_value);
}

// For map to compare the sequence of RTP.
struct SrsSeqCompareLess {
    bool operator()(const uint16_t& pre_value, const uint16_t& value) const {
        return srs_rtp_seq_distance(pre_value, value) > 0;
    }
};

bool srs_seq_is_newer(uint16_t value, uint16_t pre_value);
bool srs_seq_is_rollback(uint16_t value, uint16_t pre_value);
int32_t srs_seq_distance(uint16_t value, uint16_t pre_value);

enum SrsRtpExtensionType
{
    kRtpExtensionNone,
    kRtpExtensionTransportSequenceNumber,
    kRtpExtensionAudioLevel,
    kRtpExtensionSubStreamTrans,
    kRtpExtensionPacketFec,
    kRtpExtensionSendTime,
    kRtpExtensionNumberOfExtensions  // Must be the last entity in the enum.
};

const std::string kAudioLevelUri = "urn:ietf:params:rtp-hdrext:ssrc-audio-level";
const std::string kSubStreamTransUri = "bupt:sub-stream-transmission";
const std::string kPacketFec = "bupt:packet-fec";
const std::string kSendTime = "bupt:send_time";

struct SrsExtensionInfo
{
    SrsRtpExtensionType type;
    std::string uri;
};

const SrsExtensionInfo kExtensions[] = {
    {kRtpExtensionTransportSequenceNumber, std::string("http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01")},
    {kRtpExtensionAudioLevel, kAudioLevelUri},
    {kRtpExtensionSubStreamTrans, kSubStreamTransUri},
    {kRtpExtensionPacketFec, kPacketFec},
    {kRtpExtensionSendTime, kSendTime}
};

class SrsRtpExtensionTypes
{
public:
    static const SrsRtpExtensionType kInvalidType = kRtpExtensionNone;
    static const int kInvalidId = 0;
public:
    // NOTEG: ids_每个栏位都被默认设置为空，需要通过register_by_uri注册生效对应的类型
    // 强制生效只影响 ids_ 不会影响 exists() 和扩展头的长度计算
    bool register_by_uri(int id, std::string uri);
    SrsRtpExtensionType get_type(int id) const;
public:
    SrsRtpExtensionTypes();
    virtual ~SrsRtpExtensionTypes();
private:
    bool register_id(int id, SrsRtpExtensionType type, std::string uri);
private:
    uint8_t ids_[kRtpExtensionNumberOfExtensions];
};

// Note that the extensions should never extends from any class, for performance.
class SrsRtpExtensionTwcc// : public ISrsCodec
{
    bool has_twcc_;
    uint8_t id_;
    uint16_t sn_;
public:
    SrsRtpExtensionTwcc();
    virtual ~SrsRtpExtensionTwcc();
public:
    inline bool exists() { return has_twcc_; } // SrsRtpExtensionTwcc::exists
    uint8_t get_id();
    void set_id(uint8_t id);
    uint16_t get_sn();
    void set_sn(uint16_t sn);
public:
    // ISrsCodec
    virtual srs_error_t decode(SrsBuffer* buf);
    virtual srs_error_t encode(SrsBuffer* buf);
    virtual uint64_t nb_bytes();
};

// MARKG: SrsRtpExtensionSubStreamTrans defination and methods
class SrsRtpExtensionSubStreamTrans
{
    // default form is one-byte, leave uint8_t id_ for future use
    bool has_sst_;
    uint8_t id_;
    // original sequence number 
    uint16_t osn_; 
    // sub stream number, for example: 0, 1, 2
    uint8_t snum_;
    // total degree of sub streams, for example: 3
    uint8_t sdegree_;
public:
    SrsRtpExtensionSubStreamTrans();
    virtual ~SrsRtpExtensionSubStreamTrans();
public:
    inline bool exists() { return has_sst_; } // SrsRtpExtensionSubStream:exists
    void drop_sst() { has_sst_ = false; }
    uint8_t get_id();
    void set_id(uint8_t id);
    uint16_t get_osn();
    void set_osn(uint16_t osn);
    uint8_t get_snum();
    void set_snum(uint8_t snum);
    uint8_t get_sdegree();
    void set_sdegree(uint8_t sdegree);
public:
    // ISrsCodec
    // plaintext(buffer) to object
    virtual srs_error_t decode(SrsBuffer* buf);
    // object to plaintext(buffer)
    virtual srs_error_t encode(SrsBuffer* buf);
    // return number of bytes the extension occupied
    virtual uint64_t nb_bytes();
};

class SrsRtpExtensionPacketFec
{
    bool has_pf_;
    uint8_t id_;

    // packet number of current packet (8 bit integer)
    int8_t pno_;
    // fec group number of current packet (16 bit unsigned integer)
    uint16_t gno_;
public:
    SrsRtpExtensionPacketFec();
    virtual ~SrsRtpExtensionPacketFec();
public:
    inline bool exsits() { return has_pf_; }
    void drop_pf() { has_pf_ = false; }
    uint8_t get_id() { return id_; }
    void set_id(uint8_t id) { id_ = id; has_pf_ = true; }

    int8_t get_packet_number() { return pno_; }
    uint16_t get_group_number() { return gno_; }
    void set_packet_number(const int8_t &pno) { pno_ = pno; has_pf_ = true; }
    void set_group_number(const uint16_t &gno) { gno_ = gno; has_pf_ = true; }
public:
    virtual srs_error_t decode(SrsBuffer *buf);
    virtual srs_error_t encode(SrsBuffer *buf);
    virtual uint64_t nb_bytes();
};

class SrsRtpExtensionSendTime
{
    bool has_sendtime_;
    uint8_t id_;
    uint64_t time_; //send time of current packet
public:
    SrsRtpExtensionSendTime();
    virtual ~SrsRtpExtensionSendTime();
public:
    inline bool exists() { return has_sendtime_; }
    void drop_sendtime() { has_sendtime_ = false; }
    uint8_t get_id() { return id_; }
    void set_id(uint8_t id) { id_ = id; has_sendtime_ = true; }

    uint64_t get_time() { return time_; }
    void set_time(uint64_t time) { time_ = time; has_sendtime_ = true; }
public:
    virtual srs_error_t decode(SrsBuffer *buf);
    virtual srs_error_t encode(SrsBuffer *buf);
    virtual uint64_t nb_bytes();
};
// --------------------   MARKG   --------------------

// Note that the extensions should never extends from any class, for performance.
class SrsRtpExtensionOneByte// : public ISrsCodec
{
    bool has_ext_;
    int id_;
    uint8_t value_;
public:
    SrsRtpExtensionOneByte();
    virtual ~SrsRtpExtensionOneByte();
public:
    inline bool exists() { return has_ext_; } // SrsRtpExtensionOneByte::exists
    int get_id() { return id_; }
    uint8_t get_value() { return value_; }
    void set_id(int id);
    void set_value(uint8_t value);
public:
    // ISrsCodec
    virtual srs_error_t decode(SrsBuffer* buf);
    virtual srs_error_t encode(SrsBuffer* buf);
    virtual uint64_t nb_bytes() { return 2; };
};

// Note that the extensions should never extends from any class, for performance.
class SrsRtpExtensions// : public ISrsCodec
{
// BUPT section
public:
    void trace_sst_info(uint16_t sn);
    void trace_pf_info(uint16_t sn);
    void trace_sendtime_info(uint16_t sn);
private:
    bool has_ext_;
    // by default, twcc isnot decoded. Because it is decoded by fast function(srs_rtp_fast_parse_twcc)
    bool decode_twcc_extension_;
private:
    // The extension types is used to decode the packet, which is reference to
    // the types in publish stream.
    SrsRtpExtensionTypes* types_;
private:
    SrsRtpExtensionTwcc twcc_;
    SrsRtpExtensionOneByte audio_level_;
    SrsRtpExtensionSubStreamTrans sst_;
    SrsRtpExtensionPacketFec pf_;
    SrsRtpExtensionSendTime sendtime_;
public:
    SrsRtpExtensions();
    virtual ~SrsRtpExtensions();
public:
    void enable_twcc_decode() { decode_twcc_extension_ = true; } // SrsRtpExtensions::enable_twcc_decode
    inline bool exists() { return has_ext_; } // SrsRtpExtensions::exists
    void set_types_(SrsRtpExtensionTypes* types);
    srs_error_t get_twcc_sequence_number(uint16_t& twcc_sn);
    srs_error_t set_twcc_sequence_number(uint8_t id, uint16_t sn);
    srs_error_t get_audio_level(uint8_t& level);
    srs_error_t set_audio_level(int id, uint8_t level);
    // BUPT section
    srs_error_t get_sst_original_sn(uint16_t& osn);
    srs_error_t set_sst_original_sn(uint8_t id, uint16_t osn);
    srs_error_t get_sst_info(uint16_t& osn, uint8_t& snum, uint8_t& sdegree);
    srs_error_t set_sst_info(uint8_t id, uint16_t osn, uint8_t snum, uint8_t sdegree);
    srs_error_t get_pf_info(int8_t &pno, uint16_t &gno);
    srs_error_t get_pf_pno(int8_t &pno);
    srs_error_t get_pf_gno(uint16_t &gno);
    srs_error_t set_pf_info(uint8_t id, int8_t pno, uint16_t gno);
    srs_error_t get_sendtime_info(uint64_t &time);
    srs_error_t set_sendtime_info(uint8_t id, uint64_t time);
    // NOTEG: 删除单个扩展头时注意其他扩展头
    void drop_sst();
    void drop_pf();
    void drop_sendtime();
    void drop_all_extensions() { sst_.drop_sst(); pf_.drop_pf(); sendtime_.drop_sendtime(); has_ext_ = false; };
// ISrsCodec
public:
    virtual srs_error_t decode(SrsBuffer* buf);
private:
    // NOTEG: two-bytes格式不支持（直接跳过）, 只使用decode_0xbede解码one-byte格式
    srs_error_t decode_0xbede(SrsBuffer* buf);
public:
    virtual srs_error_t encode(SrsBuffer* buf);
    virtual uint64_t nb_bytes();
};

// Note that the header should never extends from any class, for performance.
class SrsRtpHeader// : public ISrsCodec
{
// BUPT section
public:
    bool check_sequence_log_point(int devider);
    void trace_sst_info();
    bool has_ext();
    srs_error_t move_sst_osn_to_sn();
    srs_error_t set_sst_new_sn(uint16_t base_sn, int sdegree);
public:
    uint8_t padding_length;
    uint8_t cc;
    bool marker;
    uint8_t payload_type;
    uint16_t sequence;
    uint32_t timestamp;
    uint32_t ssrc;
    uint32_t csrc[15];
    SrsRtpExtensions extensions_;
    bool ignore_padding_;
public:
    SrsRtpHeader();
    virtual ~SrsRtpHeader();
public:
    virtual srs_error_t decode(SrsBuffer* buf);
private:
    srs_error_t parse_extensions(SrsBuffer* buf);
public:
    virtual srs_error_t encode(SrsBuffer* buf);
    virtual uint64_t nb_bytes();
public:
    void enable_twcc_decode() { extensions_.enable_twcc_decode(); } // SrsRtpHeader::enable_twcc_decode
    void set_marker(bool v);
    bool get_marker() const;
    void set_payload_type(uint8_t v);
    uint8_t get_payload_type() const;
    void set_sequence(uint16_t v);
    uint16_t get_sequence() const;
    void set_timestamp(uint32_t v);
    uint32_t get_timestamp() const;
    void set_ssrc(uint32_t v);
    inline uint32_t get_ssrc() const { return ssrc; } // SrsRtpHeader::get_ssrc
    void set_padding(uint8_t v);
    uint8_t get_padding() const;
    void set_extensions(SrsRtpExtensionTypes* extmap);
    void ignore_padding(bool v);
    // NOTEG: 此处的get和set未被实际使用
    srs_error_t get_twcc_sequence_number(uint16_t& twcc_sn);
    srs_error_t set_twcc_sequence_number(uint8_t id, uint16_t sn);
    srs_error_t get_sst_original_sn(uint16_t& osn);
    srs_error_t set_sst_original_sn(uint8_t id, uint16_t osn);
    srs_error_t get_sst_info(uint16_t& osn, uint8_t& snum, uint8_t& sdegree);
    srs_error_t set_sst_info(uint8_t id, uint16_t osn, uint8_t snum, uint8_t sdegree);
    srs_error_t get_pf_info(int8_t &pno, uint16_t &gno);
    int8_t get_pf_pno();
    uint16_t get_pf_gno();
    srs_error_t set_pf_info(uint8_t id, int8_t pno, uint16_t gno);
    srs_error_t set_sendtime_info(uint8_t id, uint64_t time);
    srs_error_t get_sendtime_info(uint64_t& time);
    void drop_sst() { extensions_.drop_sst(); }
    void drop_pf() { extensions_.drop_pf(); }
    void drop_sendtime() { extensions_.drop_sendtime(); }
    void drop_all_extensions() { extensions_.drop_all_extensions(); }
};

// The common payload interface for RTP packet.
class ISrsRtpPayloader : public ISrsCodec
{
public:
    ISrsRtpPayloader();
    virtual ~ISrsRtpPayloader();
public:
    virtual ISrsRtpPayloader* copy() = 0;
};

// The payload type, for performance to avoid dynamic cast.
enum SrsRtspPacketPayloadType
{
    SrsRtspPacketPayloadTypeRaw,
    SrsRtspPacketPayloadTypeFUA2,
    SrsRtspPacketPayloadTypeFUA,
    SrsRtspPacketPayloadTypeNALU,
    SrsRtspPacketPayloadTypeSTAP,
    SrsRtspPacketPayloadTypeUnknown,
};

class ISrsRtspPacketDecodeHandler
{
public:
    ISrsRtspPacketDecodeHandler();
    virtual ~ISrsRtspPacketDecodeHandler();
public:
    // We don't know the actual payload, so we depends on external handler.
    virtual void on_before_decode_payload(SrsRtpPacket* pkt, SrsBuffer* buf, ISrsRtpPayloader** ppayload, SrsRtspPacketPayloadType* ppt) = 0;
};

// The RTP packet with cached shared message.
class SrsRtpPacket
{
// BUPT section
public:
    bool check_sequence_log_point(int devider);
    bool is_equal_to(SrsRtpPacket *pkt);
    void refresh_cached_payload_size() { cached_payload_size = 0; nb_bytes(); };
// RTP packet fields.
public:
    SrsRtpHeader header;
private:
    // using SrsRtpRawPayload by default
    ISrsRtpPayloader* payload_;
    SrsRtspPacketPayloadType payload_type_;
private:
    // The original shared message, all RTP packets can refer to its data.
    // Note that the size of shared msg, is not the packet size, it's a larger aligned buffer.
    // @remark Note that it may point to the whole RTP packet(for RTP parser, which decode RTP packet from buffer),
    //      and it may point to the RTP payload(for RTMP to RTP, which build RTP header and payload).
    SrsSharedPtrMessage* shared_buffer_;
    // The size of RTP packet or RTP payload.
    int actual_buffer_size_;
// Helper fields.
public:
    // The first byte as nalu type, for video decoder only.
    SrsAvcNaluType nalu_type;
    // The frame type, for RTMP bridger or SFU source.
    SrsFrameType frame_type;
// Fast cache for performance.
private:
    // The cached payload size for packet.
    int cached_payload_size;
    // The helper handler for decoder, use RAW payload if NULL.
    ISrsRtspPacketDecodeHandler* decode_handler;
private:
    int64_t avsync_time_;
public:
    SrsRtpPacket();
    virtual ~SrsRtpPacket();
public:
    // Wrap buffer to shared_message, which is managed by us.
    char* wrap(int size);
    char* wrap(char* data, int size);
    // Wrap the shared message, we copy it.
    char* wrap(SrsSharedPtrMessage* msg);
    // Copy the RTP packet.
    virtual SrsRtpPacket* copy();
public:
    // Parse the TWCC extension, ignore by default.
    void enable_twcc_decode() { header.enable_twcc_decode(); } // SrsRtpPacket::enable_twcc_decode
    // Get and set the payload of packet.
    // @remark Note that return NULL if no payload.
    void set_payload(ISrsRtpPayloader* p, SrsRtspPacketPayloadType pt) { payload_ = p; payload_type_ = pt; }
    ISrsRtpPayloader* payload() { return payload_; }
    // Set the padding of RTP packet.
    void set_padding(int size);
    // Increase the padding of RTP packet.
    void add_padding(int size);
    // Set the decode handler.
    void set_decode_handler(ISrsRtspPacketDecodeHandler* h);
    // Whether the packet is Audio packet.
    bool is_audio();
    // Set RTP header extensions for encoding or decoding header extension
    void set_extension_types(SrsRtpExtensionTypes* v);
    SrsRtspPacketPayloadType get_payload_type() { return payload_type_; };
// interface ISrsEncoder
public:
    virtual uint64_t nb_bytes();
    virtual srs_error_t encode(SrsBuffer* buf);
    virtual srs_error_t decode(SrsBuffer* buf);
public:
    bool is_keyframe();
    void set_avsync_time(int64_t avsync_time) { avsync_time_ = avsync_time; }
    int64_t get_avsync_time() const { return avsync_time_; }
};

// Single payload data.
class SrsRtpRawPayload : public ISrsRtpPayloader
{
public:
    // The RAW payload, directly point to the shared memory.
    // @remark We only refer to the memory, user must free its bytes.
    char* payload;
    int nn_payload;
public:
    SrsRtpRawPayload();
    virtual ~SrsRtpRawPayload();
// interface ISrsRtpPayloader
public:
    virtual uint64_t nb_bytes();
    virtual srs_error_t encode(SrsBuffer* buf);
    virtual srs_error_t decode(SrsBuffer* buf);
    virtual ISrsRtpPayloader* copy();
};

// Multiple NALUs, automatically insert 001 between NALUs.
class SrsRtpRawNALUs : public ISrsRtpPayloader
{
private:
    // We will manage the samples, but the sample itself point to the shared memory.
    std::vector<SrsSample*> nalus;
    int nn_bytes;
    int cursor;
public:
    SrsRtpRawNALUs();
    virtual ~SrsRtpRawNALUs();
public:
    void push_back(SrsSample* sample);
public:
    uint8_t skip_first_byte();
    // We will manage the returned samples, if user want to manage it, please copy it.
    srs_error_t read_samples(std::vector<SrsSample*>& samples, int packet_size);
// interface ISrsRtpPayloader
public:
    virtual uint64_t nb_bytes();
    virtual srs_error_t encode(SrsBuffer* buf);
    virtual srs_error_t decode(SrsBuffer* buf);
    virtual ISrsRtpPayloader* copy();
};

// STAP-A, for multiple NALUs.
class SrsRtpSTAPPayload : public ISrsRtpPayloader
{
public:
    // The NRI in NALU type.
    SrsAvcNaluType nri;
    // The NALU samples, we will manage the samples.
    // @remark We only refer to the memory, user must free its bytes.
    std::vector<SrsSample*> nalus;
public:
    SrsRtpSTAPPayload();
    virtual ~SrsRtpSTAPPayload();
public:
    SrsSample* get_sps();
    SrsSample* get_pps();
// interface ISrsRtpPayloader
public:
    virtual uint64_t nb_bytes();
    virtual srs_error_t encode(SrsBuffer* buf);
    virtual srs_error_t decode(SrsBuffer* buf);
    virtual ISrsRtpPayloader* copy();
};

// FU-A, for one NALU with multiple fragments.
// With more than one payload.
class SrsRtpFUAPayload : public ISrsRtpPayloader
{
public:
    // The NRI in NALU type.
    SrsAvcNaluType nri;
    // The FUA header.
    bool start;
    bool end;
    SrsAvcNaluType nalu_type;
    // The NALU samples, we manage the samples.
    // @remark We only refer to the memory, user must free its bytes.
    std::vector<SrsSample*> nalus;
public:
    SrsRtpFUAPayload();
    virtual ~SrsRtpFUAPayload();
// interface ISrsRtpPayloader
public:
    virtual uint64_t nb_bytes();
    virtual srs_error_t encode(SrsBuffer* buf);
    virtual srs_error_t decode(SrsBuffer* buf);
    virtual ISrsRtpPayloader* copy();
};

// FU-A, for one NALU with multiple fragments.
// With only one payload.
class SrsRtpFUAPayload2 : public ISrsRtpPayloader
{
public:
    // The NRI in NALU type.
    SrsAvcNaluType nri;
    // The FUA header.
    bool start;
    bool end;
    SrsAvcNaluType nalu_type;
    // The payload and size,
    char* payload;
    int size;
public:
    SrsRtpFUAPayload2();
    virtual ~SrsRtpFUAPayload2();
// interface ISrsRtpPayloader
public:
    virtual uint64_t nb_bytes();
    virtual srs_error_t encode(SrsBuffer* buf);
    virtual srs_error_t decode(SrsBuffer* buf);
    virtual ISrsRtpPayloader* copy();
};

#endif
