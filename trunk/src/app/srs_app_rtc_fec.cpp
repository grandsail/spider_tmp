#include <srs_app_rtc_fec.hpp>

SrsFecDecoder::SrsFecDecoder(int queue_size, FecMethod method)
{
    origin_num_ = DEFAULT_ORIGIN_NUM;
    redundant_num_ = DEFAULT_REDUNDANT_NUM;
    if (queue_size % (origin_num_ + redundant_num_) != 0)
    {
        srs_error("fec decoder buffer size must be divisible by (origin_num+redundant_num)");
    }
    origin_pkt_buffer_ = new SrsRtpRingBuffer(queue_size);
    redundant_pkt_buffer_ = new SrsRtpRingBuffer(queue_size);
    convert_seq_ = 0;
    base_seq_ = 0;
    method_ = method;
}

SrsFecDecoder::~SrsFecDecoder()
{
    srs_freep(origin_pkt_buffer_);
    srs_freep(redundant_pkt_buffer_);
    origin_num_ = 0;
    redundant_num_ = 0;
    convert_seq_ = 0;
    method_ = NONEMETHOD;
}

bool SrsFecDecoder::check_ready(uint16_t seq)
{
    if (method_ != SIMPLEXOR)
    {
        srs_warn("fec decoder check ready cannot specify this method");
        return false;
    }

    // TOFIXG: 识别冗余包，计算到达的数目
    SrsRtpPacket *pkt = origin_pkt_buffer_->at(seq);
    if (pkt == NULL)
    {
        srs_error_new(ERROR_FEC_CODEC, "%u seq not found in decode buffer");
        return false;
    }

    int8_t pno = pkt->header.get_pf_pno();
    uint16_t gno = pkt->header.get_pf_gno();

    if (pno < 0 || pno >= origin_num_ + redundant_num_)
    {
        srs_warn("fec decoder find wrong packet number");
        return false;
    }
    SrsRtpPacket *p;
    int ready_num = 0;
    for (uint16_t s = seq - pno; s < seq - pno + origin_num_ + redundant_num_; s++)
    {
        if ((p = origin_pkt_buffer_->at(s)) != NULL)
        {
            ready_num += 1;
        }
    }

    if (ready_num >= origin_num_)
    {
        // printf("<DEBUG> checked ready: seq=%u, pno=%d, ready_num=%d\n", pkt->header.get_sequence(), pno, ready_num);
        return true;
    }
    else
    {
        // printf("<DEBUG> cannot decode: seq=%u, pno=%d, ready_num=%d\n", pkt->header.get_sequence(), pno, ready_num);
        return false;
    }
}

// void SrsFecDecoder::get_size_list(vector<int> &size_list, int &packet_max_len)
// {
//     packet_max_len = 0;
//     for (uint16_t bias = 0; bias < origin_num_; bias ++)
//     {
//         uint16_t seq = base_seq_ + bias;
//         SrsRtpPacket *pkt = origin_pkt_buffer_->at(seq);
//         SrsRtpRawPayload *payload = dynamic_cast<SrsRtpRawPayload *>(pkt->payload());
//         int cur_size = payload->nn_payload;
//         size_list[bias] = cur_size;
//         if (packet_max_len < cur_size)
//             packet_max_len = cur_size;
//     }
//     return;
// }

SrsRtpPacket *SrsFecDecoder::xor_decode(SrsRtpPacket *pkt)
{
    // pkt 不需要是复制后的，但需要保留PF扩展头
    int8_t pno = pkt->header.get_pf_pno();
    uint16_t gno = pkt->header.get_pf_gno();
    if (pno < 0 || pno >= origin_num_ + redundant_num_)
    {
        srs_error("pno error, seq=%u, pno=%d", pkt->header.get_sequence(), pno);
        return NULL;
    }
    pkt->header.drop_all_extensions();
    uint16_t group_first_seq = pkt->header.get_sequence() - pno;
    uint16_t redundant_pkt_seq = group_first_seq + origin_num_;
    // uint16_t not_arrive_seq = group_first_seq + 1; //  DEBUG
    uint16_t not_arrive_seq = redundant_pkt_seq;
    for (uint16_t bias = 0; bias < origin_num_; bias ++)
    {
        uint16_t seq = group_first_seq + bias;
        if (origin_pkt_buffer_->at(seq) == NULL || origin_pkt_buffer_->at(seq)->header.get_sequence() != seq)
        {
            not_arrive_seq = seq;
            break;
        }
    }
    if (not_arrive_seq == redundant_pkt_seq)
    {
        srs_error("should decode check wrong, redundant_pkt_seq=%u", redundant_pkt_seq);
        return NULL;
    }
    SrsRtpPacket *redundant_pkt = redundant_pkt_buffer_->at(redundant_pkt_seq);
    if (redundant_pkt == NULL || redundant_pkt->header.get_sequence() != redundant_pkt_seq)
    {
        srs_error("redundant pkt null or seq miss match in xor decode, redundant_pkt_seq=%u", redundant_pkt_seq);
        return NULL;
    }
    SrsRtpRawPayload *codec_payload = dynamic_cast<SrsRtpRawPayload *>(redundant_pkt->payload());
    if (codec_payload == NULL)
    {
        srs_error("redundant packet payload is null, redundant_pkt_seq=%u", redundant_pkt_seq);
        return NULL;
    }
    char *codec_payload_ptr = codec_payload->payload;
    int origin_num = int(*codec_payload_ptr);
    codec_payload_ptr += 1;
    if (origin_num != origin_num_)
    {
        srs_error("origin num wrong in xor decoding, origin from packet=%d, origin in decoder=%d, redundant_pkt_seq=%u", origin_num, origin_num_, redundant_pkt_seq);
        return NULL;
    }
    vector<int> size_list(origin_num_, 0);
    for (int i = 0; i < origin_num_; i++)
    {
        size_list[i] = (int(*codec_payload_ptr) * 128) + int(*(codec_payload_ptr + 1));
        codec_payload_ptr += 2;
    }

    int not_arrive_size = size_list[uint16_t(not_arrive_seq - group_first_seq)];
    char *new_packet_base = new char[not_arrive_size]{};
    for (int i = 0; i < not_arrive_size; i++)
    {
        new_packet_base[i] = *codec_payload_ptr;
        codec_payload_ptr += 1;
    }
    uint32_t ssrc = 0;
    for (uint16_t bias = 0; bias < origin_num; bias ++)
    {
        uint16_t seq = group_first_seq + bias;
        if (seq == not_arrive_seq)
        {
            continue;
        }
        SrsRtpPacket *pkt = origin_pkt_buffer_->at(seq);
        if (pkt == NULL)
        {
            srs_error("packet at seq=%u is null, group_first_seq=%u", seq, group_first_seq);
            return NULL;
        }
        ssrc = pkt->header.get_ssrc();
        int cur_size = size_list[bias];
        char *packet_base = new char[cur_size];
        SrsBuffer *buf = new SrsBuffer(packet_base, cur_size);
        pkt->encode(buf);
        for (int i = 0; i < not_arrive_size && i < size_list[bias]; i++)
        {
            new_packet_base[i] ^= packet_base[i];
        }
        delete[] packet_base;
    }
    if (ssrc == 0)
    {
        srs_warn("not found proper ssrc for new packet, group_first_seq=%u", group_first_seq);
        return NULL;
    }
    SrsBuffer *buf = new SrsBuffer(new_packet_base, not_arrive_size);
    SrsRtpPacket *new_pkt = new SrsRtpPacket();
    new_pkt->wrap(new_packet_base, not_arrive_size);
    srs_error_t err;
    if ((err = new_pkt->decode(buf)) != srs_success)
    {
        srs_error("xor decode fail, group_first_seq=%u", group_first_seq);
        return NULL;
    }
    new_pkt->header.set_sequence(not_arrive_seq);
    new_pkt->header.set_ssrc(ssrc);

    // printf("<DEBUG> create new packet, seq=%u\n", new_pkt->header.get_sequence());
    return new_pkt;
}

bool SrsFecDecoder::should_decode(SrsRtpPacket *pkt)
{
    // 传入的 pkt 不需要是复制后的结果，但需要保留PF扩展头内容
    int8_t pno = pkt->header.get_pf_pno();
    uint16_t gno = pkt->header.get_pf_gno();
    if (pno < 0 || pno >= origin_num_ + redundant_num_)
    {
        return srs_error_new(ERROR_FEC_CODEC, "cannot get pf pno in put_and_decode, seq=%u", pkt->header.get_sequence());
    }
    uint16_t group_first_seq = pkt->header.get_sequence() - pno;
    int origin_ready_num = 0;
    for (uint16_t bias = 0; bias < origin_num_; bias ++)
    {
        uint16_t seq = group_first_seq + bias;
        if (origin_pkt_buffer_->at(seq) != NULL && seq == origin_pkt_buffer_->at(seq)->header.get_sequence())
        {
            origin_ready_num += 1;
        }
    }

    uint16_t redundant_pkt_seq = group_first_seq + origin_num_;
    if (origin_ready_num == origin_num_)
    {
        // already sent enough packets
        // printf("<DEBUG> send enough packets, seq=%u, pno=%d, gno=%u\n", pkt->header.get_sequence(), pno, gno);
        return false;
    }
    if (origin_ready_num == origin_num_ - 1 && redundant_pkt_buffer_->at(redundant_pkt_seq) != NULL && redundant_pkt_seq == redundant_pkt_buffer_->at(redundant_pkt_seq)->header.get_sequence())
    {
        // printf("<DEBUG> ready to decode, seq=%u, pno=%d, gno=%u\n", pkt->header.get_sequence(), pno, gno);
        return true;
    }
    else
    {
        // printf("<DEBUG> not enough packets for decoding, seq=%u, pno=%d, gno=%u\n", pkt->header.get_sequence(), pno, gno);
        return false;
    }
}

srs_error_t SrsFecDecoder::put_decode_buffer(SrsRtpPacket *pkt)
{
    // 传入的 pkt 必须是复制后的
    srs_error_t err = srs_success;

    uint16_t seq = pkt->header.get_sequence();
    int8_t pno = pkt->header.get_pf_pno();
    pkt->header.drop_all_extensions();
    if (pno < 0 || pno > origin_num_)
    {
        return srs_error_new(ERROR_FEC_CODEC, "pf info wrong, seq=%u, pno=%d", pkt->header.get_sequence(), pno);
    }

    if (pno < origin_num_)
    {
        // ORIGIN PKT
        // printf("<DEBUG> put origin packet into origin buffer, seq=%u, pno=%d\n", pkt->header.get_sequence(), pno);
        origin_pkt_buffer_->set(seq, pkt);
    }
    else
    {
        // REDUNDANT PKT
        // printf("<DEBUG> put redundant packet into redundant buffer, seq=%u, pno=%d\n", pkt->header.get_sequence(), pno);
        redundant_pkt_buffer_->set(seq, pkt);
    }

    return err;
}

SrsFecEncoder::SrsFecEncoder(int queue_size, FecMethod method)
{
    origin_num_ = DEFAULT_ORIGIN_NUM;
    redundant_num_ = DEFAULT_REDUNDANT_NUM;
    if (queue_size % (origin_num_ + redundant_num_) != 0)
    {
        srs_error("fec encoder buffer must be devisible by (origin_num_ + redundant_num_)");
    }
    encode_buffer_ = new SrsRtpRingBuffer(queue_size);
    base_seq_ = 0;
    base_is_set_ = false;
    method_ = method;
}

SrsFecEncoder::~SrsFecEncoder()
{
    delete encode_buffer_;
    origin_num_ = 0;
    redundant_num_ = 0;
    method_ = NONEMETHOD;
}

void SrsFecEncoder::check_init_base_seq(uint16_t seq)
{
    if (!base_is_set_)
    {
        base_seq_ = seq;
        srs_trace("<BTRACE> encoder seq init: base_seq=%u, buffer_capacity=%u", base_seq_, encode_buffer_->capacity_);
    }
    base_is_set_ = true;
}

void SrsFecEncoder::get_size_list(vector<int> &size_list, int &packet_max_len)
{
    packet_max_len = 0;
    for (uint16_t bias = 0; bias < origin_num_; bias ++)
    {
        uint16_t seq = base_seq_ + bias;
        SrsRtpPacket *pkt = encode_buffer_->at(seq);
        if (pkt == NULL)
        {
            srs_error("not found %u in fec encode buffer", seq);
            return;
        }
        int cur_size = pkt->nb_bytes();
        size_list[bias] = cur_size;
        if (packet_max_len < cur_size)
            packet_max_len = cur_size;
    }
    return;
}

bool SrsFecEncoder::encode_size_info(vector<int> size_list, char *redundant_pkt_payload)
{
    /* raw buffer origin num encode
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   origin num  |        packet size 1          |  packet size 2
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      packet size 2 |        packet size 3          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    */
    char *redundant_pkt_ptr = redundant_pkt_payload;
    if ((origin_num_ > 0x00ff) || (origin_num_ < 0))
    {
        srs_error("encode origin num incorrectly");
        return false;
    }
    *redundant_pkt_ptr = (char)origin_num_;
    redundant_pkt_ptr += 1;
    for (int i = 0; i < origin_num_; i++)
    {
        *redundant_pkt_ptr = (char)(size_list[i] / 128);
        redundant_pkt_ptr += 1;
        *redundant_pkt_ptr = (char)(size_list[i] % 128);
        redundant_pkt_ptr += 1;
    }
    return true;
}

SrsRtpPacket *SrsFecEncoder::simple_xor_encode()
{
    // encode a new redundant packet to place (base_seq_+origin_num_)

    int packet_max_len = 0;
    vector<int> size_list(origin_num_, 0);
    get_size_list(size_list, packet_max_len);

    char *redundant_payload_base = new char[origin_num_ * 2 + 1 + packet_max_len]{};
    encode_size_info(size_list, redundant_payload_base);
    for (uint16_t bias = 0; bias < origin_num_; bias ++)
    {
        uint16_t seq = base_seq_ + bias;
        char *redundant_payload_ptr = redundant_payload_base + origin_num_ * 2 + 1;
        SrsRtpPacket *pkt = encode_buffer_->at(seq);
        if (pkt == NULL || pkt->header.get_sequence() != seq)
        {
            srs_error("seq=%u in encoder buffer not match", seq);
        }
        int cur_size = size_list[bias];
        char *packet_base = new char[cur_size];
        SrsBuffer *buf = new SrsBuffer(packet_base, cur_size);
        pkt->encode(buf);
        for (int i = 0; i < cur_size; i++)
        {
            *redundant_payload_ptr = (*redundant_payload_ptr) ^ packet_base[i];
            redundant_payload_ptr += 1;
        }
        delete[] packet_base;
    }

    SrsRtpRawPayload *redundant_payload = new SrsRtpRawPayload();
    redundant_payload->payload = redundant_payload_base;
    redundant_payload->nn_payload = packet_max_len + 1 + origin_num_ * 2;
    SrsRtpPacket *redundant_pkt = new SrsRtpPacket();
    redundant_pkt->set_payload(redundant_payload, SrsRtspPacketPayloadTypeRaw);

    // only support one redundant packet
    return redundant_pkt;
}

SrsRtpPacket *SrsFecEncoder::put_and_encode(SrsRtpPacket *pkt)
{
    // pkt 指针必须是复制后的指针，FEC编码完成后会被释放
    uint16_t cur_seq = pkt->header.get_sequence();
    check_init_base_seq(cur_seq);
    pkt->header.drop_all_extensions();
    pkt->refresh_cached_payload_size();

    encode_buffer_->set(cur_seq, pkt);

    bool encode_ready_flag = false;
    if (srs_rtp_seq_distance(base_seq_, cur_seq) == origin_num_ - 1)
    {
        // ready to encode
        if (method_ == SIMPLEXOR)
        {
            SrsRtpPacket *redundant_pkt = simple_xor_encode();
            for (uint16_t bias = 0; bias < origin_num_; bias++)
            {
                uint16_t seq = base_seq_ + bias;
                encode_buffer_->set(seq, NULL);
            }
            base_seq_ += origin_num_;
            return redundant_pkt;
        }
    }
}
