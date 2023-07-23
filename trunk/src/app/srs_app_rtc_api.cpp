//
// Copyright (c) 2013-2021 Winlin
//
// SPDX-License-Identifier: MIT
//

#include <srs_app_rtc_api.hpp>

#include <srs_app_rtc_conn.hpp>
#include <srs_app_rtc_server.hpp>
#include <srs_protocol_json.hpp>
#include <srs_core_autofree.hpp>
#include <srs_app_http_api.hpp>
#include <srs_protocol_utility.hpp>
#include <srs_app_config.hpp>
#include <srs_app_statistic.hpp>
#include <srs_app_http_hooks.hpp>
#include <srs_app_utility.hpp>
#include <unistd.h>
#include <deque>
using namespace std;

SrsGoApiRtcSwitch::SrsGoApiRtcSwitch(SrsRtcServer* server)
{
    server_ = server;
}

SrsGoApiRtcSwitch::~SrsGoApiRtcSwitch()
{
}

// Request:
//      POST /rtc/v1/switch/
//      {
//          "session_id" : "xxx",
//          "old_ip": "xxx",
//          "snum": xx,
//          "new_ip": "xxx",
//      }
// Response:
//      {
//          "status": "ok" / "error",
//      }

srs_error_t SrsGoApiRtcSwitch::serve_http(ISrsHttpResponseWriter* w, ISrsHttpMessage* r)
{
    srs_error_t err = srs_success;

    SrsJsonObject* res = SrsJsonAny::object();
    SrsAutoFree(SrsJsonObject, res);

    if ((err = do_serve_http(w, r, res)) != srs_success) {
        srs_warn("RTC error %s", srs_error_desc(err).c_str()); srs_freep(err);
        return srs_api_response_code(w, r, SRS_CONSTS_HTTP_BadRequest);
    }

    return srs_api_response(w, r, res->dumps());
}

srs_error_t SrsGoApiRtcSwitch::do_serve_http(ISrsHttpResponseWriter* w, ISrsHttpMessage* r, SrsJsonObject* res)
{
    cout << "refresh upstream" << endl;
    srs_error_t err = srs_success;

    // For each RTC session, we use short-term HTTP connection.
    SrsHttpHeader* hdr = w->header();
    hdr->set("Connection", "Close");

    // Parse req, the request json object, from body.
    SrsJsonObject* req = NULL;
    SrsAutoFree(SrsJsonObject, req);
    if (true) {
        string req_json;
        if ((err = r->body_read_all(req_json)) != srs_success) {
            return srs_error_wrap(err, "read body");
        }

        SrsJsonAny* json = SrsJsonAny::loads(req_json);
        if (!json || !json->is_object()) {
            return srs_error_new(ERROR_RTC_API_BODY, "invalid body %s", req_json.c_str());
        }

        req = json->to_object();
    }

    SrsJsonAny* prop = NULL;
    if ((prop = req->ensure_property_string("session_id")) == NULL) {
        return srs_error_wrap(err, "no session_id");
    }
    string session_id = prop->to_str();
    if ((prop = req->ensure_property_string("old_ip")) == NULL) {
        return srs_error_wrap(err, "no old_ip");
    }
    string old_ip = prop->to_str();
    if ((prop = req->ensure_property_string("new_ip")) == NULL) {
        return srs_error_wrap(err, "no new_ip");
    }
    string new_ip = prop->to_str();
    if ((prop = req->ensure_property_integer("snum")) == NULL) {
        return srs_error_wrap(err, "no snum");
    }
    int snum = prop->to_integer();
    srs_trace("<BTRACE> session_id=%s, old_ip=%s, new_ip=%s, snum=%d", session_id.c_str(), old_ip.c_str(), new_ip.c_str(), snum);

    SrsRtcConnection* chrome_player_session = server_->find_session_by_username(session_id);
    if (!chrome_player_session) {
        return srs_error_wrap(err, "cannot find session by username %s", session_id.c_str());
    }
    for (SstPublisherSession* sst_publisher : chrome_player_session->sst_publishers_) {
        SrsRtcConnection* session = sst_publisher->sst_publisher_;
        SrsRtcPublishStream* publisher = session->get_first_publish_stream();
        if (publisher->snum_ != snum) {
            continue;
        }
        // 找到snum对应的session
        string upstream_ip = sst_publisher->upstream_ip_;
        srs_trace("<BTRACE> upstream_ip=%s, peer_id=%s, snum=%d", upstream_ip.c_str(), session->get_session_peer_id().c_str(), session->get_first_publish_stream()->snum_);

        // *********** test *********
        // 此处需要signal完成后更改
        // new_ip = upstream_ip;
        old_ip = upstream_ip;
        srs_trace("<BTRACE> switch from %s to %s", old_ip.c_str(), new_ip.c_str());

        //删除原ssrc的键值对，否则切流后track会有四个ssrc
        session->monitor_->recv_rtt.clear();
        session->monitor_->recv_loss_rate.clear();
        session->monitor_->ssrc_jitter_map.clear();

        server_->refresh_upstream(session, new_ip);
        // *********** test *********


        sst_publisher->upstream_ip_ = new_ip;
        static char id_buf[128];
        int len = snprintf(id_buf, sizeof(id_buf), "%s:%d", new_ip.c_str(), 8000);
        string new_peer_id = string(id_buf, len);
        string old_peer_id = session->get_session_peer_id();
        srs_trace("<BDEBUG> refresh peer id: old_peer_id=%s, new_peer_id=%s", old_peer_id.c_str(), new_peer_id.c_str());
        _srs_rtc_manager->replace_conn_id(old_peer_id, new_peer_id);
    }
    
    // NOTEG: 目前没有写res

    return err;
}

SrsGoApiLogIn::SrsGoApiLogIn(SrsRtcServer* server)
{
    server_ = server;
}

SrsGoApiLogIn::~SrsGoApiLogIn()
{
}

// Request:
//      POST /rtc/v1/login/
//      {
//          "username" : "xxx", 
//      }
// Response:
//      {
//          "innner_ip" : "xxx",
//      }

srs_error_t SrsGoApiLogIn::serve_http(ISrsHttpResponseWriter* w, ISrsHttpMessage* r)
{
    srs_error_t err = srs_success;

    SrsJsonObject* res = SrsJsonAny::object();
    SrsAutoFree(SrsJsonObject, res);

    if ((err = do_serve_http(w, r, res)) != srs_success) {
        srs_warn("RTC error %s", srs_error_desc(err).c_str()); srs_freep(err);
        return srs_api_response_code(w, r, SRS_CONSTS_HTTP_BadRequest);
    }

    return srs_api_response(w, r, res->dumps());
}

srs_error_t SrsGoApiLogIn::do_serve_http(ISrsHttpResponseWriter* w, ISrsHttpMessage* r, SrsJsonObject* res)
{
    srs_error_t err = srs_success;

    // For each RTC session, we use short-term HTTP connection.
    SrsHttpHeader* hdr = w->header();
    hdr->set("Connection", "Close");

    // Parse req, the request json object, from body.
    SrsJsonObject* req = NULL;
    SrsAutoFree(SrsJsonObject, req);
    if (true) {
        string req_json;
        if ((err = r->body_read_all(req_json)) != srs_success) {
            return srs_error_wrap(err, "read body");
        }

        SrsJsonAny* json = SrsJsonAny::loads(req_json);
        if (!json || !json->is_object()) {
            return srs_error_new(ERROR_RTC_API_BODY, "invalid body %s", req_json.c_str());
        }

        req = json->to_object();
    }

    SrsJsonAny* prop = NULL;
    if ((prop = req->ensure_property_string("username")) == NULL) {
        return srs_error_wrap(err, "no username");
    }
    string username = prop->to_str();
    srs_set_login_username(username);

    vector<SrsIPAddress*> ips = srs_get_local_ips();
    string inner_ip = ips.front()->ip;
    res->set("inner_ip", SrsJsonAny::str(inner_ip.c_str()));

    srs_trace("<BTRACE> login api called, username=%s, inner_ip=%s", username.c_str(), inner_ip.c_str());

    return err;
}

//////////////////////////////////////////////////////////////////////
SrsGoApiRtcMonitor::SrsGoApiRtcMonitor(SrsRtcServer* server)
{
    server_ = server;
}

SrsGoApiRtcMonitor::~SrsGoApiRtcMonitor()
{
}

// Request:
//      POST /rtc/v1/monitor/
//      {
//          "session_id" : "xxx", 
//      }
// Response:
//      {"recv_tpt":"xxx", "sent_tpt":"xxx", ...}

srs_error_t SrsGoApiRtcMonitor::serve_http(ISrsHttpResponseWriter* w, ISrsHttpMessage* r)
{
    srs_error_t err = srs_success;

    SrsJsonObject* res = SrsJsonAny::object();
    SrsAutoFree(SrsJsonObject, res);

    if ((err = do_serve_http(w, r, res)) != srs_success) {
        srs_warn("RTC error %s", srs_error_desc(err).c_str()); srs_freep(err);
        return srs_api_response_code(w, r, SRS_CONSTS_HTTP_BadRequest);
    }

    return srs_api_response(w, r, res->dumps());
}

srs_error_t SrsGoApiRtcMonitor::do_serve_http(ISrsHttpResponseWriter* w, ISrsHttpMessage* r, SrsJsonObject* res)
{
    srs_error_t err = srs_success;

    // For each RTC session, we use short-term HTTP connection.
    SrsHttpHeader* hdr = w->header();
    hdr->set("Connection", "Close");

    // Parse req, the request json object, from body.
    SrsJsonObject* req = NULL;
    SrsAutoFree(SrsJsonObject, req);
    if (true) {
        string req_json;
        if ((err = r->body_read_all(req_json)) != srs_success) {
            return srs_error_wrap(err, "read body");
        }

        SrsJsonAny* json = SrsJsonAny::loads(req_json);
        if (!json || !json->is_object()) {
            return srs_error_new(ERROR_RTC_API_BODY, "invalid body %s", req_json.c_str());
        }

        req = json->to_object();
    }

    // Fetch params from req object
    SrsJsonAny* prop = NULL;
    if ((prop = req->ensure_property_string("session_id")) == NULL) {
        return srs_error_wrap(err, "no session_id");
    }
    string session_id = prop->to_str();

    if ((prop = req->ensure_property_string("stream_url")) == NULL) {
        return srs_error_wrap(err, "no stream_url");
    }
    string stream_url = prop->to_str();


    // int start_reinject = 0;
    // int reinject_index = 0;
    string reinject_stream_ssrc = "";
    string send_map = "";
    // if ((prop = req->ensure_property_integer("start_reinject")) != NULL) {
    //     start_reinject = prop->to_integer();
    // }
    // if ((prop = req->ensure_property_integer("reinject_index")) != NULL) {
    //     reinject_index = prop->to_integer();
    // }
    if ((prop = req->ensure_property_string("reinject_stream_ssrc")) != NULL) {
        reinject_stream_ssrc = prop->to_str();
    }
    if ((prop = req->ensure_property_string("send_map")) != NULL) {
        send_map = prop->to_str();
    }

    SrsRtcConnection* chrome_player_session = server_->find_session_by_username(session_id);
    if (!chrome_player_session) {
        return srs_error_wrap(err, "cannot find session by username %s", session_id.c_str());
    }

    
    // chrome session stats
    SrsJsonObject* chrome_player = SrsJsonAny::object();
    double chrome_play_throughput = chrome_player_session->monitor_->get_sent_throughput();
    chrome_player->set("id", SrsJsonAny::str(chrome_player_session->get_username().c_str()));
    chrome_player->set("throughput", SrsJsonAny::str(to_string(chrome_play_throughput).c_str()));
    res->set("chrome_player", chrome_player);

    // player session towards L2 SRS stats
    SrsJsonArray* res_players = SrsJsonAny::array();
    for (int i = 0; i < (int)_srs_rtc_manager->size(); i++) {
        SrsRtcConnection* session = dynamic_cast<SrsRtcConnection*>(_srs_rtc_manager->at(i));
        // Ignore not session, or already disposing, or not alive
        if (!session || session->disposing_ || !session->is_alive()) {
            continue;
        }      
        if (session->connection_type_ != SstUpstreamPlayerSession) {
            continue;
        }
        SrsRtcPlayStream* play_stream = session->get_first_play_stream();
        if (!play_stream)
        {
            continue;
        }
        uint32_t video_ssrc = play_stream->get_first_video_ssrc();
        SrsRtcConsumer* consumer = play_stream->consumer_;
        if (!consumer)
        {
            continue;
        }
        // if (start_reinject != 0 && reinject_stream_ssrc == to_string(video_ssrc))
        // {
        //     consumer->set_reinjection_rules(start_reinject, reinject_index);
        // }
        if (reinject_stream_ssrc.size() > 0 && reinject_stream_ssrc == to_string(video_ssrc)) {
            consumer->set_send_map(send_map);
        }  

        SrsJsonObject* player = SrsJsonAny::object();
        double play_throughput = session->monitor_->get_sent_throughput();
        int delay = session->monitor_-> get_delay();
        int inboundRtt = session->monitor_-> get_inboundRtt();
        player->set("id", SrsJsonAny::str(session->get_username().c_str()));
        player->set("throughput", SrsJsonAny::str(to_string(play_throughput).c_str()));
        player->set("snum", SrsJsonAny::str(to_string(consumer->snum_).c_str()));
        player->set("sdegree", SrsJsonAny::str(to_string(consumer->sdegree_).c_str()));
        player->set("video_ssrc", SrsJsonAny::str(to_string(video_ssrc).c_str()));
        player->set("delay", SrsJsonAny::str(to_string(delay).c_str()));
        player->set("inboundRtt", SrsJsonAny::str(to_string(inboundRtt).c_str()));
        res_players->add(player);
    }
    res->set("to_downstream_players", res_players);
    
    // publisher session from L1 SRS stats
    SrsJsonArray* res_publishers = SrsJsonAny::array();
    std::vector<SstPublisherSession*>::iterator it_session;
    for (it_session = chrome_player_session->sst_publishers_.begin(); it_session != chrome_player_session->sst_publishers_.end(); it_session++) {
        SrsRtcConnection* sub_publish_session = (*it_session)->sst_publisher_;
        SrsJsonObject* sub_publisher = SrsJsonAny::object();

        double sub_publish_throughput = sub_publish_session->monitor_->get_recv_throughput();
        sub_publisher->set("id", SrsJsonAny::str(sub_publish_session->get_username().c_str()));
        sub_publisher->set("throughput", SrsJsonAny::str(to_string(sub_publish_throughput).c_str()));
        SrsRtcPublishStream* publish_stream = sub_publish_session->get_first_publish_stream();
        if (!publish_stream)
        {
            continue;
        } 
        sub_publisher->set("snum", SrsJsonAny::str(to_string(publish_stream->snum_).c_str()));
        sub_publisher->set("sdegree", SrsJsonAny::str(to_string(publish_stream->sdegree_).c_str()));

        SrsJsonArray* tracks = SrsJsonAny::array();
        std::map<uint32_t, int>::iterator it_track = sub_publish_session->monitor_->recv_rtt.begin();
        for (;it_track!=sub_publish_session->monitor_->recv_rtt.end();it_track++) {
            SrsJsonObject* track_stats = SrsJsonAny::object();
            uint32_t ssrc = it_track->first;
            track_stats->set("ssrc", SrsJsonAny::str(to_string(ssrc).c_str()));
            track_stats->set("rtt", SrsJsonAny::str(to_string(sub_publish_session->monitor_->get_rtt(ssrc)).c_str()));
            track_stats->set("jitter", SrsJsonAny::str(to_string(sub_publish_session->monitor_->get_jitter(ssrc)).c_str()));
            track_stats->set("total_loss", SrsJsonAny::str(to_string(sub_publish_session->monitor_->get_total_loss_rate(ssrc)).c_str()));
            track_stats->set("fraction_loss", SrsJsonAny::str(to_string(sub_publish_session->monitor_->get_fraction_loss_rate(ssrc)).c_str()));
            tracks->add(track_stats);
        }
        sub_publisher->set("tracks", tracks);
        res_publishers->add(sub_publisher);
    }
    res->set("from_upstream_publishers", res_publishers);
    srs_trace("<BTRACE> monitor response: %s", res->dumps().c_str());
    
    return err;
}

SrsGoApiRtcPlay::SrsGoApiRtcPlay(SrsRtcServer* server)
{
    server_ = server;
}

SrsGoApiRtcPlay::~SrsGoApiRtcPlay()
{
}


// Request:
//      POST /rtc/v1/play/
//      {
//          "sdp":"offer...", "streamurl":"webrtc://r.ossrs.net/live/livestream",
//          "api":'http...", "clientip":"..."
//      }
// Response:
//      {"sdp":"answer...", "sid":"..."}
// @see https://github.com/rtcdn/rtcdn-draft
srs_error_t SrsGoApiRtcPlay::serve_http(ISrsHttpResponseWriter* w, ISrsHttpMessage* r)
{
    // NOTEG: SRS服务前端推/拉流请求的最外层
    srs_error_t err = srs_success;

    SrsJsonObject* res = SrsJsonAny::object();
    SrsAutoFree(SrsJsonObject, res);

    if ((err = do_serve_http(w, r, res)) != srs_success) {
        srs_warn("RTC error %s", srs_error_desc(err).c_str()); srs_freep(err);
        return srs_api_response_code(w, r, SRS_CONSTS_HTTP_BadRequest);
    }

    return srs_api_response(w, r, res->dumps());
}

srs_error_t SrsGoApiRtcPlay::do_serve_http(ISrsHttpResponseWriter* w, ISrsHttpMessage* r, SrsJsonObject* res)
{
    srs_error_t err = srs_success;

    // For each RTC session, we use short-term HTTP connection.
    SrsHttpHeader* hdr = w->header();
    hdr->set("Connection", "Close");

    // Parse req, the request json object, from body.
    SrsJsonObject* req = NULL;
    SrsAutoFree(SrsJsonObject, req);
    if (true) {
        string req_json;
        if ((err = r->body_read_all(req_json)) != srs_success) {
            return srs_error_wrap(err, "read body");
        }
        srs_trace("<BTRACE> SrsGoApiRtcPlay req received: \n%s", req_json.c_str());

        SrsJsonAny* json = SrsJsonAny::loads(req_json);
        if (!json || !json->is_object()) {
            return srs_error_new(ERROR_RTC_API_BODY, "invalid body %s", req_json.c_str());
        }

        req = json->to_object();
    }

    // Fetch params from req object.
    SrsJsonAny* prop = NULL;
    if ((prop = req->ensure_property_string("sdp")) == NULL) {
        return srs_error_wrap(err, "not sdp");
    }
    string remote_sdp_str = prop->to_str();

    if ((prop = req->ensure_property_string("streamurl")) == NULL) {
        return srs_error_wrap(err, "not streamurl");
    }
    string streamurl = prop->to_str();

    string clientip;
    if ((prop = req->ensure_property_string("clientip")) != NULL) {
        clientip = prop->to_str();
    }
    if (clientip.empty()) {
        clientip = dynamic_cast<SrsHttpMessage*>(r)->connection()->remote_ip();
        // Overwrite by ip from proxy.        
        string oip = srs_get_original_ip(r);
        if (!oip.empty()) {
            clientip = oip;
        }
    }
    srs_trace("<BTRACE> play request from ip=%s", clientip.c_str());

    string api;
    if ((prop = req->ensure_property_string("api")) != NULL) {
        api = prop->to_str();
    }

    string tid;
    if ((prop = req->ensure_property_string("tid")) != NULL) {
        tid = prop->to_str();
    }

    // The RTC user config object.
    SrsRtcUserConfig ruc;
    ruc.req_->ip = clientip;
    ruc.api_ = api;

    // MARKG server api modify & ruc properties and methods add

    /* sst api properties
        snum: int  
        sdegree: int
        // publishers: "ip:port;ip:port;ip:port;", notice the ';' in the end!
        publishers: string   
    */
    int snum = -1;
    if ((prop = req->ensure_property_integer("snum")) != NULL) {
        snum = prop->to_integer();
        ruc.snum_ = snum;
    }

    int sdegree = 0;
    if ((prop = req->ensure_property_integer("sdegree")) != NULL) {
        sdegree = prop->to_integer();
        ruc.sdegree_ = sdegree;
    }

    string cascade_publishers_str;
    if ((prop = req->ensure_property_string("publishers")) != NULL) {
        cascade_publishers_str = prop->to_str();
        string::size_type right = 0, left = 0;
        while((right = cascade_publishers_str.find(";",left)) != string::npos){
            string ip_port = cascade_publishers_str.substr(left,right - left);
            int pos = ip_port.find(":");
            ruc.cascade_publishers_.push_back(std::make_pair(ip_port.substr(0,pos), stoi(ip_port.substr(pos+1))));
            left = right + 1;
        }
    }

    // NOTEG: 根据API参数填写请求来源，没有填写sdegree或snum则为普通无sst传输
    SstPlayerType player_type = NormalPlayer;
    if (sdegree > 0 && snum < 0) {
        player_type = sstDownstreamBrowser;
        if (ruc.sdegree_ > 0 && ruc.sdegree_ != ruc.cascade_publishers_.size()) {
            srs_warn("[BUPT WARN] sdegree_ != cascade_publishers_.size() in RUC: (sdegree)%d, (publishers)%d-%s", ruc.sdegree_, ruc.cascade_publishers_.size(), cascade_publishers_str.c_str());
        }
        srs_trace("[BUPT TRACE] player type sstDownstreamBrowser snum: %d, sdegree: %d, cascade_publishers_str: %s.", snum, sdegree, cascade_publishers_str.c_str());
    } else if (sdegree > 0 && snum >= 0) {
        player_type = sstDownstreamSRS;
        srs_trace("[BUPT TRACE] player type sstDownstreamSRS snum: %d, sdegree: %d", snum, sdegree);
    }
    ruc.sst_player_ = player_type;

    // --------------------   MARKG   --------------------

    srs_parse_rtmp_url(streamurl, ruc.req_->tcUrl, ruc.req_->stream);

    srs_discovery_tc_url(ruc.req_->tcUrl, ruc.req_->schema, ruc.req_->host, ruc.req_->vhost, 
                         ruc.req_->app, ruc.req_->stream, ruc.req_->port, ruc.req_->param);

    // discovery vhost, resolve the vhost from config
    SrsConfDirective* parsed_vhost = _srs_config->get_vhost(ruc.req_->vhost);
    if (parsed_vhost) {
        ruc.req_->vhost = parsed_vhost->arg0();
    }

    if ((err = http_hooks_on_play(ruc.req_)) != srs_success) {
        return srs_error_wrap(err, "RTC: http_hooks_on_play");
    }

    // For client to specifies the candidate(EIP) of server.
    string eip = r->query_get("eip");
    if (eip.empty()) {
        eip = r->query_get("candidate");
    }
    string codec = r->query_get("codec");
    // For client to specifies whether encrypt by SRTP.
    string srtp = r->query_get("encrypt");
    string dtls = r->query_get("dtls");

    srs_trace("RTC play %s, api=%s, tid=%s, clientip=%s, app=%s, stream=%s, offer=%dB, eip=%s, codec=%s, srtp=%s, dtls=%s",
        streamurl.c_str(), api.c_str(), tid.c_str(), clientip.c_str(), ruc.req_->app.c_str(), ruc.req_->stream.c_str(), remote_sdp_str.length(),
        eip.c_str(), codec.c_str(), srtp.c_str(), dtls.c_str()
    );

    ruc.eip_ = eip;
    ruc.codec_ = codec;
    ruc.publish_ = false;
    ruc.dtls_ = (dtls != "false");

    if (srtp.empty()) {
        ruc.srtp_ = _srs_config->get_rtc_server_encrypt();
    } else {
        ruc.srtp_ = (srtp != "false");
    }

    // TODO: FIXME: It seems remote_sdp doesn't represents the full SDP information.
    if ((err = ruc.remote_sdp_.parse(remote_sdp_str)) != srs_success) {
        return srs_error_wrap(err, "parse sdp failed: %s", remote_sdp_str.c_str());
    }

    if ((err = check_remote_sdp(ruc.remote_sdp_)) != srs_success) {
        return srs_error_wrap(err, "remote sdp check failed");
    }

    SrsSdp local_sdp;

    // Config for SDP and session.
    local_sdp.session_config_.dtls_role = _srs_config->get_rtc_dtls_role(ruc.req_->vhost);
    local_sdp.session_config_.dtls_version = _srs_config->get_rtc_dtls_version(ruc.req_->vhost);

    // Whether enabled.
    bool server_enabled = _srs_config->get_rtc_server_enabled();
    bool rtc_enabled = _srs_config->get_rtc_enabled(ruc.req_->vhost);
    if (server_enabled && !rtc_enabled) {
        srs_warn("RTC disabled in vhost %s", ruc.req_->vhost.c_str());
    }
    if (!server_enabled || !rtc_enabled) {
        return srs_error_new(ERROR_RTC_DISABLED, "Disabled server=%d, rtc=%d, vhost=%s",
            server_enabled, rtc_enabled, ruc.req_->vhost.c_str());
    }

    // Whether RTC stream is active.
    bool is_rtc_stream_active = false;
    if (true) {
        SrsRtcSource* source = _srs_rtc_sources->fetch(ruc.req_);
        is_rtc_stream_active = (source && !source->can_publish());
    }

    // For RTMP to RTC, fail if disabled and RTMP is active, see https://github.com/ossrs/srs/issues/2728
    if (!is_rtc_stream_active && !_srs_config->get_rtc_from_rtmp(ruc.req_->vhost)) {
        SrsLiveSource* rtmp = _srs_sources->fetch(ruc.req_);
        if (rtmp && !rtmp->inactive()) {
            return srs_error_new(ERROR_RTC_DISABLED, "Disabled rtmp_to_rtc of %s, see #2728", ruc.req_->vhost.c_str());
        }
    }

    // TODO: FIXME: When server enabled, but vhost disabled, should report error.
    SrsRtcConnection* session = NULL;
    if ((err = server_->create_session(&ruc, local_sdp, &session)) != srs_success) {
        return srs_error_wrap(err, "create session, dtls=%u, srtp=%u, eip=%s", ruc.dtls_, ruc.srtp_, eip.c_str());
    }

    ostringstream os;
    if ((err = local_sdp.encode(os)) != srs_success) {
        return srs_error_wrap(err, "encode sdp");
    }

    string local_sdp_str = os.str();
    // srs_trace("[BUPT DEBUG] SrsGoApiRtcPlay local_sdp_str: %s", local_sdp_str.c_str());
    // Filter the \r\n to \\r\\n for JSON.
    string local_sdp_escaped = srs_string_replace(local_sdp_str.c_str(), "\r\n", "\\r\\n");
    

    res->set("code", SrsJsonAny::integer(ERROR_SUCCESS));
    res->set("server", SrsJsonAny::str(SrsStatistic::instance()->server_id().c_str()));

    // TODO: add candidates in response json?

    res->set("sdp", SrsJsonAny::str(local_sdp_str.c_str()));
    res->set("sessionid", SrsJsonAny::str(session->username().c_str()));

    srs_trace("RTC username=%s, dtls=%u, srtp=%u, offer=%dB, answer=%dB", session->username().c_str(),
        ruc.dtls_, ruc.srtp_, remote_sdp_str.length(), local_sdp_escaped.length());
    srs_trace("RTC remote offer: %s", srs_string_replace(remote_sdp_str.c_str(), "\r\n", "\\r\\n").c_str());
    srs_trace("RTC local answer: %s", local_sdp_escaped.c_str());

    return err;
}

srs_error_t SrsGoApiRtcPlay::check_remote_sdp(const SrsSdp& remote_sdp)
{
    srs_error_t err = srs_success;

    if (remote_sdp.group_policy_ != "BUNDLE") {
        return srs_error_new(ERROR_RTC_SDP_EXCHANGE, "now only support BUNDLE, group policy=%s", remote_sdp.group_policy_.c_str());
    }

    if (remote_sdp.media_descs_.empty()) {
        return srs_error_new(ERROR_RTC_SDP_EXCHANGE, "no media descriptions");
    }

    for (std::vector<SrsMediaDesc>::const_iterator iter = remote_sdp.media_descs_.begin(); iter != remote_sdp.media_descs_.end(); ++iter) {
        if (iter->type_ != "audio" && iter->type_ != "video") {
            return srs_error_new(ERROR_RTC_SDP_EXCHANGE, "unsupport media type=%s", iter->type_.c_str());
        }

        if (! iter->rtcp_mux_) {
            return srs_error_new(ERROR_RTC_SDP_EXCHANGE, "now only suppor rtcp-mux");
        }

        if (iter->sendonly_) {
            return srs_error_new(ERROR_RTC_SDP_EXCHANGE, "play API only support sendrecv/recvonly");
        }
    }

    return err;
}

srs_error_t SrsGoApiRtcPlay::http_hooks_on_play(SrsRequest* req)
{
    srs_error_t err = srs_success;

    if (!_srs_config->get_vhost_http_hooks_enabled(req->vhost)) {
        return err;
    }

    // the http hooks will cause context switch,
    // so we must copy all hooks for the on_connect may freed.
    // @see https://github.com/ossrs/srs/issues/475
    vector<string> hooks;

    if (true) {
        SrsConfDirective* conf = _srs_config->get_vhost_on_play(req->vhost);

        if (!conf) {
            return err;
        }

        hooks = conf->args;
    }

    for (int i = 0; i < (int)hooks.size(); i++) {
        std::string url = hooks.at(i);
        if ((err = SrsHttpHooks::on_play(url, req)) != srs_success) {
            return srs_error_wrap(err, "on_play %s", url.c_str());
        }
    }

    return err;
}

SrsGoApiRtcPublish::SrsGoApiRtcPublish(SrsRtcServer* server)
{
    server_ = server;
}

SrsGoApiRtcPublish::~SrsGoApiRtcPublish()
{
}


// Request:
//      POST /rtc/v1/publish/
//      {
//          "sdp":"offer...", "streamurl":"webrtc://r.ossrs.net/live/livestream",
//          "api":'http...", "clientip":"..."
//      }
// Response:
//      {"sdp":"answer...", "sid":"..."}
// @see https://github.com/rtcdn/rtcdn-draft
srs_error_t SrsGoApiRtcPublish::serve_http(ISrsHttpResponseWriter* w, ISrsHttpMessage* r)
{
    srs_error_t err = srs_success;

    SrsJsonObject* res = SrsJsonAny::object();
    SrsAutoFree(SrsJsonObject, res);

    if ((err = do_serve_http(w, r, res)) != srs_success) {
        srs_warn("RTC error %s", srs_error_desc(err).c_str()); srs_freep(err);
        return srs_api_response_code(w, r, SRS_CONSTS_HTTP_BadRequest);
    }

    return srs_api_response(w, r, res->dumps());
}

srs_error_t SrsGoApiRtcPublish::do_serve_http(ISrsHttpResponseWriter* w, ISrsHttpMessage* r, SrsJsonObject* res)
{
    srs_error_t err = srs_success;

    // For each RTC session, we use short-term HTTP connection.
    SrsHttpHeader* hdr = w->header();
    hdr->set("Connection", "Close");

    // Parse req, the request json object, from body.
    SrsJsonObject* req = NULL;
    SrsAutoFree(SrsJsonObject, req);
    if (true) {
        string req_json;
        if ((err = r->body_read_all(req_json)) != srs_success) {
            return srs_error_wrap(err, "read body");
        }
        srs_trace("[BUPT DEBUG] SrsGoApiRtcPublish req received: \n%s", req_json.c_str());

        SrsJsonAny* json = SrsJsonAny::loads(req_json);
        if (!json || !json->is_object()) {
            return srs_error_new(ERROR_RTC_API_BODY, "invalid body %s", req_json.c_str());
        }

        req = json->to_object();
    }

    // Fetch params from req object.
    SrsJsonAny* prop = NULL;
    if ((prop = req->ensure_property_string("sdp")) == NULL) {
        return srs_error_wrap(err, "not sdp");
    }
    string remote_sdp_str = prop->to_str();

    if ((prop = req->ensure_property_string("streamurl")) == NULL) {
        return srs_error_wrap(err, "not streamurl");
    }
    string streamurl = prop->to_str();

    string clientip;
    if ((prop = req->ensure_property_string("clientip")) != NULL) {
        clientip = prop->to_str();
    }
    if (clientip.empty()){
        clientip = dynamic_cast<SrsHttpMessage*>(r)->connection()->remote_ip();
        // Overwrite by ip from proxy.
        string oip = srs_get_original_ip(r);
        if (!oip.empty()) {
            clientip = oip;
        }
    }

    string api;
    if ((prop = req->ensure_property_string("api")) != NULL) {
        api = prop->to_str();
    }

    string tid;
    if ((prop = req->ensure_property_string("tid")) != NULL) {
        tid = prop->to_str();
    }

    // The RTC user config object.
    SrsRtcUserConfig ruc;
    ruc.req_->ip = clientip;
    ruc.api_ = api;

    srs_parse_rtmp_url(streamurl, ruc.req_->tcUrl, ruc.req_->stream);
    srs_discovery_tc_url(ruc.req_->tcUrl, ruc.req_->schema, ruc.req_->host, ruc.req_->vhost,
    ruc.req_->app, ruc.req_->stream, ruc.req_->port, ruc.req_->param);

    // Identify WebRTC publisher by param upstream=rtc
    ruc.req_->param = srs_string_trim_start(ruc.req_->param + "&upstream=rtc", "&");

    // discovery vhost, resolve the vhost from config
    SrsConfDirective* parsed_vhost = _srs_config->get_vhost(ruc.req_->vhost);
    if (parsed_vhost) {
        ruc.req_->vhost = parsed_vhost->arg0();
    }

	if ((err = http_hooks_on_publish(ruc.req_)) != srs_success) {
        return srs_error_wrap(err, "RTC: http_hooks_on_publish");
    }

    // For client to specifies the candidate(EIP) of server.
    string eip = r->query_get("eip");
    if (eip.empty()) {
        eip = r->query_get("candidate");
    }
    string codec = r->query_get("codec");

    srs_trace("RTC publish %s, api=%s, tid=%s, clientip=%s, app=%s, stream=%s, offer=%dB, eip=%s, codec=%s",
        streamurl.c_str(), api.c_str(), tid.c_str(), clientip.c_str(), ruc.req_->app.c_str(), ruc.req_->stream.c_str(),
        remote_sdp_str.length(), eip.c_str(), codec.c_str()
    );

    ruc.eip_ = eip;
    ruc.codec_ = codec;
    ruc.publish_ = true;
    ruc.dtls_ = ruc.srtp_ = true;

    // TODO: FIXME: It seems remote_sdp doesn't represents the full SDP information.
    if ((err = ruc.remote_sdp_.parse(remote_sdp_str)) != srs_success) {
        return srs_error_wrap(err, "parse sdp failed: %s", remote_sdp_str.c_str());
    }

    if ((err = check_remote_sdp(ruc.remote_sdp_)) != srs_success) {
        return srs_error_wrap(err, "remote sdp check failed");
    }

    SrsSdp local_sdp;

    // TODO: FIXME: move to create_session.
    // Config for SDP and session.
    local_sdp.session_config_.dtls_role = _srs_config->get_rtc_dtls_role(ruc.req_->vhost);
    local_sdp.session_config_.dtls_version = _srs_config->get_rtc_dtls_version(ruc.req_->vhost);

    // Whether enabled.
    bool server_enabled = _srs_config->get_rtc_server_enabled();
    bool rtc_enabled = _srs_config->get_rtc_enabled(ruc.req_->vhost);
    if (server_enabled && !rtc_enabled) {
        srs_warn("RTC disabled in vhost %s", ruc.req_->vhost.c_str());
    }
    if (!server_enabled || !rtc_enabled) {
        return srs_error_new(ERROR_RTC_DISABLED, "Disabled server=%d, rtc=%d, vhost=%s",
            server_enabled, rtc_enabled, ruc.req_->vhost.c_str());
    }

    // TODO: FIXME: When server enabled, but vhost disabled, should report error.
    SrsRtcConnection* session = NULL;
    if ((err = server_->create_session(&ruc, local_sdp, &session)) != srs_success) {
        return srs_error_wrap(err, "create session");
    }

    ostringstream os;
    if ((err = local_sdp.encode(os)) != srs_success) {
        return srs_error_wrap(err, "encode sdp");
    }

    string local_sdp_str = os.str();
    // Filter the \r\n to \\r\\n for JSON.
    string local_sdp_escaped = srs_string_replace(local_sdp_str.c_str(), "\r\n", "\\r\\n");

    res->set("code", SrsJsonAny::integer(ERROR_SUCCESS));
    res->set("server", SrsJsonAny::str(SrsStatistic::instance()->server_id().c_str()));

    // TODO: add candidates in response json?

    res->set("sdp", SrsJsonAny::str(local_sdp_str.c_str()));
    res->set("sessionid", SrsJsonAny::str(session->username().c_str()));

    srs_trace("RTC username=%s, offer=%dB, answer=%dB", session->username().c_str(),
        remote_sdp_str.length(), local_sdp_escaped.length());
    srs_trace("RTC remote offer: %s", srs_string_replace(remote_sdp_str.c_str(), "\r\n", "\\r\\n").c_str());
    srs_trace("RTC local answer: %s", local_sdp_escaped.c_str());

    return err;
}

srs_error_t SrsGoApiRtcPublish::check_remote_sdp(const SrsSdp& remote_sdp)
{
    srs_error_t err = srs_success;

    if (remote_sdp.group_policy_ != "BUNDLE") {
        return srs_error_new(ERROR_RTC_SDP_EXCHANGE, "now only support BUNDLE, group policy=%s", remote_sdp.group_policy_.c_str());
    }

    if (remote_sdp.media_descs_.empty()) {
        return srs_error_new(ERROR_RTC_SDP_EXCHANGE, "no media descriptions");
    }

    for (std::vector<SrsMediaDesc>::const_iterator iter = remote_sdp.media_descs_.begin(); iter != remote_sdp.media_descs_.end(); ++iter) {
        if (iter->type_ != "audio" && iter->type_ != "video") {
            return srs_error_new(ERROR_RTC_SDP_EXCHANGE, "unsupport media type=%s", iter->type_.c_str());
        }

        if (! iter->rtcp_mux_) {
            return srs_error_new(ERROR_RTC_SDP_EXCHANGE, "now only suppor rtcp-mux");
        }

        if (iter->recvonly_) {
            return srs_error_new(ERROR_RTC_SDP_EXCHANGE, "publish API only support sendrecv/sendonly");
        }
    }

    return err;
}

srs_error_t SrsGoApiRtcPublish::http_hooks_on_publish(SrsRequest* req)
{
    srs_error_t err = srs_success;

    if (!_srs_config->get_vhost_http_hooks_enabled(req->vhost)) {
        return err;
    }

    // the http hooks will cause context switch,
    // so we must copy all hooks for the on_connect may freed.
    // @see https://github.com/ossrs/srs/issues/475
    vector<string> hooks;

    if (true) {
        SrsConfDirective* conf = _srs_config->get_vhost_on_publish(req->vhost);
        if (!conf) {
            return err;
        }
        hooks = conf->args;
    }

    for (int i = 0; i < (int)hooks.size(); i++) {
        std::string url = hooks.at(i);
        if ((err = SrsHttpHooks::on_publish(url, req)) != srs_success) {
            return srs_error_wrap(err, "rtmp on_publish %s", url.c_str());
        }
    }

    return err;
}

SrsGoApiRtcNACK::SrsGoApiRtcNACK(SrsRtcServer* server)
{
    server_ = server;
}

SrsGoApiRtcNACK::~SrsGoApiRtcNACK()
{
}

srs_error_t SrsGoApiRtcNACK::serve_http(ISrsHttpResponseWriter* w, ISrsHttpMessage* r)
{
    srs_error_t err = srs_success;

    SrsJsonObject* res = SrsJsonAny::object();
    SrsAutoFree(SrsJsonObject, res);

    res->set("code", SrsJsonAny::integer(ERROR_SUCCESS));

    if ((err = do_serve_http(w, r, res)) != srs_success) {
        srs_warn("RTC: NACK err %s", srs_error_desc(err).c_str());
        res->set("code", SrsJsonAny::integer(srs_error_code(err)));
        srs_freep(err);
    }

    return srs_api_response(w, r, res->dumps());
}

srs_error_t SrsGoApiRtcNACK::do_serve_http(ISrsHttpResponseWriter* w, ISrsHttpMessage* r, SrsJsonObject* res)
{
    string username = r->query_get("username");
    string dropv = r->query_get("drop");

    SrsJsonObject* query = SrsJsonAny::object();
    res->set("query", query);

    query->set("username", SrsJsonAny::str(username.c_str()));
    query->set("drop", SrsJsonAny::str(dropv.c_str()));
    query->set("help", SrsJsonAny::str("?username=string&drop=int"));

    int drop = ::atoi(dropv.c_str());
    if (drop <= 0) {
        return srs_error_new(ERROR_RTC_INVALID_PARAMS, "invalid drop=%s/%d", dropv.c_str(), drop);
    }

    SrsRtcConnection* session = server_->find_session_by_username(username);
    if (!session) {
        return srs_error_new(ERROR_RTC_NO_SESSION, "no session username=%s", username.c_str());
    }

    session->simulate_nack_drop(drop);

    srs_trace("RTC: NACK session username=%s, drop=%s/%d", username.c_str(), dropv.c_str(), drop);

    return srs_success;
}

