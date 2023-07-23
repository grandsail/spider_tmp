//
// Copyright (c) 2013-2021 Winlin
//
// SPDX-License-Identifier: MIT
//

#ifndef SRS_APP_RTC_API_HPP
#define SRS_APP_RTC_API_HPP

#include <srs_core.hpp>

#include <srs_http_stack.hpp>

class SrsRtcServer;
class SrsRequest;
class SrsSdp;

class SrsGoApiRtcMonitor : public ISrsHttpHandler
{
public:
    SrsGoApiRtcMonitor(SrsRtcServer* server);
    virtual ~SrsGoApiRtcMonitor();
    virtual srs_error_t serve_http(ISrsHttpResponseWriter* w, ISrsHttpMessage* r);

private:
    SrsRtcServer* server_;
    virtual srs_error_t do_serve_http(ISrsHttpResponseWriter* w, ISrsHttpMessage* r, SrsJsonObject* res);
};

class SrsGoApiRtcSwitch : public ISrsHttpHandler
{
public:
    SrsGoApiRtcSwitch(SrsRtcServer* server);
    virtual ~SrsGoApiRtcSwitch();
    virtual srs_error_t serve_http(ISrsHttpResponseWriter* w, ISrsHttpMessage* r);
private:
    SrsRtcServer* server_;
    virtual srs_error_t do_serve_http(ISrsHttpResponseWriter* w, ISrsHttpMessage* r, SrsJsonObject* res);
};

class SrsGoApiLogIn :  public ISrsHttpHandler
{
public:
    SrsGoApiLogIn(SrsRtcServer* server);
    virtual ~SrsGoApiLogIn();
    virtual srs_error_t serve_http(ISrsHttpResponseWriter* w, ISrsHttpMessage* r);
private:
    SrsRtcServer* server_;
    virtual srs_error_t do_serve_http(ISrsHttpResponseWriter* w, ISrsHttpMessage* r, SrsJsonObject* res);
};

class SrsGoApiRtcPlay : public ISrsHttpHandler
{
private:
    SrsRtcServer* server_;
public:
    SrsGoApiRtcPlay(SrsRtcServer* server);
    virtual ~SrsGoApiRtcPlay();
public:
    virtual srs_error_t serve_http(ISrsHttpResponseWriter* w, ISrsHttpMessage* r);
private:
    virtual srs_error_t do_serve_http(ISrsHttpResponseWriter* w, ISrsHttpMessage* r, SrsJsonObject* res);
    srs_error_t check_remote_sdp(const SrsSdp& remote_sdp);
private:
    virtual srs_error_t http_hooks_on_play(SrsRequest* req);
};

class SrsGoApiRtcPublish : public ISrsHttpHandler
{
private:
    SrsRtcServer* server_;
public:
    SrsGoApiRtcPublish(SrsRtcServer* server);
    virtual ~SrsGoApiRtcPublish();
public:
    virtual srs_error_t serve_http(ISrsHttpResponseWriter* w, ISrsHttpMessage* r);
private:
    virtual srs_error_t do_serve_http(ISrsHttpResponseWriter* w, ISrsHttpMessage* r, SrsJsonObject* res);
    srs_error_t check_remote_sdp(const SrsSdp& remote_sdp);
private:
    virtual srs_error_t http_hooks_on_publish(SrsRequest* req);
};

class SrsGoApiRtcNACK : public ISrsHttpHandler
{
private:
    SrsRtcServer* server_;
public:
    SrsGoApiRtcNACK(SrsRtcServer* server);
    virtual ~SrsGoApiRtcNACK();
public:
    virtual srs_error_t serve_http(ISrsHttpResponseWriter* w, ISrsHttpMessage* r);
private:
    virtual srs_error_t do_serve_http(ISrsHttpResponseWriter* w, ISrsHttpMessage* r, SrsJsonObject* res);
};

#endif

