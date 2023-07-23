# SRS 分流支持
## 扩展头结构
```
SrsRtpHeader 
    SrsRtpExtensions extensions_;
        SrsRtpExtensionTwcc twcc_;
        SrsRtpExtensionOneByte audio_level_;
        SrsRtpExtensionSubStreamTrans sst_;
            // original sequence number 
            uint16_t osn_;  
            // sub stream number, for example: 0, 1, 2
            uint8_t snum_;  
            // total degree of sub streams, for example: 3
            uint8_t sdegree_;   
            
            // plaintext(buffer) to object
            virtual srs_error_t decode(SrsBuffer* buf);
            // object to plaintext(buffer)
            virtual srs_error_t encode(SrsBuffer* buf);
            // return number of bytes the extension occupied
            virtual uint64_t nb_bytes(); 
```