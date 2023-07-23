#ifndef SCHIFRA_RS_FEC_SOURCE
#define SCHIFRA_RS_FEC_SOURCE

#include "schifra_galois_field.hpp"
#include "schifra_galois_field_polynomial.hpp"
#include "schifra_sequential_root_generator_polynomial_creator.hpp"
#include "schifra_reed_solomon_encoder.hpp"
#include "schifra_reed_solomon_decoder.hpp"
#include "schifra_reed_solomon_block.hpp"
#include "schifra_error_processes.hpp"

const std::size_t rs_field_descriptor = 8;
const std::size_t rs_generator_polynomial_index = 0;
const schifra::galois::field rs_field(rs_field_descriptor,
                                      schifra::galois::primitive_polynomial_size06,
                                      schifra::galois::primitive_polynomial06);

const std::size_t rs_code_length = 255;

// NOTEG: encoder和decoder的template只能使用常量
// TOFIXG-RS: 能运行时定义的encoder和decoder

// origin_num = 2, redundant_num = 1, data_length = 170, fec_length = 85
const std::size_t rs_2_1_data_length = 170;
const std::size_t rs_2_1_fec_length = 85;

/* Define Encoder and Decoder Template*/
typedef schifra::reed_solomon::encoder<rs_code_length, rs_2_1_fec_length, rs_2_1_data_length> encoder_t;
typedef schifra::reed_solomon::decoder<rs_code_length, rs_2_1_fec_length, rs_2_1_data_length> decoder_t;
        
inline schifra::reed_solomon::block<rs_code_length, rs_2_1_fec_length> rs_2_1_block;
// origin_num = 3, redundant_num = 1

#endif