#include <cstddef>
#include <iostream>
#include <string>

#include "schifra_galois_field.hpp"
#include "schifra_galois_field_polynomial.hpp"
#include "schifra_sequential_root_generator_polynomial_creator.hpp"
#include "schifra_reed_solomon_encoder.hpp"
#include "schifra_reed_solomon_decoder.hpp"
#include "schifra_reed_solomon_block.hpp"
#include "schifra_error_processes.hpp"

int main()
{
    /* Finite Field Parameters */
    const std::size_t field_descriptor = 8;
    const std::size_t generator_polynomial_index = 0;
    const std::size_t generator_polynomial_root_count = 64;

    /* Reed Solomon Code Parameters */
    const std::size_t code_length = 255;
    const std::size_t fec_length = 64;
    const std::size_t data_length = code_length - fec_length;

    /* Instantiate Finite Field and Generator Polynomials */
    const schifra::galois::field field(field_descriptor,
                                       schifra::galois::primitive_polynomial_size06,
                                       schifra::galois::primitive_polynomial06);

    schifra::galois::field_polynomial generator_polynomial(field);

    if (
        !schifra::make_sequential_root_generator_polynomial(field,
                                                            generator_polynomial_index,
                                                            generator_polynomial_root_count,
                                                            generator_polynomial))
    {
        std::cout << "Error - Failed to create sequential root generator!" << std::endl;
        return 1;
    }

    /* Instantiate Encoder and Decoder (Codec) */
    typedef schifra::reed_solomon::encoder<code_length, fec_length, data_length> encoder_t;
    typedef schifra::reed_solomon::decoder<code_length, fec_length, data_length> decoder_t;

    const encoder_t encoder(field, generator_polynomial);
    const decoder_t decoder(field, generator_polynomial_index);

    std::string message = "An expert is someone who knows more and more about less and "
                          "less until they know absolutely everything about nothing";

    /* Pad message with nulls up until the code-word length */
    message.resize(code_length, 'x');

    std::cout << "Original Message:  [" << message << "]" << std::endl;

    /* Instantiate RS Block For Codec */
    schifra::reed_solomon::block<code_length, fec_length> block;

    /* Transform message into Reed-Solomon encoded codeword */
    if (!encoder.encode(message, block))
    {
        std::cout << "Error - Critical encoding failure! "
                  << "Msg: " << block.error_as_string() << std::endl;
        return 1;
    }

    // NOTG: 获取block中的data和fec
    std::string data_str(data_length, 0x00);
    std::string fec_str(fec_length, 0x00);
    if (!block.data_to_string(data_str))
    {
        std::cout << "data string get error" << std::endl;
    }
    if (!block.fec_to_string(fec_str))
    {
        std::cout << "data string get error" << std::endl;
    }

    std::cout << "data: [" << data_str << "], fec: [" << fec_str << "]" << std::endl;

    // NOTEG: 把编码后的整个字符串装载到block中
    schifra::reed_solomon::block<code_length, fec_length> new_block;
    std::string coded_str = data_str + fec_str;
    new_block.load_string(coded_str);

    if (!decoder.decode(new_block))
    {
        std::cout << "Error - Critical decoding failure! "
                  << "Msg: " << block.error_as_string() << std::endl;
        return 1;
    }
    else if (!schifra::is_block_equivelent(block, message))
    {
        std::cout << "Error - Error correction failed!" << std::endl;
        return 1;
    }

    block.data_to_string(message);

    std::cout << "Corrected Message: [" << message << "]" << std::endl;

    std::cout << "Encoder Parameters [" << encoder_t::trait::code_length << ","
              << encoder_t::trait::data_length << ","
              << encoder_t::trait::fec_length << "]" << std::endl;

    std::cout << "Decoder Parameters [" << decoder_t::trait::code_length << ","
              << decoder_t::trait::data_length << ","
              << decoder_t::trait::fec_length << "]" << std::endl;

    return 0;
}
