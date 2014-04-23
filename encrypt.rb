require "openssl"

MEGABYTE=1024*1024

class CryptoHelper

    attr_reader :key

    def initialize(keyfile)
        raise ArgumentError, "Key cannot be nil" if keyfile.nil?
        @rsakey = OpenSSL::PKey::RSA::new File.new(keyfile)
        cipher = OpenSSL::Cipher::AES256.new 'CBC'
        @key = cipher.random_key
        @iv = cipher.random_iv
    end

    def encrypt_text(text)
        raise ArgumentError, "Invalid text" if text.nil? or text.empty?
        @rsakey.public_encrypt text
    end

    def encrypt_file(source, target)
        source = open source, 'r'
        target = open target, 'w'
        @shared_key = OpenSSL::Cipher::AES256.new 'CBC'
        @shared_key.encrypt
        @shared_key.key = @key
        @shared_key.iv = @iv

        begin
            source.each_chunk do | chunk |
                target.write @shared_key.update(chunk)
            end
            target.write @shared_key.final
        ensure
            target.close
            source.close
        end
    end

    def decrypt_file(source, target)
        source = open source, 'r'
        target = open target, 'w'
        @shared_key = OpenSSL::Cipher::AES256.new 'CBC'
        @shared_key.decrypt
        @shared_key.key = @key
        @shared_key.iv = @iv
        begin
            source.each_chunk do | chunk |
                target.write @shared_key.update(chunk)
            end
            target.write @shared_key.final
        ensure
            target.close
            source.close
        end
    end

    def open file, mode
        case file
        when String 
            File.open file, mode
        when File
            file
        else
            raise ArgumentError, 'Invalid file'
        end
    end

end


class File
    def each_chunk(chunk_size=MEGABYTE)
        yield read(chunk_size) until eof?
    end
end

