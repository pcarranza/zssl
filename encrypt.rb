require "openssl"
require "base64"

MEGABYTE=1024*1024

class CryptoHelper

    attr_reader :key
    attr_writer :chunk_size

    def initialize(keyfile)
        raise ArgumentError, "Key cannot be nil" if keyfile.nil?
        @rsakey = OpenSSL::PKey::RSA::new File.new(keyfile)
        @chunk_size = 1024
    end

    def encrypt_text(text)
        raise ArgumentError, "Invalid text" if text.nil? or text.empty?
        @rsakey.public_encrypt text
    end

    def encrypt_file(source, target)
        source = open_file source, 'r'
        target = open_file target, 'w'

        cipher = OpenSSL::Cipher::AES256.new 'CBC'
        cipher.encrypt
        key = cipher.random_key
        iv = cipher.random_iv
        cipher.key = key
        cipher.iv = iv

        target.write Base64.encode64(@rsakey.public_encrypt(key))
        target.write Base64.encode64(@rsakey.public_encrypt(iv))

        begin
            encrypted = "" 
            begin
                chunk = source.read(@chunk_size)
                encrypted += cipher.update(chunk)
                encrypted += cipher.final if source.eof?
                while encrypted.length >= 45
                    target.write Base64.encode64(encrypted.slice!(0..44))
                end 
            end until source.eof?
            target.write Base64.encode64 encrypted
        ensure
            target.close
            source.close
        end
    end

    def decrypt_file(source, target)
        source = open_file source, 'r'
        target = open_file target, 'w'
        @shared_key = OpenSSL::Cipher::AES256.new 'CBC'
        @shared_key.decrypt
        @shared_key.key = @key
        @shared_key.iv = @iv
        begin
            begin
                chunk = source.read @chunk_size
                target.write @shared_key.update(chunk)
            end until source.eof?
            target.write @shared_key.final
        ensure
            target.close
            source.close
        end
    end
end

def open_file file, mode
    case file
    when String 
        File.open file, mode
    when File
        file
    else
        raise ArgumentError, 'Invalid file'
    end
end

