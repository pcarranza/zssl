require "openssl"
require "base64"

class CryptoHelper

    attr_reader :key

    def initialize(key)
        raise ArgumentError, "Key cannot be nil" if key.nil?
        case key
        when OpenSSL::PKey::PKey
            @pkey = key
        else
            @pkey = OpenSSL::PKey.read File.new(key)
        end
        @chunk_size = 1024
        @division_line = '-' * 60
    end

    def encrypt_text(text)
        raise ArgumentError, "Invalid text" if text.nil? or text.empty?
        raise ArgumentError, "Invalid key for encryption" unless @pkey.public?
        @pkey.public_encrypt text
    end

    def decrypt_text(text)
        raise ArgumentError, "Invalid text" if text.nil? or text.empty?
        raise ArgumentError, "Invalid key for decryption" unless @pkey.private?
        @pkey.private_decrypt text
    end

    def encrypt_file(source, target)
        source = open_file source, 'r'
        target = open_file target, 'w'

        cipher = OpenSSL::Cipher::AES256.new 'CBC'
        cipher.encrypt
        key = cipher.random_key # TODO create a key with a user defined salt and
        iv = cipher.random_iv
        cipher.key = key
        cipher.iv = iv

        encrypt_encode = Proc.new do |v|
            target.write Base64.encode64(@pkey.public_encrypt(v))
            target.write @division_line + "\n"
        end
        encrypt_encode.call key
        encrypt_encode.call iv

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

        decode_decrypt = Proc.new do
            buffer = ""
            begin
                line = source.readline.chomp
                if line == @division_line
                    break
                end
                buffer += line
            end until source.eof?
            @pkey.private_decrypt Base64.decode64(buffer)
        end

        cipher = OpenSSL::Cipher::AES256.new 'CBC'
        cipher.decrypt
        cipher.key = decode_decrypt.call
        cipher.iv = decode_decrypt.call 
        begin
            begin
                chunk = Base64.decode64(source.readline)
                target.write cipher.update(chunk)
            end until source.eof?
            target.write cipher.final
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
    when File, IO
        file
    else
        raise ArgumentError, "Invalid file #{file}"
    end
end

class CryptoOptions

    attr_reader :source, :target, :key

    def initialize options, args
        raise ArgumentError, "Invalid options" if options.nil?
        raise ArgumentError, "Invalid arguments" if args.nil?
        @mode, @source, @target = *args
        raise ArgumentError, "mode is mandatory" if @mode.nil?
        raise ArgumentError, "invalid mode '#{@mode}'" unless ['e', 'd', 'encrypt', 'decrypt'].include? @mode
        raise ArgumentError, "source is mandatory" if @source.nil?
        if @source == "-"
            @source = STDIN  
        else
            @source = open_file @source, 'r'
        end
        if @target.nil?
            @target = STDOUT
        else
            @target = open_file @target, 'w'
        end
        if options.has_key? 'k'
            @key = open_file options['k'], 'r'
        else
            Dir.glob(File.expand_path('~/.ssh/id_?sa')) do |f|
                next unless @key.nil?
                @key = open_file f, 'r'
            end
        end
    end

    def encrypt?
        ["e", "encrypt"].include? @mode
    end
end
