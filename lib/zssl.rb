require "openssl"
require "base64"

module Zoocial
    class Cipher

        attr_reader :key, :noise_size

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
            @noise_size = @pkey.n.num_bytes >> 1 | @pkey.n.num_bytes >> 2
        end

        def encrypt(source, target)
            source = Zoocial.open_file source, 'r'
            target = Zoocial.open_file target, 'w'

            cipher = OpenSSL::Cipher::AES256.new 'CBC'
            cipher.encrypt
            key = cipher.random_key 
            iv = cipher.random_iv
            cipher.key = key
            cipher.iv = iv
            hidden_key = hide_shared_key_in_buffer key, iv

            target.write Base64.encode64(@pkey.public_encrypt(hidden_key))
            target.write @division_line + "\n"

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
                target.close unless target.tty?
                source.close unless source.tty?
            end
        end

        def decrypt(source, target)
            source = Zoocial.open_file source, 'r'
            target = Zoocial.open_file target, 'w'

            buffer = ""
            begin
                line = source.readline.chomp
                if line == @division_line
                    break
                end
                buffer += line
            end until source.eof?
            buffer = @pkey.private_decrypt Base64.decode64(buffer)
            key, iv = read_shared_key_from_buffer buffer

            cipher = OpenSSL::Cipher::AES256.new 'CBC'
            cipher.decrypt
            cipher.key = key
            cipher.iv = iv
            begin
                begin
                    chunk = Base64.decode64(source.readline)
                    target.write cipher.update(chunk)
                end until source.eof?
                target.write cipher.final
            ensure
                target.close unless target.tty?
                source.close unless source.tty?
            end
        end

        private

        def hide_shared_key_in_buffer key, iv
            seed = [(SecureRandom.random_number * 1_000_000_000_000)].pack("I")
            pos_in_buffer = seed.unpack("I").pop.modulo(@noise_size - (32 + 16 + 4))
            random_buffer = ""
            begin 
                random_buffer += SecureRandom.random_bytes 
            end while random_buffer.length <= @noise_size
            first = seed + random_buffer.byteslice(0..pos_in_buffer - 1) + key + iv
            second = random_buffer.byteslice(first.bytesize..@noise_size - 1)
            return first + second
        end

        def read_shared_key_from_buffer buffer
            pos_in_buffer = buffer.byteslice(0..4).unpack("I").pop.modulo(@noise_size - (32 + 16 + 4)) + 4
            return buffer.byteslice(pos_in_buffer, 32), \
                buffer.byteslice(pos_in_buffer + 32, 16)
        end

    end

    def self.open_file file, mode
        case file
        when String 
            File.open file, mode
        when File, IO
            file
        else
            raise ArgumentError, "Invalid file #{file}"
        end
    end

    class CipherOptions

        attr_reader :source, :target, :key

        def initialize options, args
            raise ArgumentError, "Invalid options" if options.nil?
            raise ArgumentError, "Invalid arguments" if args.nil?
            @mode, @source, @target = *args
            @verbose = options.has_key? 'v'
            raise ArgumentError, "mode is mandatory" if @mode.nil?
            raise ArgumentError, "invalid mode '#{@mode}'" unless ['e', 'd', 'encrypt', 'decrypt'].include? @mode
            raise ArgumentError, "source is mandatory" if @source.nil?
            if @source == "-"
                @source = STDIN  
                STDERR.write "reading from SDTIN" if @verbose
            else
                @source = Zoocial.open_file @source, 'r'
                STDERR.write "reading file #{@source.path}" if @verbose
            end
            if @target.nil?
                @target = STDOUT
                STDERR.write "writing to sdtout" if @verbose
            else
                @target = Zoocial.open_file @target, 'w'
                STDERR.write "writing to #{@target.path}" if @verbose
            end
            if options.has_key? 'i'
                @key = Zoocial.open_file options['i'], 'r'
            else
                Dir.glob(File.expand_path('~/.ssh/id_?sa')) do |f|
                    next unless @key.nil?
                    @key = Zoocial.open_file f, 'r'
                end
            end
            STDERR.write "using key #{@key.path}" if @verbose
            STDERR.write "encrypting" if @verbose and encrypt?
            STDERR.write "decrypting" if @verbose and not encrypt?
        end

        def encrypt?
            ["e", "encrypt"].include? @mode
        end
    end
end
